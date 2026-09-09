"""Isolated kernel tests for #47 S1 (framework-execution-r1+r2+r3).

Covers identity Context, Trustee operation_lookup / alignment_paths,
compose_scope, trusts.runtime, and AuthorizedQuerySet. Isolated
registries only. Does not close #47. Does not implement S2–S4.
"""

import inspect
import re
from pathlib import Path

from django.contrib.auth.models import AnonymousUser
from django.core.checks import Error
from django.db import models
from django.db.models import UniqueConstraint
from django.test import TestCase, TransactionTestCase

from trusts.checks import CHECK_ID_INVALID_TRUSTEE, check_trustee_registry
from trusts.context import (
    KIND_IDENTITY,
    Context,
    ContextRegistrationError,
    ContextRegistry,
    ContextRegistryFrozen,
    check_registration as check_context_registration,
)
from trusts.path import (
    AuthorizationBranch,
    AuthorizationPath,
    AuthorizationPathError,
    compose,
    compose_scope,
    empty_grant_q,
)
from trusts.query import AuthorizedManager, AuthorizedQuerySet
from trusts.runtime import (
    AuthorizationConfigError,
    AuthorizationDenied,
    authorized_q,
    authorized_scope_q,
    filter_authorized,
    filter_authorized_scope,
    is_authorized,
    is_scope_authorized,
    principal_is_usable,
    require_authorized,
    require_scope_authorized,
)
from trusts.trustee import (
    KIND_GRANT,
    Trustee,
    TrusteeAdapter,
    TrusteeRegistrationError,
    TrusteeRegistry,
    TrusteeRegistryFrozen,
    check_registration as check_trustee_registration,
)
from tests.models import (
    S1Account,
    S1Bundle,
    S1DirectGrant,
    S1Issue,
    S1Operation,
    S1Organization,
    S1Repository,
    S1Team,
    S1TeamGrant,
    S1TrapGrant,
    S1UnregisteredNote,
    TrusteeOperation,
    TrusteeRequester,
    TrusteeScope,
)


S1_TEAM = 'team'
S1_DIRECT = 'direct'


def _s1_maps(grant_model=None, include_direct=True, alignment=True):
    """Isolated identity + alignment registries. Never touch process-wide maps."""
    if grant_model is None:
        grant_model = S1TeamGrant
    context = ContextRegistry()
    context.register_identity(S1Repository)
    trustee = TrusteeRegistry(
        requester_model=S1Account,
        scope_model=S1Repository,
        operation_model=S1Operation,
        operation_lookup='code',
    )
    alignment_paths = (
        (('team__organization', 'repository__organization'),)
        if alignment else ()
    )
    trustee.register(
        name=S1_TEAM,
        trustee_model=S1Team,
        grant_model=grant_model,
        trustee_path='team',
        scope_path='repository',
        operation_path='operation',
        membership_path='members',
        constraint_paths=('team__bundles__operations',),
        alignment_paths=alignment_paths,
    )
    if include_direct:
        trustee.register(
            name=S1_DIRECT,
            trustee_model=S1Account,
            grant_model=S1DirectGrant,
            trustee_path='account',
            scope_path='repository',
            operation_path='operation',
            membership_path='',
        )
    return context, trustee


class S1ReusableLayerTest(TestCase):
    def test_runtime_and_query_have_no_product_nouns(self):
        from trusts import query, runtime
        for module in (runtime, query):
            source = Path(inspect.getfile(module)).read_text()
            for noun in ('Trust', 'Content', 'Junction', 'GitHub'):
                self.assertIsNone(
                    re.search(r'\b%s\b' % noun, source),
                    '%r appears as a product noun in %s' % (
                        noun, module.__name__,
                    ),
                )

    def test_authorized_queryset_name_is_the_r1_choice(self):
        self.assertEqual(AuthorizedQuerySet.__name__, 'AuthorizedQuerySet')
        self.assertTrue(issubclass(AuthorizedManager, type(S1Repository.objects)))
        self.assertIsInstance(S1Repository.objects.all(), AuthorizedQuerySet)
        self.assertTrue(callable(S1Repository.objects.all().authorized))


class S1IdentityContextTest(TestCase):
    def test_register_identity_paths_and_idempotence(self):
        registry = ContextRegistry()
        adapter = registry.register_identity(S1Repository)
        self.assertEqual(adapter.kind, KIND_IDENTITY)
        self.assertEqual(adapter.scope_path(), '')
        self.assertEqual(adapter.resource_path(), '')
        self.assertIs(adapter.scope_model(), S1Repository)
        self.assertIs(adapter.terminal_model(), S1Repository)
        again = registry.register_identity(S1Repository)
        self.assertTrue(again.equivalent(adapter))
        self.assertIsNone(
            check_context_registration(S1Repository, KIND_IDENTITY, '')
        )

    def test_identity_related_joins_without_trailing_separator(self):
        registry = ContextRegistry()
        registry.register_identity(S1Repository)
        registry.register_related(S1Issue, through='repository')
        self.assertEqual(registry.scope_path(S1Issue), 'repository')
        self.assertEqual(registry.resource_path(S1Issue), 'issues')

    def test_identity_conflicts_with_direct(self):
        registry = ContextRegistry()
        registry.register_identity(S1Repository)
        with self.assertRaises(ContextRegistrationError):
            registry.register_direct(S1Repository, scope_field='organization')

    def test_identity_freeze_rejects_late_registration(self):
        registry = ContextRegistry()
        registry.register_identity(S1Repository)
        registry.freeze()
        with self.assertRaises(ContextRegistryFrozen):
            registry.register_identity(S1Issue)
        self.assertFalse(registry.is_registered(S1Issue))

    def test_process_wide_map_does_not_register_s1_identity(self):
        self.assertFalse(Context.is_registered(S1Repository))


class S1OperationLookupTest(TestCase):
    def test_unique_lookup_configures_and_is_idempotent(self):
        registry = TrusteeRegistry(
            requester_model=S1Account,
            scope_model=S1Repository,
            operation_model=S1Operation,
        )
        registry.configure(operation_lookup='code')
        self.assertEqual(registry.operation_lookup(), 'code')
        registry.configure(operation_lookup='code')
        self.assertEqual(registry.operation_lookup(), 'code')

    def test_non_unique_and_relation_lookups_fail(self):
        class RelOp(models.Model):
            owner = models.ForeignKey(
                S1Account, on_delete=models.CASCADE, related_name='+',
            )
            label = models.CharField(max_length=16)

            class Meta:
                app_label = 'trusts_tests'
                managed = False

        rel = TrusteeRegistry(
            requester_model=S1Account,
            operation_model=RelOp,
        )
        with self.assertRaises(TrusteeRegistrationError) as ctx:
            rel.configure(operation_lookup='owner')
        self.assertIn('unique scalar', str(ctx.exception).lower())

        class NonUniqueOp(models.Model):
            label = models.CharField(max_length=16)

            class Meta:
                app_label = 'trusts_tests'
                managed = False

        bad = TrusteeRegistry(
            requester_model=S1Account,
            operation_model=NonUniqueOp,
        )
        with self.assertRaises(TrusteeRegistrationError):
            bad.configure(operation_lookup='label')

    def test_frozen_registry_rejects_lookup_change(self):
        registry = TrusteeRegistry(
            requester_model=S1Account,
            scope_model=S1Repository,
            operation_model=S1Operation,
            operation_lookup='code',
        )
        registry.freeze()
        registry.configure(operation_lookup='code')
        with self.assertRaises(TrusteeRegistryFrozen):
            registry.configure(operation_lookup='id')

    def test_unique_constraint_lookup_is_accepted(self):
        class ConstrainedOp(models.Model):
            slug = models.CharField(max_length=16)

            class Meta:
                app_label = 'trusts_tests'
                managed = False
                constraints = [
                    UniqueConstraint(fields=('slug',), name='s1_op_slug'),
                ]

        registry = TrusteeRegistry(
            requester_model=S1Account,
            operation_model=ConstrainedOp,
            operation_lookup='slug',
        )
        self.assertEqual(registry.operation_lookup(), 'slug')

    def test_string_without_lookup_is_config_error_at_compose(self):
        context, trustee = _s1_maps()
        trustee._operation_lookup = None
        with self.assertRaises(AuthorizationPathError):
            compose(S1Repository, 'read', context=context, trustee=trustee)


class S1AlignmentRegistrationTest(TestCase):
    def test_valid_pair_freezes_on_adapter_and_branch(self):
        context, trustee = _s1_maps()
        adapter = trustee.get(S1_TEAM)
        expected = (('team__organization', 'repository__organization'),)
        self.assertEqual(adapter.alignment_paths, expected)
        path = compose(S1Repository, None, context=context, trustee=trustee)
        team_branch = [b for b in path.branches if b.name == S1_TEAM][0]
        self.assertIsInstance(team_branch, AuthorizationBranch)
        self.assertEqual(team_branch.alignment_paths, expected)
        self.assertIsInstance(team_branch.alignment_paths, tuple)
        self.assertIsInstance(team_branch.alignment_paths[0], tuple)
        direct = [b for b in path.branches if b.name == S1_DIRECT][0]
        self.assertEqual(direct.alignment_paths, ())

    def test_default_empty_alignment_matches_today(self):
        registry = TrusteeRegistry(
            requester_model=TrusteeRequester,
            scope_model=TrusteeScope,
            operation_model=TrusteeOperation,
        )
        from tests.models import TrusteeDirectGrant
        adapter = registry.register(
            name='direct',
            trustee_model=TrusteeRequester,
            grant_model=TrusteeDirectGrant,
            trustee_path='requester',
            scope_path='scope',
            operation_path='operation',
        )
        self.assertEqual(adapter.alignment_paths, ())
        self.assertTrue(adapter.equivalent(adapter))

    def test_registration_traps(self):
        registry = TrusteeRegistry(
            requester_model=S1Account,
            scope_model=S1Repository,
            operation_model=S1Operation,
        )
        base = dict(
            name=S1_TEAM,
            trustee_model=S1Team,
            grant_model=S1TeamGrant,
            trustee_path='team',
            scope_path='repository',
            operation_path='operation',
            membership_path='members',
        )
        with self.assertRaises(TrusteeRegistrationError):
            registry.register(**base, alignment_paths=lambda: ())
        with self.assertRaises(TrusteeRegistrationError):
            registry.register(**base, alignment_paths=('team__organization',))
        with self.assertRaises(TrusteeRegistrationError):
            registry.register(**base, alignment_paths=(('team__organization',),))
        with self.assertRaises(TrusteeRegistrationError):
            registry.register(**base, alignment_paths=(('', 'repository__organization'),))
        with self.assertRaises(TrusteeRegistrationError) as ctx:
            registry.register(
                **base,
                alignment_paths=(('team__name__foo', 'repository__title'),),
            )
        self.assertIn('scalar', str(ctx.exception).lower())
        with self.assertRaises(TrusteeRegistrationError) as ctx:
            registry.register(
                **base,
                alignment_paths=(('team__members', 'repository__organization'),),
            )
        self.assertIn('many-valued', str(ctx.exception).lower())
        with self.assertRaises(TrusteeRegistrationError):
            registry.register(
                **base,
                alignment_paths=(('missing', 'repository__organization'),),
            )
        with self.assertRaises(TrusteeRegistrationError) as ctx:
            registry.register(
                **base,
                alignment_paths=(('team__organization', 'id'),),
            )
        self.assertIn('compatible', str(ctx.exception).lower())
        with self.assertRaises(TrusteeRegistrationError):
            registry.register(
                **base,
                alignment_paths=(('team__organization', 'team'),),
            )
        self.assertIsNotNone(check_trustee_registration(
            S1_TEAM, S1Team, S1TeamGrant, 'team', 'repository', 'operation',
            membership_path='members',
            alignment_paths=(('team__organization', 'id'),),
            requester_model=S1Account,
            scope_model=S1Repository,
            operation_model=S1Operation,
        ))

    def test_revalidate_and_e007_report_stale_alignment(self):
        _context, trustee = _s1_maps()
        saved = trustee.get(S1_TEAM)
        trustee._adapters[S1_TEAM] = TrusteeAdapter(
            KIND_GRANT, S1_TEAM, saved.trustee_model, saved.membership_path,
            saved.grant_model, saved.trustee_path, saved.scope_path,
            saved.operation_path, saved.constraint_paths, trustee,
            alignment_paths=(('not_a_field', 'repository__organization'),),
        )
        try:
            with self.assertRaises(TrusteeRegistrationError) as ctx:
                trustee.revalidate(trustee.get(S1_TEAM))
            self.assertIn('not a field', str(ctx.exception))
        finally:
            trustee._adapters[S1_TEAM] = saved

        from trusts.zero.models import DIRECT_TRUSTEE, TrustUserPermission
        from trusts.zero.models import prepare_trustee_registry
        prepare_trustee_registry()
        process = Trustee.registry
        process_saved = process._adapters[DIRECT_TRUSTEE]
        process._adapters[DIRECT_TRUSTEE] = TrusteeAdapter(
            KIND_GRANT, DIRECT_TRUSTEE, process_saved.trustee_model,
            process_saved.membership_path, TrustUserPermission,
            process_saved.trustee_path, process_saved.scope_path,
            'not_a_field', process_saved.constraint_paths, process,
            alignment_paths=(('not_a_field', 'trust'),),
        )
        try:
            messages = check_trustee_registry(None)
            e007 = [m for m in messages if m.id == CHECK_ID_INVALID_TRUSTEE]
            self.assertTrue(e007)
            self.assertIsInstance(e007[0], Error)
            self.assertIn('not a field', e007[0].msg)
        finally:
            process._adapters[DIRECT_TRUSTEE] = process_saved


class S1ComposeScopeTest(TestCase):
    def test_compose_scope_needs_no_context_adapter(self):
        _context, trustee = _s1_maps()
        path = compose_scope(S1Repository, None, trustee=trustee)
        self.assertIsInstance(path, AuthorizationPath)
        self.assertTrue(path.scope_origin)
        self.assertEqual(path.resource_to_scope, '')
        self.assertIs(path.scope_model, S1Repository)
        self.assertIs(path.resource_model, S1Repository)
        self.assertIsNone(path._context_adapter)

    def test_compose_scope_rejects_wrong_scope_model(self):
        _context, trustee = _s1_maps()
        with self.assertRaises(AuthorizationPathError):
            compose_scope(S1Team, None, trustee=trustee)

    def test_resource_compose_of_unregistered_scope_model_fails(self):
        _context, trustee = _s1_maps()
        bare = ContextRegistry()
        with self.assertRaises(AuthorizationPathError):
            compose(S1Organization, None, context=bare, trustee=trustee)


class S1EvaluationTest(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        super(S1EvaluationTest, self).setUp()
        self.org_a = S1Organization.objects.create(name='acme')
        self.org_b = S1Organization.objects.create(name='other')
        self.team = S1Team.objects.create(organization=self.org_a, name='writers')
        self.other_team = S1Team.objects.create(
            organization=self.org_b, name='outsiders',
        )
        self.member = S1Account.objects.create(name='member')
        self.stranger = S1Account.objects.create(name='stranger')
        self.team.members.add(self.member)
        self.read = S1Operation.objects.create(code='read')
        self.write = S1Operation.objects.create(code='write')
        self.bundle = S1Bundle.objects.create(team=self.team, name='reader')
        self.bundle.operations.add(self.read)
        self.repo_a = S1Repository.objects.create(
            organization=self.org_a, title='repo-a',
        )
        self.repo_b = S1Repository.objects.create(
            organization=self.org_a, title='repo-b',
        )
        self.cross_repo = S1Repository.objects.create(
            organization=self.org_b, title='cross',
        )
        S1TeamGrant.objects.create(
            team=self.team, repository=self.repo_a, operation=self.read,
        )
        self.context, self.trustee = _s1_maps()
        self.path = compose(
            S1Repository, self.read, context=self.context, trustee=self.trustee,
        )
        self.runtime = dict(context=self.context, trustee=self.trustee)

    def _assert_object_list_equiv(self, principal, operation, obj, expected):
        with self.assertNumQueries(1):
            via_obj = is_authorized(principal, operation, obj, **self.runtime)
        with self.assertNumQueries(1):
            via_exists = type(obj).objects.filter(pk=obj.pk).filter(
                authorized_q(type(obj), principal, operation, **self.runtime)
            ).exists()
        with self.assertNumQueries(1):
            via_list = obj in list(
                filter_authorized(
                    type(obj).objects.filter(pk=obj.pk), principal, operation,
                    **self.runtime,
                )
            )
        self.assertEqual(via_obj, expected)
        self.assertEqual(via_exists, expected)
        self.assertEqual(via_list, expected)

    def test_same_org_team_grant_object_equals_list_one_query(self):
        self._assert_object_list_equiv(self.member, self.read, self.repo_a, True)
        self._assert_object_list_equiv(self.member, self.read, self.repo_b, False)
        with self.assertNumQueries(1):
            listed = list(
                filter_authorized(
                    S1Repository.objects.all(), self.member, self.read,
                    **self.runtime,
                ).order_by('pk').values_list('pk', flat=True)
            )
        self.assertEqual(listed, [self.repo_a.pk])

    def test_string_operation_compiles_without_preliminary_get(self):
        with self.assertNumQueries(1):
            self.assertTrue(
                is_authorized(self.member, 'read', self.repo_a, **self.runtime)
            )
        with self.assertNumQueries(1):
            listed = list(
                filter_authorized(
                    S1Repository.objects.all(), self.member, 'read',
                    **self.runtime,
                ).values_list('pk', flat=True)
            )
        self.assertEqual(listed, [self.repo_a.pk])
        exists_sql = str(
            S1Repository.objects.filter(pk=self.repo_a.pk).filter(
                authorized_q(S1Repository, self.member, 'read', **self.runtime)
            ).query
        )
        self.assertIn('code', exists_sql.lower())
        with self.assertNumQueries(1):
            self.assertFalse(
                is_authorized(self.member, 'missing', self.repo_a, **self.runtime)
            )

    def test_cross_org_malformed_grant_denies(self):
        other_bundle = S1Bundle.objects.create(team=self.team, name='cross-bundle')
        other_bundle.operations.add(self.read)
        S1TeamGrant.objects.create(
            team=self.team, repository=self.cross_repo, operation=self.read,
        )
        self._assert_object_list_equiv(
            self.member, self.read, self.cross_repo, False,
        )

    def test_null_alignment_denies(self):
        null_team = S1Team.objects.create(organization=None, name='null-team')
        null_team.members.add(self.member)
        null_bundle = S1Bundle.objects.create(team=null_team, name='null-bundle')
        null_bundle.operations.add(self.read)
        null_repo = S1Repository.objects.create(
            organization=self.org_a, title='null-team-repo',
        )
        S1TeamGrant.objects.create(
            team=null_team, repository=null_repo, operation=self.read,
        )
        self._assert_object_list_equiv(self.member, self.read, null_repo, False)

        null_org_repo = S1Repository.objects.create(
            organization=None, title='null-org-repo',
        )
        S1TeamGrant.objects.create(
            team=self.team, repository=null_org_repo, operation=self.read,
        )
        self._assert_object_list_equiv(
            self.member, self.read, null_org_repo, False,
        )

    def test_membership_grant_and_bundle_each_required(self):
        self._assert_object_list_equiv(
            self.stranger, self.read, self.repo_a, False,
        )
        S1TeamGrant.objects.create(
            team=self.team, repository=self.repo_a, operation=self.write,
        )
        self._assert_object_list_equiv(
            self.member, self.write, self.repo_a, False,
        )
        self.bundle.operations.add(self.write)
        self._assert_object_list_equiv(
            self.member, self.write, self.repo_a, True,
        )

    def test_direct_grant_is_independent_of_cross_org_team_row(self):
        S1TeamGrant.objects.create(
            team=self.team, repository=self.cross_repo, operation=self.read,
        )
        S1DirectGrant.objects.create(
            account=self.member, repository=self.repo_b, operation=self.read,
        )
        self._assert_object_list_equiv(self.member, self.read, self.repo_b, True)
        self._assert_object_list_equiv(
            self.member, self.read, self.cross_repo, False,
        )
        with self.assertNumQueries(1):
            listed = list(
                filter_authorized(
                    S1Repository.objects.all(), self.member, self.read,
                    **self.runtime,
                ).order_by('pk').values_list('pk', flat=True)
            )
        self.assertEqual(listed, [self.repo_a.pk, self.repo_b.pk])

    def test_compose_scope_listings_apply_alignment(self):
        S1TeamGrant.objects.create(
            team=self.team, repository=self.cross_repo, operation=self.read,
        )
        with self.assertNumQueries(1):
            listed = list(
                filter_authorized_scope(
                    S1Repository.objects.all(), self.member, 'read',
                    trustee=self.trustee,
                ).order_by('pk').values_list('pk', flat=True)
            )
        self.assertEqual(listed, [self.repo_a.pk])
        with self.assertNumQueries(1):
            self.assertTrue(
                is_scope_authorized(
                    self.member, 'read', self.repo_a, trustee=self.trustee,
                )
            )
        with self.assertNumQueries(1):
            self.assertFalse(
                is_scope_authorized(
                    self.member, 'read', self.cross_repo, trustee=self.trustee,
                )
            )

    def test_getters_are_not_executed(self):
        grant = S1TrapGrant.objects.create(
            team=self.team, repository=self.repo_a, operation=self.read,
        )
        context, trustee = _s1_maps(grant_model=S1TrapGrant, include_direct=False)
        with self.assertNumQueries(1):
            self.assertTrue(
                is_authorized(
                    self.member, 'read', self.repo_a,
                    context=context, trustee=trustee,
                )
            )
        with self.assertRaises(AssertionError):
            grant.forbidden
        with self.assertRaises(AssertionError):
            grant.get_team()

    def test_authorized_queryset_manager(self):
        with self.assertNumQueries(1):
            listed = list(
                S1Repository.objects.authorized(
                    self.member, 'read', **self.runtime,
                ).order_by('pk').values_list('pk', flat=True)
            )
        self.assertEqual(listed, [self.repo_a.pk])

    def test_require_helpers(self):
        self.assertIs(
            require_authorized(self.member, 'read', self.repo_a, **self.runtime),
            self.repo_a,
        )
        with self.assertRaises(AuthorizationDenied):
            require_authorized(self.member, 'read', self.repo_b, **self.runtime)
        self.assertIs(
            require_scope_authorized(
                self.member, 'read', self.repo_a, trustee=self.trustee,
            ),
            self.repo_a,
        )
        with self.assertRaises(AuthorizationDenied):
            require_scope_authorized(
                self.member, 'read', self.repo_b, trustee=self.trustee,
            )


class S1RuntimeConfigTest(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        super(S1RuntimeConfigTest, self).setUp()
        self.org = S1Organization.objects.create(name='acme')
        self.account = S1Account.objects.create(name='pat')
        self.repo = S1Repository.objects.create(
            organization=self.org, title='repo',
        )
        self.read = S1Operation.objects.create(code='read')
        self.context, self.trustee = _s1_maps()
        self.runtime = dict(context=self.context, trustee=self.trustee)

    def test_unusable_principal_denies(self):
        self.account.is_anonymous = True
        self.assertFalse(principal_is_usable(self.account))
        self.assertFalse(
            is_authorized(self.account, 'read', self.repo, **self.runtime)
        )
        self.assertEqual(
            list(filter_authorized(
                S1Repository.objects.all(), self.account, 'read', **self.runtime,
            )),
            [],
        )
        del self.account.is_anonymous
        self.account.is_authenticated = False
        self.assertFalse(
            is_authorized(self.account, 'read', self.repo, **self.runtime)
        )
        del self.account.is_authenticated
        self.account.is_active = False
        self.assertFalse(
            is_authorized(self.account, 'read', self.repo, **self.runtime)
        )
        with self.assertRaises(AuthorizationDenied):
            require_authorized(self.account, 'read', self.repo, **self.runtime)

    def test_missing_flags_are_usable(self):
        self.assertTrue(principal_is_usable(self.account))

    def test_anonymous_user_takes_ordinary_denial_path(self):
        principal = AnonymousUser()
        self.assertFalse(principal_is_usable(principal))

        with self.assertNumQueries(0):
            self.assertFalse(
                is_authorized(principal, 'read', self.repo, **self.runtime)
            )
            self.assertFalse(
                is_scope_authorized(
                    principal, 'read', self.repo, trustee=self.trustee,
                )
            )

        with self.assertNumQueries(0):
            filtered = filter_authorized(
                S1Repository.objects.all(), principal, 'read', **self.runtime,
            )
            self.assertTrue(filtered.query.is_empty())
            self.assertEqual(list(filtered), [])
            scoped = filter_authorized_scope(
                S1Repository.objects.all(), principal, 'read',
                trustee=self.trustee,
            )
            self.assertTrue(scoped.query.is_empty())
            self.assertEqual(list(scoped), [])

        with self.assertNumQueries(0):
            with self.assertRaises(AuthorizationDenied):
                require_authorized(
                    principal, 'read', self.repo, **self.runtime,
                )
            with self.assertRaises(AuthorizationDenied):
                require_scope_authorized(
                    principal, 'read', self.repo, trustee=self.trustee,
                )

        empty = authorized_q(
            S1Repository, principal, 'read', **self.runtime,
        )
        empty_scope = authorized_scope_q(
            S1Repository, principal, 'read', trustee=self.trustee,
        )
        self.assertEqual(str(empty), str(empty_grant_q()))
        self.assertEqual(str(empty_scope), str(empty_grant_q()))

    def test_wrong_model_and_raw_pk_are_config_errors(self):
        with self.assertRaises(AuthorizationConfigError):
            is_authorized(self.repo, 'read', self.repo, **self.runtime)
        with self.assertRaises(AuthorizationConfigError):
            is_authorized(self.account.pk, 'read', self.repo, **self.runtime)
        with self.assertRaises(AuthorizationConfigError):
            is_authorized(self.account, self.read.pk, self.repo, **self.runtime)
        with self.assertRaises(AuthorizationConfigError):
            filter_authorized(
                S1Repository.objects.all(), self.repo, 'read', **self.runtime,
            )
        with self.assertRaises(AuthorizationConfigError):
            is_scope_authorized(
                self.repo, 'read', self.repo, trustee=self.trustee,
            )
        with self.assertRaises(AuthorizationConfigError):
            is_scope_authorized(
                self.account.pk, 'read', self.repo, trustee=self.trustee,
            )

    def test_unregistered_resource_and_wrong_queryset_raise(self):
        note = S1UnregisteredNote.objects.create(
            repository=self.repo, text='nope',
        )
        with self.assertRaises(AuthorizationConfigError):
            is_authorized(self.account, 'read', note, **self.runtime)
        with self.assertRaises(AuthorizationConfigError):
            filter_authorized(
                S1UnregisteredNote.objects.all(), self.account, 'read',
                **self.runtime,
            )
        with self.assertRaises(AuthorizationConfigError):
            filter_authorized(
                S1Team.objects.all(), self.account, 'read', **self.runtime,
            )
        with self.assertRaises(AuthorizationConfigError):
            filter_authorized_scope(
                S1Team.objects.all(), self.account, 'read',
                trustee=self.trustee,
            )

    def test_string_without_lookup_raises_on_direct_api(self):
        context = ContextRegistry()
        context.register_identity(S1Repository)
        trustee = TrusteeRegistry(
            requester_model=S1Account,
            scope_model=S1Repository,
            operation_model=S1Operation,
        )
        trustee.register(
            name=S1_DIRECT,
            trustee_model=S1Account,
            grant_model=S1DirectGrant,
            trustee_path='account',
            scope_path='repository',
            operation_path='operation',
        )
        with self.assertRaises(AuthorizationConfigError):
            is_authorized(
                self.account, 'read', self.repo,
                context=context, trustee=trustee,
            )

    def test_empty_adapters_raise(self):
        context = ContextRegistry()
        context.register_identity(S1Repository)
        trustee = TrusteeRegistry(
            requester_model=S1Account,
            scope_model=S1Repository,
            operation_model=S1Operation,
            operation_lookup='code',
        )
        with self.assertRaises(AuthorizationConfigError):
            filter_authorized(
                S1Repository.objects.all(), self.account, 'read',
                context=context, trustee=trustee,
            )

    def test_scope_q_siblings(self):
        S1DirectGrant.objects.create(
            account=self.account, repository=self.repo, operation=self.read,
        )
        with self.assertNumQueries(1):
            self.assertTrue(
                is_scope_authorized(
                    self.account, 'read', self.repo, trustee=self.trustee,
                )
            )
        with self.assertNumQueries(1):
            listed = list(
                S1Repository.objects.filter(
                    authorized_scope_q(
                        S1Repository, self.account, 'read',
                        trustee=self.trustee,
                    )
                ).values_list('pk', flat=True)
            )
        self.assertEqual(listed, [self.repo.pk])
