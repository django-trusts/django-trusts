"""GH-shaped noun-independent authorization proof (#43 Step 1).

Private vocabulary: Account, Organization, Team, PermissionBundle,
Policy, Repository. Public relations used to authorize:

    account.teams
    team.permission_bundles
    repository.policy

``organization.teams`` is owner containment and is not sufficient for a
grant. Kernel APIs only (not ``User.has_perm``). Isolated registries;
the process-wide Zero path is unchanged. Does not close #43.
"""

import inspect
from pathlib import Path

from django.test import TestCase, TransactionTestCase

from trusts.context import Context, ContextRegistrationError, ContextRegistry
from trusts.models import (
    DIRECT_TRUSTEE,
    GROUP_TRUSTEE,
    prepare_context_registry,
    prepare_trustee_registry,
)
from trusts.path import (
    AuthorizationBranch,
    AuthorizationPathError,
    compose,
    filter_granted,
    row_is_granted,
)
from trusts.trustee import Trustee, TrusteeRegistrationError, TrusteeRegistry
from tests.gh_vocab.models import (
    Account,
    GhTrapGrant,
    Operation,
    Organization,
    PermissionBundle,
    Policy,
    Repository,
    Team,
    TeamPolicyGrant,
    UnregisteredGhNote,
)
from tests.models import TEST_TEAM_TRUSTEE


FORBIDDEN_PUBLIC_RELATIONS = (
    'trusts', 'trustees', 'contexts', 'roles', 'groups', 'member_teams',
)
GH_TEAM_ADAPTER = 'team'


def _gh_source():
    return Path(inspect.getfile(Account)).read_text()


def _related_accessor_names(model):
    names = set()
    for field in model._meta.get_fields():
        names.add(field.name)
        related_name = getattr(field, 'related_name', None)
        if isinstance(related_name, str):
            names.add(related_name)
        query_name = None
        if getattr(field, 'is_relation', False):
            remote = getattr(field, 'remote_field', None)
            if remote is not None:
                query_name = getattr(remote, 'related_name', None)
                if isinstance(query_name, str):
                    names.add(query_name)
            getter = getattr(field, 'related_query_name', None)
            if callable(getter):
                try:
                    qn = getter()
                except Exception:
                    qn = None
                if isinstance(qn, str):
                    names.add(qn)
    return names


def _gh_maps(grant_model=None):
    """Isolated GH registries. Never touch the process-wide maps."""
    if grant_model is None:
        grant_model = TeamPolicyGrant
    context = ContextRegistry()
    context.register_direct(Repository, scope_field='policy')
    trustee = TrusteeRegistry(
        requester_model=Account,
        scope_model=Policy,
        operation_model=Operation,
    )
    trustee.register(
        name=GH_TEAM_ADAPTER,
        trustee_model=Team,
        grant_model=grant_model,
        trustee_path='team',
        scope_path='policy',
        operation_path='operation',
        membership_path='members',
        constraint_paths=('team__permission_bundles__operations',),
    )
    return context, trustee


class GhVocabNamingTest(TestCase):
    def test_package_and_models_use_gh_not_full_external_name(self):
        source = _gh_source()
        self.assertNotIn('GitHub', source)
        self.assertNotIn('github', source.lower())
        self.assertIn('GH-shaped', source)
        self.assertEqual(Account._meta.app_label, 'gh_vocab')
        self.assertEqual(Account._meta.object_name, 'Account')
        self.assertEqual(Organization._meta.object_name, 'Organization')
        self.assertEqual(Team._meta.object_name, 'Team')
        self.assertEqual(PermissionBundle._meta.object_name, 'PermissionBundle')
        self.assertEqual(Policy._meta.object_name, 'Policy')
        self.assertEqual(Repository._meta.object_name, 'Repository')

    def test_public_relations_are_the_advertised_names(self):
        self.assertEqual(
            Account._meta.get_field('teams').related_model, Team,
        )
        members = Team._meta.get_field('members')
        self.assertEqual(members.related_model, Account)
        self.assertEqual(members.remote_field.related_name, 'teams')
        organization = Team._meta.get_field('organization')
        self.assertEqual(organization.related_model, Organization)
        self.assertEqual(organization.remote_field.related_name, 'teams')
        bundles = Team._meta.get_field('permission_bundles')
        self.assertTrue(bundles.one_to_many)
        self.assertEqual(
            Repository._meta.get_field('policy').related_model, Policy,
        )

    def test_no_required_django_trusts_public_relations(self):
        for model in (
            Account, Organization, Team, PermissionBundle, Policy,
            Repository, Operation, TeamPolicyGrant,
        ):
            names = _related_accessor_names(model)
            leaked = names.intersection(FORBIDDEN_PUBLIC_RELATIONS)
            self.assertFalse(
                leaked,
                '%s exposes forbidden public relations %s' % (
                    model._meta.label, sorted(leaked),
                ),
            )
            for name in FORBIDDEN_PUBLIC_RELATIONS:
                self.assertFalse(hasattr(model, name))

    def test_kernel_does_not_inject_zero_adapter_names_or_auth_permission(self):
        context, trustee = _gh_maps()
        path = compose(
            Repository, None, context=context, trustee=trustee,
        )
        self.assertEqual(path.adapter_names, (GH_TEAM_ADAPTER,))
        self.assertNotIn(DIRECT_TRUSTEE, path.adapter_names)
        self.assertNotIn(GROUP_TRUSTEE, path.adapter_names)
        self.assertNotEqual(path.operation_model._meta.label, 'auth.Permission')
        self.assertEqual(len(path.branches), 1)
        branch = path.branches[0]
        self.assertIsInstance(branch, AuthorizationBranch)
        self.assertIs(branch.subject_model, Team)
        self.assertEqual(branch.membership_path, 'members')
        self.assertEqual(
            branch.constraint_paths,
            ('team__permission_bundles__operations',),
        )
        prepare_trustee_registry()
        process_names = [adapter.name for adapter in Trustee.adapters()]
        self.assertIn(DIRECT_TRUSTEE, process_names)
        self.assertIn(GROUP_TRUSTEE, process_names)
        self.assertIn(TEST_TEAM_TRUSTEE, process_names)
        team_adapter = Trustee.get(TEST_TEAM_TRUSTEE)
        self.assertNotEqual(team_adapter.trustee_model, Team)
        self.assertFalse(Context.is_registered(Repository))


class GhVocabProofTest(TransactionTestCase):
    reset_sequences = True

    def setUp(self):
        super(GhVocabProofTest, self).setUp()
        self.organization = Organization.objects.create(name='acme')
        self.other_org = Organization.objects.create(name='other')
        self.team = Team.objects.create(
            organization=self.organization, name='writers',
        )
        self.other_team = Team.objects.create(
            organization=self.other_org, name='outsiders',
        )
        self.member = Account.objects.create(name='member')
        self.stranger = Account.objects.create(name='stranger')
        self.team.members.add(self.member)
        self.read = Operation.objects.create(code='read')
        self.write = Operation.objects.create(code='write')
        self.bundle = PermissionBundle.objects.create(
            team=self.team, name='reader-bundle',
        )
        self.bundle.operations.add(self.read)
        self.policy_a = Policy.objects.create(title='policy-a')
        self.policy_b = Policy.objects.create(title='policy-b')
        self.repo_a = Repository.objects.create(
            policy=self.policy_a, title='repo-a',
        )
        self.repo_b = Repository.objects.create(
            policy=self.policy_b, title='repo-b',
        )
        TeamPolicyGrant.objects.create(
            policy=self.policy_a, team=self.team, operation=self.read,
        )
        self.context, self.trustee = _gh_maps()
        self.path = compose(
            Repository, self.read, context=self.context, trustee=self.trustee,
        )

    def test_ir_fields_match_r3_registration(self):
        self.assertIs(self.path.resource_model, Repository)
        self.assertEqual(self.path.resource_to_scope, 'policy')
        self.assertIs(self.path.scope_model, Policy)
        self.assertIs(self.path.requester_model, Account)
        self.assertEqual(len(self.path.branches), 1)
        branch = self.path.branches[0]
        self.assertIsInstance(branch, AuthorizationBranch)
        self.assertEqual(branch.requester_from_grant, 'team__members')
        self.assertIs(branch.subject_model, Team)
        self.assertEqual(branch.subject_from_grant, 'team')
        self.assertEqual(branch.membership_path, 'members')
        self.assertIs(branch.grant_model, TeamPolicyGrant)
        self.assertEqual(branch.grant_to_scope, 'policy')
        self.assertEqual(branch.grant_to_operation, 'operation')
        self.assertIs(self.path.operation_model, Operation)
        self.assertEqual(
            branch.constraint_paths,
            ('team__permission_bundles__operations',),
        )

    def test_account_teams_membership_grants_without_organization_ownership(self):
        self.assertIn(self.team, list(self.member.teams.all()))
        self.assertIn(self.team, list(self.organization.teams.all()))
        self.assertFalse(hasattr(self.member, 'organizations'))
        with self.assertNumQueries(1):
            self.assertTrue(
                self.path.row_is_granted(
                    self.repo_a, self.member, self.read,
                )
            )
        with self.assertNumQueries(1):
            listed = list(
                self.path.filter_granted(
                    Repository.objects.all(), self.member, self.read,
                ).order_by('pk').values_list('pk', flat=True)
            )
        self.assertEqual(listed, [self.repo_a.pk])

    def test_organization_containment_without_membership_is_denied(self):
        """Repository-owning org containing a Team grants nothing without members."""
        self.assertIn(self.team, list(self.organization.teams.all()))
        self.assertNotIn(self.team, list(self.stranger.teams.all()))
        self.assertFalse(self.team.members.filter(pk=self.stranger.pk).exists())
        with self.assertNumQueries(1):
            self.assertFalse(
                self.path.row_is_granted(
                    self.repo_a, self.stranger, self.read,
                )
            )
        with self.assertNumQueries(1):
            listed = list(
                self.path.filter_granted(
                    Repository.objects.all(), self.stranger, self.read,
                ).values_list('pk', flat=True)
            )
        self.assertEqual(listed, [])

    def test_wrong_operation_is_denied(self):
        with self.assertNumQueries(1):
            self.assertFalse(
                self.path.row_is_granted(
                    self.repo_a, self.member, self.write,
                )
            )

    def test_bundle_constraint_is_ceiling_not_a_grant(self):
        TeamPolicyGrant.objects.create(
            policy=self.policy_a, team=self.team, operation=self.write,
        )
        with self.assertNumQueries(1):
            self.assertFalse(
                row_is_granted(
                    self.repo_a, self.member, self.write,
                    context=self.context, trustee=self.trustee,
                )
            )
        self.bundle.operations.add(self.write)
        with self.assertNumQueries(1):
            self.assertTrue(
                row_is_granted(
                    self.repo_a, self.member, self.write,
                    context=self.context, trustee=self.trustee,
                )
            )

    def test_wrong_policy_repo_is_denied(self):
        with self.assertNumQueries(1):
            self.assertFalse(
                self.path.row_is_granted(
                    self.repo_b, self.member, self.read,
                )
            )

    def test_other_org_team_grant_does_not_leak(self):
        other_bundle = PermissionBundle.objects.create(
            team=self.other_team, name='other-bundle',
        )
        other_bundle.operations.add(self.read)
        TeamPolicyGrant.objects.create(
            policy=self.policy_b, team=self.other_team, operation=self.read,
        )
        with self.assertNumQueries(1):
            self.assertFalse(
                self.path.row_is_granted(
                    self.repo_b, self.member, self.read,
                )
            )
        self.other_team.members.add(self.member)
        with self.assertNumQueries(1):
            self.assertTrue(
                self.path.row_is_granted(
                    self.repo_b, self.member, self.read,
                )
            )

    def test_module_helpers_match_path_methods(self):
        with self.assertNumQueries(1):
            via_path = self.path.row_is_granted(
                self.repo_a, self.member, self.read,
            )
        with self.assertNumQueries(1):
            via_module = row_is_granted(
                self.repo_a, self.member, self.read,
                context=self.context, trustee=self.trustee,
            )
        self.assertEqual(via_path, via_module)
        with self.assertNumQueries(1):
            listed = list(
                filter_granted(
                    Repository.objects.all(), self.member, self.read,
                    context=self.context, trustee=self.trustee,
                ).order_by('pk').values_list('pk', flat=True)
            )
        self.assertEqual(listed, [self.repo_a.pk])

    def test_same_compiled_predicate_for_exists_and_filter(self):
        exists_sql = str(
            Repository.objects.filter(pk=self.repo_a.pk).filter(
                self.path.grant_q(self.member, self.read)
            ).query
        )
        list_sql = str(
            self.path.filter_granted(
                Repository.objects.all(), self.member, self.read,
            ).query
        )
        combined = (exists_sql + list_sql).lower().replace('_', '').replace('"', '')
        self.assertIn('exists', combined)
        self.assertIn('teampolicygrant', combined)
        self.assertIn('permissionbundle', combined)

    def test_getters_are_not_executed(self):
        grant = GhTrapGrant.objects.create(
            policy=self.policy_a, team=self.team, operation=self.read,
        )
        context, trustee = _gh_maps(grant_model=GhTrapGrant)
        path = compose(
            Repository, self.read, context=context, trustee=trustee,
        )
        with self.assertNumQueries(1):
            self.assertTrue(
                path.row_is_granted(self.repo_a, self.member, self.read)
            )
        with self.assertRaises(AssertionError):
            grant.forbidden
        with self.assertRaises(AssertionError):
            grant.get_team()


class GhVocabFailClosedTest(TestCase):
    def test_unregistered_note_cannot_compose(self):
        context, trustee = _gh_maps()
        with self.assertRaises(AuthorizationPathError):
            compose(
                UnregisteredGhNote, None, context=context, trustee=trustee,
            )

    def test_late_registration_is_rejected_after_freeze(self):
        context, trustee = _gh_maps()
        compose(Repository, None, context=context, trustee=trustee)
        self.assertTrue(context.is_frozen())
        self.assertTrue(trustee.is_frozen())
        with self.assertRaises(Exception):
            context.register_related(UnregisteredGhNote, through='repository')
        self.assertFalse(context.is_registered(UnregisteredGhNote))

    def test_wrong_membership_terminal_fails_at_trustee_registration(self):
        trustee = TrusteeRegistry(
            requester_model=Account,
            scope_model=Policy,
            operation_model=Operation,
        )
        with self.assertRaises(TrusteeRegistrationError) as ctx:
            trustee.register(
                name=GH_TEAM_ADAPTER,
                trustee_model=Team,
                grant_model=TeamPolicyGrant,
                trustee_path='team',
                scope_path='policy',
                operation_path='operation',
                membership_path='organization',
            )
        self.assertIn('not the configured requester', str(ctx.exception))

    def test_process_wide_compose_of_gh_resource_fails_closed(self):
        prepare_context_registry()
        prepare_trustee_registry()
        with self.assertRaises(AuthorizationPathError):
            compose(Repository, None)

    def test_malformed_many_valued_resource_path_fails_closed(self):
        context = ContextRegistry()
        with self.assertRaises(ContextRegistrationError):
            context.register_direct(Team, scope_field='members')
