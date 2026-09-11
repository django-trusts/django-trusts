"""S3a: path-scoped registries and aggregate list authorization (issue #75).

Backend ``has_perm`` / enumeration stay on the historical path. Structural
and behavioral tests only — no source-token or ``inspect.getsource``
assertions.
"""

from unittest.mock import patch

from django.apps import apps
from django.contrib.auth.models import Group, Permission, User
from django.contrib.contenttypes.models import ContentType
from django.core.checks import Error, run_checks
from django.core.management import call_command
from django.db.models.query import QuerySet
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import isolate_apps

from tests.apps import (
    TestsConfig,
    apply_zero_trust_donation,
    install_writable_registry,
    isolate_live_registry,
    override_apps_ready,
)
from tests.backends import (
    HostTrustModelBackend,
    MalformedCompilerBackend,
    MixinOnlyBackend,
    MissingCompilerBackend,
    RaisingCompilerBackend,
)
import tests as tests_module
from tests.models import Category, Organization, Ticket
from trusts.apps import AppConfig as TrustsAppConfig, kernel_config
from trusts.backends import (
    HistoricalGroupQueryCompiler,
    TrustModelBackend,
    TrustModelBackendMixin,
)
from trusts.checks import CHECK_ID_MISSING_COMPILER, check_query_compilers
from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    Ref,
    TrustsCompilerError,
    TrustsConfigurationError,
    TrustsRegistry,
    compiler_for_class,
    granted,
)
from trusts.models import Content, Trust, TrustUserPermission
from trusts.query import trust_grant_q
from trusts.tests import (
    enable_local_group_grant,
    get_or_create_root_user,
)


CONCRETE = 'trusts.backends.TrustModelBackend'
MIXIN = 'tests.backends.MixinOnlyBackend'
HOST = 'tests.backends.HostTrustModelBackend'
ALIASED = 'tests.backends.AliasedTrustModelBackend'
MISSING = 'tests.backends.MissingCompilerBackend'
MALFORMED = 'tests.backends.MalformedCompilerBackend'
RAISING = 'tests.backends.RaisingCompilerBackend'


def _pks(qs):
    return set(qs.values_list('pk', flat=True))


def _perm(model, codename):
    return Permission.objects.get(
        content_type=ContentType.objects.get_for_model(model),
        codename=codename,
    )


def _new_contributor(apps_registry):
    contributor = TestsConfig('tests', tests_module)
    contributor.apps = apps_registry
    return contributor


def _contribute_category(registry):
    j = Ref(TrustUserPermission)
    rev = Category._meta.get_field('trust').remote_field.get_accessor_name()
    registry.register(
        content=getattr(j.trust, rev),
        user=j.entity,
        permission=j.permission,
    )


def _contribute_ticket(registry):
    j = Ref(TrustUserPermission)
    rev = Ticket._meta.get_field('trust').remote_field.get_accessor_name()
    registry.register(
        content=getattr(j.trust, rev),
        user=j.entity,
        permission=j.permission,
    )


def _category_rows(registry):
    return [
        record for record in registry.records
        if record.root is TrustUserPermission
        and record.content_model is Category._meta.concrete_model
    ]


def _trust_rows(registry):
    return [
        record for record in registry.records
        if record.root is TrustUserPermission
        and record.content_model is Trust._meta.concrete_model
    ]


def _evaluate(handle, queryset, user, permission):
    plan = handle.registry.plan_for(
        queryset, user=user, permission=permission,
    )
    return handle.compiler.complete_exists(plan, queryset, user, permission)


class _RegistryRestoreMixin(object):
    def setUp(self):
        super().setUp()
        self.live = kernel_config()
        self.saved_registries = dict(self.live.registries)
        self.saved_trust_sentinel = getattr(
            self.live, '_trusts_tup_trust_registry_id', None
        )
        self.saved_trust_ids = getattr(
            self.live, '_trusts_tup_trust_registry_ids', None
        )
        self.live_contributor = apps.get_app_config('trusts_tests')
        self.saved_category_sentinel = getattr(
            self.live_contributor, '_trusts_tup_category_registry_id', None
        )
        self.saved_ticket_sentinel = getattr(
            self.live_contributor, '_trusts_tup_ticket_registry_id', None
        )
        self.saved_group_sentinel = getattr(
            self.live_contributor, '_trusts_tup_group_registry_id', None
        )

    def tearDown(self):
        self.live.registries.clear()
        self.live.registries.update(self.saved_registries)
        self.live._trusts_tup_trust_registry_id = self.saved_trust_sentinel
        if self.saved_trust_ids is None:
            if hasattr(self.live, '_trusts_tup_trust_registry_ids'):
                delattr(self.live, '_trusts_tup_trust_registry_ids')
        else:
            self.live._trusts_tup_trust_registry_ids = self.saved_trust_ids
        self.live_contributor._trusts_tup_category_registry_id = (
            self.saved_category_sentinel
        )
        self.live_contributor._trusts_tup_ticket_registry_id = (
            self.saved_ticket_sentinel
        )
        self.live_contributor._trusts_tup_group_registry_id = (
            self.saved_group_sentinel
        )
        super().tearDown()


class PathScopedRegistryStoreTest(_RegistryRestoreMixin, SimpleTestCase):
    def test_one_path_registry_alias_is_exact_store(self):
        handle = self.live.configured_backend()
        self.assertEqual(handle.path, CONCRETE)
        self.assertIs(handle.registry, self.live.registry)
        self.assertIs(self.live.registry, self.live.registries[CONCRETE])
        self.assertIsInstance(handle, BackendHandle)
        self.assertIs(handle.compiler, TrustModelBackend.query_compiler)
        self.assertIsInstance(handle.compiler, HistoricalGroupQueryCompiler)

    def test_duplicate_identical_paths_dedupe(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, CONCRETE)):
            paths = self.live._configured_trusts_paths()
            self.assertEqual(paths, (CONCRETE,))
            self.assertIs(self.live.registry, self.live.registries[CONCRETE])
            handle = self.live.configured_backend()
            self.assertEqual(handle.path, CONCRETE)
            self.assertIs(handle.registry, self.live.registry)

    def test_same_class_alias_is_ambiguity_error(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, ALIASED)):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                self.live._configured_trusts_paths()
            self.assertIn('multiple paths', str(ctx.exception))
            with self.assertRaises(TrustsConfigurationError):
                self.live.configured_backend()
            with self.assertRaises(TrustsConfigurationError):
                self.live.registry

    def test_unconfigured_path_fails_loud(self):
        with self.assertRaises(TrustsConfigurationError) as ctx:
            self.live.configured_backend(MIXIN)
        self.assertIn(MIXIN, str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError):
            self.live.path_for_class(MixinOnlyBackend)
        with self.assertRaises(TrustsConfigurationError):
            self.live.path_for_backend(MixinOnlyBackend())

    def test_zero_and_multiple_alias_access_fail(self):
        with override_settings(AUTHENTICATION_BACKENDS=(
            'django.contrib.auth.backends.ModelBackend',
        )):
            self.assertEqual(self.live._configured_trusts_paths(), ())
            with self.assertRaises(TrustsConfigurationError):
                self.live.registry
            with self.assertRaises(TrustsConfigurationError):
                self.live.configured_backend()
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            with self.assertRaises(TrustsConfigurationError):
                self.live.registry
            with self.assertRaises(TrustsConfigurationError):
                self.live.configured_backend()
            handle = self.live.configured_backend(MIXIN)
            self.assertEqual(handle.path, MIXIN)
            self.assertIs(handle.registry, self.live.registries[MIXIN])

    def test_ready_does_not_replace_store_or_registry(self):
        store = self.live.registries
        first = self.live.registry
        self.live.ready()
        self.assertIs(self.live.registries, store)
        self.assertIs(self.live.registry, first)
        self.assertIs(self.live.registries[CONCRETE], first)

    def test_swapped_registry_identity_receives_declaration_again(self):
        isolated = TrustsRegistry()
        isolate_live_registry(self.live, isolated, CONCRETE)
        self.assertIs(self.live.registries[CONCRETE], isolated)
        with override_apps_ready(False):
            apply_zero_trust_donation(self.live)
        self.assertIs(self.live._trusts_tup_trust_registry_id, isolated)
        self.assertEqual(len(_trust_rows(isolated)), 1)

    def test_new_appconfig_gets_its_own_store(self):
        import trusts

        isolated = TrustsAppConfig('trusts', trusts)
        self.assertEqual(isolated.registries, {})
        first = isolated.registry
        self.assertIs(isolated.registries[CONCRETE], first)
        isolated.ready()
        apply_zero_trust_donation(isolated)
        self.assertIs(isolated.registry, first)
        self.assertIsNot(isolated.registry, self.live.registry)
        self.assertEqual(len(_trust_rows(isolated.registry)), 1)

    def test_compiler_is_class_owned_not_instance_state(self):
        first = TrustModelBackend()
        second = TrustModelBackend()
        self.assertIs(first.query_compiler, TrustModelBackend.query_compiler)
        self.assertIs(second.query_compiler, first.query_compiler)
        self.assertIs(
            MixinOnlyBackend.query_compiler,
            TrustModelBackendMixin.query_compiler,
        )
        self.assertIsInstance(
            TrustModelBackendMixin.query_compiler, PlanQueryCompiler,
        )
        self.assertIs(
            compiler_for_class(TrustModelBackend),
            TrustModelBackend.query_compiler,
        )
        self.assertIs(
            compiler_for_class(MixinOnlyBackend),
            MixinOnlyBackend.query_compiler,
        )
        self.assertIsNot(
            TrustModelBackend.query_compiler,
            TrustModelBackendMixin.query_compiler,
        )
        self.assertIs(
            HostTrustModelBackend.query_compiler,
            TrustModelBackend.query_compiler,
        )


@isolate_apps(
    'tests',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    attr_name='isolated_apps',
)
class IsolatedAppsPathStoreTest(SimpleTestCase):
    def test_isolate_apps_without_trusts_does_not_donate(self):
        live = kernel_config()
        before = live.registry.records
        self.assertFalse(self.isolated_apps.is_installed('trusts'))
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_category_registry_id', None)
        )
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_ticket_registry_id', None)
        )
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_group_registry_id', None)
        )
        self.assertEqual(live.registry.records, before)


class ContributionPathTest(_RegistryRestoreMixin, SimpleTestCase):
    def test_explicit_path_contribution_writes_one_registry(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            mixin = install_writable_registry(self.live, MIXIN)
            _contribute_category(mixin)
            handle_b = self.live.configured_backend(MIXIN)
            self.assertEqual(len(_category_rows(handle_b.registry)), 1)
            handle_a = self.live.configured_backend(CONCRETE)
            self.assertEqual(len(_category_rows(handle_a.registry)), 1)
            self.assertIsNot(handle_a.registry, handle_b.registry)

    def test_omitted_ambiguous_path_fails_before_writing(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            contributor = _new_contributor(apps)
            before_a = self.live.registries[CONCRETE].records
            with self.assertRaises(TrustsConfigurationError) as ctx:
                contributor.ready()
            self.assertIn('explicit path', str(ctx.exception))
            self.assertNotIn(MIXIN, self.live.registries)
            self.assertEqual(self.live.registries[CONCRETE].records, before_a)
            self.assertIsNone(
                getattr(contributor, '_trusts_tup_category_registry_id', None)
            )
            self.assertIsNone(
                getattr(contributor, '_trusts_tup_group_registry_id', None)
            )

    def test_no_mixin_fan_out(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            handle_b = self.live.configured_backend(MIXIN)
            self.assertFalse(handle_b.registry.plan_for(Category).records)
            self.assertFalse(handle_b.registry.plan_for(Ticket).records)
            self.assertFalse(handle_b.registry.plan_for(Group).records)
            handle_a = self.live.configured_backend(CONCRETE)
            self.assertTrue(handle_a.registry.plan_for(Category).records)
            self.assertTrue(handle_a.registry.plan_for(Ticket).records)
            self.assertTrue(handle_a.registry.plan_for(Group).records)

    def test_mixin_only_does_not_receive_package_trust(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            apply_zero_trust_donation(self.live)
            handle_a = self.live.configured_backend(CONCRETE)
            handle_b = self.live.configured_backend(MIXIN)
            self.assertTrue(handle_a.registry.plan_for(Trust).records)
            self.assertFalse(handle_b.registry.plan_for(Trust).records)
            self.assertEqual(len(_trust_rows(handle_b.registry)), 0)

    def test_concrete_subclass_receives_package_trust(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, HOST)):
            apply_zero_trust_donation(self.live)
            handle_host = self.live.configured_backend(HOST)
            self.assertEqual(len(_trust_rows(handle_host.registry)), 1)
            handle_a = self.live.configured_backend(CONCRETE)
            self.assertEqual(len(_trust_rows(handle_a.registry)), 1)
            self.assertIsNot(handle_host.registry, handle_a.registry)

    def test_contributor_reentry_does_not_duplicate(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, HOST)):
            apply_zero_trust_donation(self.live)
            handle_host = self.live.configured_backend(HOST)
            before = handle_host.registry.records
            with patch.object(
                handle_host.registry, 'register',
                wraps=handle_host.registry.register,
            ) as register:
                apply_zero_trust_donation(self.live)
            register.assert_not_called()
            self.assertEqual(handle_host.registry.records, before)
            self.assertEqual(len(_trust_rows(handle_host.registry)), 1)

    def test_host_reentry_after_swapped_host_registry(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, HOST)):
            apply_zero_trust_donation(self.live)
            isolated = TrustsRegistry()
            self.live.registries[HOST] = isolated
            with override_apps_ready(False):
                apply_zero_trust_donation(self.live)
            self.assertIs(self.live.registries[HOST], isolated)
            self.assertEqual(len(_trust_rows(isolated)), 1)


class CompilerProtocolTest(_RegistryRestoreMixin, SimpleTestCase):
    def test_malformed_compiler_is_e004(self):
        with override_settings(AUTHENTICATION_BACKENDS=(MISSING,)):
            messages = check_query_compilers(None)
            errors = [m for m in messages if m.id == CHECK_ID_MISSING_COMPILER]
            self.assertEqual(len(errors), 1)
            self.assertIsInstance(errors[0], Error)
            self.assertIn('not query-capable', errors[0].msg)
        with override_settings(AUTHENTICATION_BACKENDS=(MALFORMED,)):
            messages = check_query_compilers(None)
            errors = [m for m in messages if m.id == CHECK_ID_MISSING_COMPILER]
            self.assertEqual(len(errors), 1)

    def test_valid_compilers_emit_no_e004(self):
        messages = [m for m in run_checks() if m.id == CHECK_ID_MISSING_COMPILER]
        self.assertEqual(messages, [])

    def test_silenced_e004_still_fails_at_runtime(self):
        with override_settings(
            AUTHENTICATION_BACKENDS=(MISSING,),
            SILENCED_SYSTEM_CHECKS=['trusts.E004', 'fields.W342'],
        ):
            messages = check_query_compilers(None)
            self.assertTrue(messages)
            self.assertTrue(all(m.is_silenced() for m in messages))
            with self.assertRaises(TrustsCompilerError):
                self.live.configured_backend()

    def test_broken_second_path_is_not_omitted(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MISSING)):
            with self.assertRaises(TrustsCompilerError):
                self.live.configured_handles()

    def test_raising_compiler_propagates(self):
        with override_settings(AUTHENTICATION_BACKENDS=(RAISING,)):
            install_writable_registry(self.live, RAISING, _contribute_category)
            handle = self.live.configured_backend()
            with self.assertRaises(RuntimeError) as ctx:
                granted(
                    (handle,), Category, User(),
                    Permission(), kind='complete',
                )
            self.assertIn('compiler exploded', str(ctx.exception))


class CompilerCheckQueryCountTest(TestCase):
    def test_e004_check_issues_zero_sql(self):
        with override_settings(AUTHENTICATION_BACKENDS=(MISSING, CONCRETE)):
            with self.assertNumQueries(0):
                check_query_compilers(None)


class OnePathPermittedUnchangedTest(TestCase):
    def setUp(self):
        super().setUp()
        call_command('create_trust_root')
        get_or_create_root_user(self)
        self.alice = User.objects.create_user('alice', 'alice@example.com', 'x')
        self.carol = User.objects.create_user('carol', 'carol@example.com', 'x')
        for user in (self.alice, self.carol):
            user.is_active = True
            user.save()
        root = Trust.objects.get_root()
        self.trust_a = Trust(settlor=self.alice, trust=root, title='Trust A')
        self.trust_a.save()
        self.cat_a = Category.objects.create(trust=self.trust_a, name='keep')
        self.change = _perm(Category, 'change_category')
        self.change_code = 'trusts_tests.change_category'
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change,
        ).save()
        self.carol_group = Group.objects.create(name='carol-s3a')
        self.carol.groups.add(self.carol_group)
        self.change.group_set.add(self.carol_group)
        enable_local_group_grant(self.trust_a, self.carol_group, self.change)
        self.alice = User.objects.get(pk=self.alice.pk)
        self.carol = User.objects.get(pk=self.carol.pk)

    def test_category_ticket_trust_object_results_unchanged(self):
        self.assertEqual(
            _pks(Category.objects.permitted(self.change_code, self.alice)),
            {self.cat_a.pk},
        )
        self.assertEqual(
            _pks(Category.objects.permitted(self.change_code, self.carol)),
            {self.cat_a.pk},
        )
        organization = Organization.objects.create(name='Org', manager=self.alice)
        ticket = Ticket.objects.create(
            trust=self.trust_a, title='t', owner=self.alice,
            organization=organization, status='open',
        )
        TrustUserPermission(
            trust=self.trust_a,
            entity=self.alice,
            permission=_perm(Ticket, 'change_ticket'),
        ).save()
        self.alice = User.objects.get(pk=self.alice.pk)
        self.assertIn(
            ticket.pk,
            _pks(Ticket.objects.permitted('trusts_tests.change_ticket', self.alice)),
        )
        child = Trust(settlor=self.alice, trust=self.trust_a, title='Child A')
        child.save()
        TrustUserPermission(
            trust=self.trust_a,
            entity=self.alice,
            permission=_perm(Trust, 'change_trust'),
        ).save()
        self.alice = User.objects.get(pk=self.alice.pk)
        self.assertIn(
            child.pk,
            _pks(Trust.objects.permitted('trusts.change_trust', self.alice)),
        )


class TwoPathAuthorizationTest(_RegistryRestoreMixin, TestCase):
    def setUp(self):
        super().setUp()
        call_command('create_trust_root')
        get_or_create_root_user(self)
        self.alice = User.objects.create_user('alice75', 'alice75@example.com', 'x')
        self.carol = User.objects.create_user('carol75', 'carol75@example.com', 'x')
        for user in (self.alice, self.carol):
            user.is_active = True
            user.save()
        root = Trust.objects.get_root()
        self.trust_a = Trust(settlor=self.alice, trust=root, title='S3a A')
        self.trust_a.save()
        self.trust_b = Trust(settlor=self.alice, trust=root, title='S3a B')
        self.trust_b.save()
        self.cat_a = Category.objects.create(trust=self.trust_a, name='c-a')
        self.cat_b = Category.objects.create(trust=self.trust_b, name='c-b')
        self.change = _perm(Category, 'change_category')
        self.change_code = 'trusts_tests.change_category'
        self.ticket_perm = _perm(Ticket, 'change_ticket')
        self.ticket_code = 'trusts_tests.change_ticket'

    def _reload(self):
        self.alice = User.objects.get(pk=self.alice.pk)
        self.carol = User.objects.get(pk=self.carol.pk)

    def test_grant_only_through_a(self):
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change,
        ).save()
        self._reload()
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            handle_a = self.live.configured_backend(CONCRETE)
            handle_b = self.live.configured_backend(MIXIN)
            self.assertTrue(handle_a.registry.plan_for(Category).records)
            self.assertFalse(handle_b.registry.plan_for(Category).records)
            qs = Category.objects.all()
            pred_a = _evaluate(handle_a, qs, self.alice, self.change)
            pred_b = _evaluate(handle_b, qs, self.alice, self.change)
            self.assertIsNotNone(pred_a)
            self.assertIsNone(pred_b)
            self.assertEqual(
                _pks(qs.filter(pred_a)),
                {self.cat_a.pk},
            )
            permitted = Category.objects.permitted(self.change_code, self.alice)
            self.assertIsInstance(permitted, QuerySet)
            self.assertIsNone(permitted._result_cache)
            with self.assertNumQueries(1):
                self.assertEqual(_pks(permitted), {self.cat_a.pk})

    def test_grant_only_through_b(self):
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change,
        ).save()
        self._reload()
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            self.live.registries[CONCRETE] = TrustsRegistry()
            install_writable_registry(self.live, MIXIN, _contribute_category)
            handle_b = self.live.configured_backend(MIXIN)
            handle_a = self.live.configured_backend(CONCRETE)
            self.assertFalse(handle_a.registry.plan_for(Category).records)
            self.assertTrue(handle_b.registry.plan_for(Category).records)
            qs = Category.objects.all()
            self.assertIsNone(_evaluate(handle_a, qs, self.alice, self.change))
            pred_b = _evaluate(handle_b, qs, self.alice, self.change)
            self.assertIsNotNone(pred_b)
            self.assertEqual(_pks(qs.filter(pred_b)), {self.cat_a.pk})
            self.assertEqual(
                _pks(Category.objects.permitted(self.change_code, self.alice)),
                {self.cat_a.pk},
            )

    def test_grant_through_neither(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            install_writable_registry(self.live, MIXIN, _contribute_category)
            handle_b = self.live.configured_backend(MIXIN)
            self.assertFalse(
                Category.objects.permitted(self.change_code, self.alice).exists()
            )

    def test_aggregate_ors_both_complete_proofs_in_one_statement(self):
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change,
        ).save()
        alice_group = Group.objects.create(name='alice-s3a-or')
        self.alice.groups.add(alice_group)
        self.change.group_set.add(alice_group)
        enable_local_group_grant(self.trust_b, alice_group, self.change)
        self._reload()
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            install_writable_registry(self.live, MIXIN, _contribute_category)
            handle_b = self.live.configured_backend(MIXIN)
            handle_a = self.live.configured_backend(CONCRETE)
            qs = Category.objects.all()
            pred_a = _evaluate(handle_a, qs, self.alice, self.change)
            pred_b = _evaluate(handle_b, qs, self.alice, self.change)
            # A: TUP on cat_a plus historical group on cat_b.
            # B: TUP on cat_a only; no TrustGroup inheritance.
            self.assertEqual(_pks(qs.filter(pred_a)), {self.cat_a.pk, self.cat_b.pk})
            self.assertEqual(_pks(qs.filter(pred_b)), {self.cat_a.pk})
            permitted = Category.objects.permitted(self.change_code, self.alice)
            self.assertIsInstance(permitted, QuerySet)
            self.assertIsNone(permitted._result_cache)
            with self.assertNumQueries(1):
                self.assertEqual(_pks(permitted), {self.cat_a.pk, self.cat_b.pk})
            page = Category.objects.permitted(
                self.change_code, self.alice,
            ).order_by('pk')[:1]
            self.assertIsNone(page._result_cache)
            with self.assertNumQueries(1):
                self.assertEqual(list(page), [self.cat_a])

    def test_failed_ceiling_cannot_use_other_path_fragment(self):
        self.carol_group = Group.objects.create(name='carol-s3a-ceiling')
        self.carol.groups.add(self.carol_group)
        self.change.group_set.add(self.carol_group)
        enable_local_group_grant(self.trust_a, self.carol_group, self.change)
        self.change.group_set.remove(self.carol_group)
        self._reload()
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            install_writable_registry(self.live, MIXIN, _contribute_category)
            handle_b = self.live.configured_backend(MIXIN)
            qs = Category.objects.all()
            handle_a = self.live.configured_backend(CONCRETE)
            pred_a = _evaluate(handle_a, qs, self.carol, self.change)
            pred_b = _evaluate(handle_b, qs, self.carol, self.change)
            self.assertEqual(_pks(qs.filter(pred_a)), set())
            self.assertEqual(_pks(qs.filter(pred_b)), set())
            self.assertFalse(
                Category.objects.permitted(self.change_code, self.carol).exists()
            )

    def test_different_terminals_route_only_through_applicable_handles(self):
        organization = Organization.objects.create(name='S3aOrg', manager=self.alice)
        ticket = Ticket.objects.create(
            trust=self.trust_a, title='s3a-t', owner=self.alice,
            organization=organization, status='open',
        )
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.change,
        ).save()
        TrustUserPermission(
            trust=self.trust_a, entity=self.alice, permission=self.ticket_perm,
        ).save()
        self._reload()
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            install_writable_registry(self.live, CONCRETE, _contribute_category)
            install_writable_registry(self.live, MIXIN, _contribute_ticket)
            handle_a = self.live.configured_backend(CONCRETE)
            handle_b = self.live.configured_backend(MIXIN)
            self.assertTrue(handle_a.registry.plan_for(Category).records)
            self.assertFalse(handle_a.registry.plan_for(Ticket).records)
            self.assertFalse(handle_b.registry.plan_for(Category).records)
            self.assertTrue(handle_b.registry.plan_for(Ticket).records)
            self.assertEqual(
                _pks(Category.objects.permitted(self.change_code, self.alice)),
                {self.cat_a.pk},
            )
            self.assertEqual(
                _pks(Ticket.objects.permitted(self.ticket_code, self.alice)),
                {ticket.pk},
            )
            self.assertIsNone(
                _evaluate(handle_b, Category.objects.all(), self.alice, self.change)
            )
            self.assertIsNone(
                _evaluate(
                    handle_a, Ticket.objects.all(), self.alice, self.ticket_perm,
                )
            )


class CompilerIsolationTest(_RegistryRestoreMixin, TestCase):
    def setUp(self):
        super().setUp()
        call_command('create_trust_root')
        get_or_create_root_user(self)
        self.carol = User.objects.create_user('carol-iso', 'carol-iso@example.com', 'x')
        self.carol.is_active = True
        self.carol.save()
        root = Trust.objects.get_root()
        self.trust_a = Trust(settlor=self.carol, trust=root, title='iso')
        self.trust_a.save()
        self.cat_a = Category.objects.create(trust=self.trust_a, name='iso-c')
        self.change = _perm(Category, 'change_category')
        self.change_code = 'trusts_tests.change_category'
        self.carol_group = Group.objects.create(name='carol-iso-group')
        self.carol.groups.add(self.carol_group)
        self.change.group_set.add(self.carol_group)
        enable_local_group_grant(self.trust_a, self.carol_group, self.change)
        self.carol = User.objects.get(pk=self.carol.pk)

    def test_concrete_group_grant_is_not_inherited_by_mixin(self):
        self.assertFalse(
            TrustUserPermission.objects.filter(entity=self.carol).exists()
        )
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
            install_writable_registry(self.live, MIXIN, _contribute_category)
            handle_b = self.live.configured_backend(MIXIN)
            handle_a = self.live.configured_backend(CONCRETE)
            qs = Category.objects.all()
            pred_a = _evaluate(handle_a, qs, self.carol, self.change)
            pred_b = _evaluate(handle_b, qs, self.carol, self.change)
            self.assertIsNotNone(pred_a)
            self.assertIsNotNone(pred_b)
            self.assertEqual(_pks(qs.filter(pred_a)), {self.cat_a.pk})
            self.assertEqual(_pks(qs.filter(pred_b)), set())
            permitted = Category.objects.permitted(self.change_code, self.carol)
            with self.assertNumQueries(1):
                self.assertEqual(_pks(permitted), {self.cat_a.pk})

    def test_mixin_only_alone_denies_historical_group(self):
        with override_settings(AUTHENTICATION_BACKENDS=(MIXIN,)):
            install_writable_registry(self.live, MIXIN, _contribute_category)
            handle = self.live.configured_backend()
            self.assertIsInstance(handle.compiler, PlanQueryCompiler)
            self.assertFalse(handle.registry.plan_for(Trust).records)
            qs = Category.objects.all()
            pred = _evaluate(handle, qs, self.carol, self.change)
            self.assertIsNotNone(pred)
            self.assertEqual(_pks(qs.filter(pred)), set())
            with patch('trusts.query.trust_grant_q', wraps=trust_grant_q) as grant_q:
                result = Category.objects.permitted(self.change_code, self.carol)
                self.assertEqual(_pks(result), set())
            grant_q.assert_not_called()

    def test_raising_compiler_is_not_caught_by_aggregate(self):
        with override_settings(AUTHENTICATION_BACKENDS=(RAISING,)):
            install_writable_registry(self.live, RAISING, _contribute_category)
            handle = self.live.configured_backend()
            with self.assertRaises(RuntimeError):
                list(Category.objects.permitted(self.change_code, self.carol))

    def test_silenced_e004_permitted_still_raises(self):
        with override_settings(
            AUTHENTICATION_BACKENDS=(MISSING,),
            SILENCED_SYSTEM_CHECKS=['trusts.E004', 'fields.W342'],
        ):
            with self.assertRaises(TrustsCompilerError):
                list(Category.objects.permitted(self.change_code, self.carol))

    def test_broken_second_path_does_not_narrow_to_first(self):
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MISSING)):
            with self.assertRaises(TrustsCompilerError):
                list(Category.objects.permitted(self.change_code, self.carol))


class ContentConditionsPreservedTest(TestCase):
    def test_conditions_registry_still_lives_on_content(self):
        self.assertTrue(hasattr(Content, '_conditions'))
        self.assertIsNotNone(
            Content.get_permission_condition_record(Trust, 'own')
        )
