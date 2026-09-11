"""S8: freeze live registries and report detectable missing declarations.

Structural and behavioral tests only — no source-token or
``inspect.getsource`` assertions. Isolated ``TrustsRegistry()``
instances stay independent of Django readiness.
"""

from contextlib import contextmanager
from io import StringIO
from unittest.mock import patch

from django.apps import apps
from django.contrib.auth.models import Group, Permission, User
from django.core.checks import Error, run_checks
from django.core.management import call_command
from django.db import models
from django.test import SimpleTestCase, TestCase, override_settings

from tests.apps import (
    TestsConfig,
    forget_models,
    install_writable_registry,
    isolated_owner,
    live_config,
    override_apps_ready,
)
import tests as tests_module
from tests.models import (
    AutoAdminCategory,
    AutoAdminJunction,
    Category,
    ManualAdminCategory,
    TestGroupJunction,
    Ticket,
)
from trusts.checks import (
    CHECK_ID_MISSING_DECLARATION,
    CHECK_ID_LEGACY_CALLBACK_WARNING,
    check_missing_declarations,
    check_permission_conditions,
    check_query_compilers,
)
from trusts.core import Ref, TrustsConfigurationError, TrustsRegistry
from trusts.zero.models import Content, Junction, Trust, TrustUserPermission


CONCRETE = 'trusts.zero.backends.TrustModelBackend'
MIXIN = 'tests.backends.MixinOnlyBackend'
HOST = 'tests.backends.HostTrustModelBackend'


def _e003(messages=None):
    if messages is None:
        messages = check_missing_declarations(None)
    return [message for message in messages if message.id == CHECK_ID_MISSING_DECLARATION]


def _objs(messages):
    return {message.obj for message in messages}


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


def _new_contributor(apps_registry):
    contributor = TestsConfig('tests', tests_module)
    contributor.apps = apps_registry
    return contributor


@contextmanager
def _dynamic_models(*model_classes):
    try:
        yield model_classes
    finally:
        forget_models(*model_classes)


def _forget_leftover_detectable_models():
    known = {
        Category, Ticket, Trust, TestGroupJunction, AutoAdminCategory,
        ManualAdminCategory, AutoAdminJunction,
    }
    leftovers = [
        model for model in apps.get_models()
        if model not in known
        and (
            (issubclass(model, Content) and model is not Content)
            or (issubclass(model, Junction) and model is not Junction)
        )
        and not model._meta.abstract
        and not model._meta.proxy
    ]
    forget_models(*leftovers)


class _RegistryRestoreMixin(object):
    def setUp(self):
        super().setUp()
        self.live = live_config()
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


class StandaloneFreezeIndependenceTest(SimpleTestCase):
    def test_standalone_stays_writable_after_global_ready(self):
        self.assertTrue(apps.ready)
        first = TrustsRegistry()
        second = TrustsRegistry()
        self.assertFalse(first.frozen)
        self.assertFalse(second.frozen)
        first.freeze()
        self.assertTrue(first.frozen)
        self.assertFalse(second.frozen)
        _contribute_ticket(second)
        self.assertEqual(len(second.plan_for(Ticket).records), 1)
        self.assertFalse(second.frozen)
        with self.assertRaises(TrustsConfigurationError) as ctx:
            _contribute_ticket(first)
        self.assertIn('frozen', str(ctx.exception).lower())
        self.assertEqual(first.records, ())

    def test_freeze_is_idempotent_and_register_does_not_inspect_apps_ready(self):
        registry = TrustsRegistry()
        _contribute_category(registry)
        before = registry.records
        registry.freeze()
        registry.freeze()
        self.assertTrue(registry.frozen)
        self.assertTrue(apps.ready)
        with patch.object(apps, 'ready', True):
            with self.assertRaises(TrustsConfigurationError):
                _contribute_ticket(registry)
        self.assertEqual(registry.records, before)
        self.assertIs(registry.plan_for(Category).records[0], before[0])


class RegisterAfterFreezeLeavesRecordsUnchangedTest(SimpleTestCase):
    def test_valid_duplicate_conflict_and_malformed_all_raise(self):
        registry = TrustsRegistry()
        j = Ref(TrustUserPermission)
        rev = Category._meta.get_field('trust').remote_field.get_accessor_name()
        registry.register(
            content=getattr(j.trust, rev),
            user=j.entity,
            permission=j.permission,
        )
        before = registry.records
        registry.freeze()

        ticket_rev = Ticket._meta.get_field('trust').remote_field.get_accessor_name()
        attempts = (
            dict(
                content=getattr(j.trust, ticket_rev),
                user=j.entity,
                permission=j.permission,
            ),
            dict(
                content=getattr(j.trust, rev),
                user=j.entity,
                permission=j.permission,
            ),
            dict(
                content=getattr(j.trust, rev),
                user=j.permission,
                permission=j.entity,
            ),
            dict(content='not-a-ref', user=j.entity, permission=j.permission),
        )
        for kwargs in attempts:
            with self.assertRaises(TrustsConfigurationError) as ctx:
                registry.register(**kwargs)
            self.assertIn('frozen', str(ctx.exception).lower())
        self.assertEqual(registry.records, before)
        self.assertEqual(len(registry.plan_for(Category).records), 1)
        self.assertEqual(len(registry.plan_for(Ticket).records), 0)


class FrozenPlanProjectionsTest(SimpleTestCase):
    def test_frozen_plan_still_projects(self):
        registry = TrustsRegistry()
        _contribute_category(registry)
        before = registry.plan_for(Category)
        registry.freeze()
        plan = registry.plan_for(Category)
        self.assertEqual(plan.records, before.records)
        user = User(pk=1)
        permission = Permission(pk=1)
        exists = plan.content_exists(user, permission)
        self.assertIsNotNone(exists)
        self.assertFalse(
            registry.plan_for(Ticket).records,
        )
        qs = Category.objects.all()
        filtered = registry.filter_authorized(qs, user, permission)
        self.assertIs(filtered.model, Category)


class LiveFreezeLifecycleTest(_RegistryRestoreMixin, SimpleTestCase):
    def test_writable_during_contributor_ready_then_freeze_on_first_read(self):
        isolated = TrustsRegistry()
        self.live.registries[CONCRETE] = isolated
        self.assertFalse(isolated.frozen)
        with override_apps_ready(False):
            handle = self.live.configured_backend()
            self.assertIs(handle.registry, isolated)
            self.assertFalse(isolated.frozen)
            _contribute_category(isolated)
            alias = self.live.registry
            self.assertIs(alias, isolated)
            self.assertFalse(isolated.frozen)
            handles = self.live.configured_handles()
            self.assertIs(handles[0].registry, isolated)
            self.assertFalse(isolated.frozen)
        handle = self.live.configured_backend()
        self.assertIs(handle.registry, isolated)
        self.assertTrue(isolated.frozen)
        self.assertIs(self.live.registry, isolated)
        self.assertIs(self.live.configured_handles()[0].registry, isolated)
        with self.assertRaises(TrustsConfigurationError):
            _contribute_ticket(isolated)
        self.assertEqual(len(isolated.plan_for(Category).records), 1)
        self.assertEqual(len(isolated.plan_for(Ticket).records), 0)

    def test_multi_path_reversed_duplicate_and_late_observed_path(self):
        with override_settings(AUTHENTICATION_BACKENDS=(MIXIN, CONCRETE)):
            handles = self.live.configured_handles()
            self.assertEqual([handle.path for handle in handles], [MIXIN, CONCRETE])
            self.assertIs(handles[0].registry, self.live.registries[MIXIN])
            self.assertIs(handles[1].registry, self.live.registries[CONCRETE])
            self.assertTrue(handles[0].registry.frozen)
            self.assertTrue(handles[1].registry.frozen)
            self.assertIs(
                self.live.configured_backend(MIXIN).registry,
                self.live.registries[MIXIN],
            )
            self.assertIs(
                self.live.configured_backend(CONCRETE).registry,
                self.live.registries[CONCRETE],
            )
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, CONCRETE)):
            handle = self.live.configured_backend()
            self.assertEqual(handle.path, CONCRETE)
            self.assertIs(handle.registry, self.live.registries[CONCRETE])
            self.assertTrue(handle.registry.frozen)
            self.assertIs(self.live.registry, handle.registry)
        self.assertNotIn(HOST, self.live.registries)
        with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, HOST)):
            late = self.live.configured_backend(HOST)
            self.assertIs(late.registry, self.live.registries[HOST])
            self.assertTrue(late.registry.frozen)
            with self.assertRaises(TrustsConfigurationError):
                _contribute_category(late.registry)
            again = self.live.configured_backend(HOST)
            self.assertIs(again.registry, late.registry)

    def test_ready_does_not_replace_stored_objects_when_freezing(self):
        store = self.live.registries
        first = self.live.registries[CONCRETE]
        self.live.ready()
        self.assertIs(self.live.registries, store)
        self.assertIs(self.live.registries[CONCRETE], first)
        self.assertIs(self.live.configured_backend().registry, first)
        self.assertTrue(first.frozen)

    def test_late_registry_assignment_freezes_replacement(self):
        replacement = TrustsRegistry()
        self.assertFalse(replacement.frozen)
        before = self.live.registries[CONCRETE].records
        self.live.registry = replacement
        self.assertTrue(replacement.frozen)
        self.assertIs(self.live.registries[CONCRETE], replacement)
        with self.assertRaises(TrustsConfigurationError) as ctx:
            _contribute_category(replacement)
        self.assertIn('frozen', str(ctx.exception).lower())
        self.assertEqual(replacement.records, ())
        self.assertIs(self.live.configured_backend().registry, replacement)
        self.assertEqual(self.live.registry.records, ())
        self.assertNotEqual(before, replacement.records)

    def test_assignment_before_ready_stays_writable_then_freezes_on_read(self):
        replacement = TrustsRegistry()
        with override_apps_ready(False):
            self.live.registry = replacement
            self.assertIs(self.live.registries[CONCRETE], replacement)
            self.assertFalse(replacement.frozen)
            _contribute_category(replacement)
            self.assertFalse(replacement.frozen)
        self.assertFalse(replacement.frozen)
        handle = self.live.configured_backend()
        self.assertIs(handle.registry, replacement)
        self.assertTrue(replacement.frozen)
        before = replacement.records
        with self.assertRaises(TrustsConfigurationError):
            _contribute_ticket(replacement)
        self.assertEqual(replacement.records, before)
        self.assertEqual(len(replacement.plan_for(Category).records), 1)

    def test_standalone_appconfig_does_not_auto_freeze(self):
        import trusts

        isolated = isolated_owner()
        self.assertFalse(isolated._apps_instance_ready())
        first = isolated.registry
        self.assertFalse(first.frozen)
        isolated.ready()
        self.assertIs(isolated.registry, first)
        self.assertFalse(first.frozen)
        # C2: Trust-as-content is donated by Zero onto the live kernel
        # store, not by a standalone AppConfig.ready().
        self.assertFalse(first.plan_for(Trust).records)


class SentinelAfterFreezeTest(_RegistryRestoreMixin, SimpleTestCase):
    def test_same_instance_reentry_is_noop_after_freeze(self):
        handle = self.live.configured_backend()
        self.assertTrue(handle.registry.frozen)
        before = handle.registry.records
        with patch.object(
            handle.registry, 'register', wraps=handle.registry.register,
        ) as register:
            self.live.ready()
            self.live_contributor.ready()
        register.assert_not_called()
        self.assertEqual(handle.registry.records, before)
        self.assertIs(
            self.live_contributor._trusts_tup_category_registry_id,
            handle.registry,
        )

    def test_new_contributor_cannot_mutate_frozen_live_store(self):
        handle = self.live.configured_backend()
        before = handle.registry.records
        contributor = _new_contributor(apps)
        with self.assertRaises(TrustsConfigurationError) as ctx:
            contributor.ready()
        self.assertIn('frozen', str(ctx.exception).lower())
        self.assertEqual(handle.registry.records, before)
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_category_registry_id', None)
        )
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_ticket_registry_id', None)
        )
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_group_registry_id', None)
        )

    def test_partial_late_contribution_raises_without_setting_sentinel(self):
        isolated = install_writable_registry(self.live, CONCRETE)
        self.live.configured_backend()
        self.assertTrue(isolated.frozen)
        contributor = _new_contributor(apps)
        contributor._trusts_tup_category_registry_id = isolated
        with self.assertRaises(TrustsConfigurationError):
            contributor.ready()
        self.assertIs(contributor._trusts_tup_category_registry_id, isolated)
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_ticket_registry_id', None)
        )
        self.assertEqual(isolated.records, ())

    def test_package_ready_after_supported_read_cannot_mutate_new_registry(self):
        isolated = install_writable_registry(self.live, CONCRETE)
        self.live.configured_backend()
        self.assertTrue(isolated.frozen)
        # C2 kernel ready() does not donate Trust-as-content (Zero does
        # that on the live store during populate). Re-entry must not
        # mutate the frozen replacement.
        self.live.ready()
        self.assertFalse(isolated.plan_for(Trust).records)


class MissingDeclarationCheckTest(_RegistryRestoreMixin, TestCase):
    def setUp(self):
        super().setUp()
        _forget_leftover_detectable_models()

    def test_declared_terminals_have_no_e003(self):
        messages = _e003()
        self.assertEqual(messages, [])
        self.assertFalse(
            _objs(messages) & {Category, Ticket, Trust, TestGroupJunction, Group}
        )

    def test_undeclared_content_and_junction_are_reported(self):
        class OrphanSheet(Content):
            title = models.CharField(max_length=12)

            class Meta:
                app_label = 'trusts_tests'
                managed = False

        class OrphanTarget(models.Model):
            title = models.CharField(max_length=12)

            class Meta:
                app_label = 'trusts_tests'
                managed = False

        class OrphanJunction(Junction):
            content = models.ForeignKey(
                OrphanTarget, unique=True, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                managed = False

        with _dynamic_models(OrphanSheet, OrphanTarget, OrphanJunction):
            messages = _e003()
            objs = _objs(messages)
            self.assertIn(OrphanSheet, objs)
            self.assertIn(OrphanJunction, objs)
            self.assertNotIn(OrphanTarget, objs)
            self.assertNotIn(Category, objs)
            self.assertTrue(all(isinstance(message, Error) for message in messages))
            self.assertTrue(all(message.hint for message in messages))
            sheet = [message for message in messages if message.obj is OrphanSheet]
            junction = [
                message for message in messages if message.obj is OrphanJunction
            ]
            self.assertEqual(len(sheet), 1)
            self.assertEqual(len(junction), 1)
            self.assertIn('OrphanSheet', sheet[0].msg)
            self.assertIn('OrphanJunction', junction[0].msg)
            self.assertIn('exact backend path', sheet[0].hint)

    def test_coverage_on_second_handle_only_clears_e003(self):
        class SecondSheet(Content):
            title = models.CharField(max_length=12)

            class Meta:
                app_label = 'trusts_tests'
                managed = False

        with _dynamic_models(SecondSheet):
            self.assertIn(SecondSheet, _objs(_e003()))
            with override_settings(AUTHENTICATION_BACKENDS=(CONCRETE, MIXIN)):
                mixin = install_writable_registry(self.live, MIXIN)
                j = Ref(TrustUserPermission)
                rev = SecondSheet._meta.get_field(
                    'trust',
                ).remote_field.get_accessor_name()
                mixin.register(
                    content=getattr(j.trust, rev),
                    user=j.entity,
                    permission=j.permission,
                )
                self.assertNotIn(SecondSheet, _objs(_e003()))
                self.assertFalse(
                    self.live.configured_backend(CONCRETE).registry.plan_for(
                        SecondSheet,
                    ).records
                )
                self.assertTrue(
                    self.live.configured_backend(MIXIN).registry.plan_for(
                        SecondSheet,
                    ).records
                )

    def test_abstract_proxy_and_manual_dependents_are_not_reported(self):
        class AbstractHolder(Content):
            class Meta:
                abstract = True
                app_label = 'trusts_tests'

        class ManualImage(models.Model):
            title = models.CharField(max_length=12)

            class Meta:
                app_label = 'trusts_tests'
                managed = False

        with _dynamic_models(ManualImage):
            messages = _e003()
            objs = _objs(messages)
            self.assertNotIn(AbstractHolder, objs)
            self.assertNotIn(AutoAdminCategory, objs)
            self.assertNotIn(ManualAdminCategory, objs)
            self.assertNotIn(AutoAdminJunction, objs)
            self.assertNotIn(ManualImage, objs)

    def test_malformed_junction_is_diagnostic_not_a_crash(self):
        class BrokenJunction(Junction):
            extra = models.ForeignKey(
                User, null=True, on_delete=models.SET_NULL,
            )
            other = models.ForeignKey(
                Group, null=True, on_delete=models.SET_NULL,
            )

            class Meta:
                app_label = 'trusts_tests'
                managed = False

        with _dynamic_models(BrokenJunction):
            messages = _e003()
            broken = [message for message in messages if message.obj is BrokenJunction]
            self.assertEqual(len(broken), 1)
            self.assertIsInstance(broken[0], Error)
            self.assertIn('malformed', broken[0].msg.lower())
            self.assertEqual(broken[0].id, CHECK_ID_MISSING_DECLARATION)

    def test_check_is_zero_sql_and_does_not_register(self):
        live = self.live.configured_backend().registry
        before = live.records
        sentinels = (
            getattr(self.live, '_trusts_tup_trust_registry_id', None),
            getattr(self.live_contributor, '_trusts_tup_category_registry_id', None),
        )
        with self.assertNumQueries(0):
            messages = check_missing_declarations(None)
        self.assertEqual(_e003(messages), [])
        self.assertEqual(live.records, before)
        self.assertEqual(
            (
                getattr(self.live, '_trusts_tup_trust_registry_id', None),
                getattr(self.live_contributor, '_trusts_tup_category_registry_id', None),
            ),
            sentinels,
        )
        with patch.object(live, 'register') as register:
            check_missing_declarations(None)
        register.assert_not_called()

    def test_manage_py_check_subset_and_direct_invocation(self):
        with self.assertNumQueries(0):
            out = StringIO()
            err = StringIO()
            call_command('check', stdout=out, stderr=err)
            combined = out.getvalue() + err.getvalue()
        self.assertNotIn(CHECK_ID_MISSING_DECLARATION, combined)
        with self.assertNumQueries(0):
            out = StringIO()
            err = StringIO()
            call_command('check', 'trusts_kernel_host', stdout=out, stderr=err)
            subset = out.getvalue() + err.getvalue()
        self.assertNotIn(CHECK_ID_MISSING_DECLARATION, subset)
        trusts_only = [live_config()]
        with self.assertNumQueries(0):
            subset_messages = check_missing_declarations(app_configs=trusts_only)
        self.assertEqual(_e003(subset_messages), [])

    def test_e003_coexists_and_silencing_does_not_authorize(self):
        class QuietSheet(Content):
            title = models.CharField(max_length=12)

            class Meta:
                app_label = 'trusts_tests'
                managed = False

        with _dynamic_models(QuietSheet):
            all_ids = {message.id for message in run_checks()}
            self.assertIn(CHECK_ID_MISSING_DECLARATION, all_ids)
            condition_ids = {message.id for message in check_permission_conditions(None)}
            compiler_ids = {message.id for message in check_query_compilers(None)}
            self.assertNotIn(CHECK_ID_MISSING_DECLARATION, condition_ids)
            self.assertNotIn(CHECK_ID_MISSING_DECLARATION, compiler_ids)
            self.assertNotIn(CHECK_ID_LEGACY_CALLBACK_WARNING, _e003())
            with override_settings(
                SILENCED_SYSTEM_CHECKS=['trusts.E003', 'fields.W342'],
            ):
                silenced = check_missing_declarations(None)
                self.assertTrue(silenced)
                self.assertTrue(all(message.is_silenced() for message in silenced))
                call_command('check', stdout=StringIO(), stderr=StringIO())
            self.assertFalse(
                self.live.configured_backend().registry.plan_for(QuietSheet).records
            )


class LiveHandleIdentityTest(_RegistryRestoreMixin, SimpleTestCase):
    def test_supported_surfaces_return_the_same_stored_object(self):
        stored = self.live.registries[CONCRETE]
        handle = self.live.configured_backend()
        alias = self.live.registry
        handles = self.live.configured_handles()
        self.assertIs(handle.registry, stored)
        self.assertIs(alias, stored)
        self.assertIs(handles[0].registry, stored)
        self.assertTrue(stored.frozen)
