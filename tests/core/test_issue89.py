"""#89: freeze / projection lifecycle on standalone and live host registries.

Missing-declaration E003 on Content/Junction stays on Zero ``tests/legacy/``.
"""

from unittest.mock import patch

from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.test import SimpleTestCase, TestCase, override_settings

from tests.apps import install_writable_registry, live_config, override_apps_ready
from tests.core import KernelHostRequiredMixin
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.models import Document, DocumentGrant
from trusts.apps import implementation_for_path
from trusts.core import Ref, TrustsConfigurationError, TrustsRegistry


HOST = HOST_BACKEND
DOCUMENT = DOCUMENT_BACKEND
MIXIN = 'tests.backends.MixinOnlyBackend'


def _contribute_document(registry):
    j = Ref(DocumentGrant)
    registry.register(
        content=j.document,
        user=j.user,
        permission=j.permission,
    )


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
        _contribute_document(second)
        self.assertEqual(len(second.plan_for(Document).records), 1)
        self.assertFalse(second.frozen)
        with self.assertRaises(TrustsConfigurationError) as ctx:
            _contribute_document(first)
        self.assertIn('frozen', str(ctx.exception).lower())
        self.assertEqual(first.records, ())

    def test_freeze_is_idempotent_and_register_does_not_inspect_apps_ready(self):
        registry = TrustsRegistry()
        _contribute_document(registry)
        before = registry.records
        registry.freeze()
        registry.freeze()
        self.assertTrue(registry.frozen)
        self.assertTrue(apps.ready)
        with patch.object(apps, 'ready', True):
            with self.assertRaises(TrustsConfigurationError):
                registry.register(
                    content=Ref(DocumentGrant).document,
                    user=Ref(DocumentGrant).user,
                    permission=Ref(DocumentGrant).permission,
                )
        self.assertEqual(registry.records, before)
        self.assertIs(registry.plan_for(Document).records[0], before[0])


class RegisterAfterFreezeLeavesRecordsUnchangedTest(SimpleTestCase):
    def test_valid_duplicate_conflict_and_malformed_all_raise(self):
        registry = TrustsRegistry()
        j = Ref(DocumentGrant)
        registry.register(
            content=j.document,
            user=j.user,
            permission=j.permission,
        )
        before = registry.records
        registry.freeze()
        attempts = (
            dict(content=j.document, user=j.user, permission=j.permission),
            dict(content=j.document, user=j.permission, permission=j.user),
            dict(content='not-a-ref', user=j.user, permission=j.permission),
        )
        for kwargs in attempts:
            with self.assertRaises(TrustsConfigurationError) as ctx:
                registry.register(**kwargs)
            self.assertIn('frozen', str(ctx.exception).lower())
        self.assertEqual(registry.records, before)
        self.assertEqual(len(registry.plan_for(Document).records), 1)


class FrozenPlanProjectionsTest(TestCase):
    def test_frozen_plan_still_projects(self):
        registry = TrustsRegistry()
        _contribute_document(registry)
        before = registry.plan_for(Document)
        registry.freeze()
        plan = registry.plan_for(Document)
        self.assertEqual(plan.records, before.records)
        user = get_user_model()(pk=1)
        permission = Permission(pk=1)
        exists = plan.content_exists(user, permission)
        self.assertIsNotNone(exists)
        qs = Document.objects.all()
        filtered = registry.filter_authorized(qs, user, permission)
        self.assertIs(filtered.model, Document)


class _LiveRegistryRestoreMixin(object):
    def setUp(self):
        super().setUp()
        self.live = live_config()
        self.saved_registries = dict(self.live.registries)

    def tearDown(self):
        self.live.registries.clear()
        self.live.registries.update(self.saved_registries)
        super().tearDown()


class LiveFreezeLifecycleTest(
    KernelHostRequiredMixin, _LiveRegistryRestoreMixin, SimpleTestCase,
):
    def test_writable_during_contributor_ready_then_freeze_on_first_read(self):
        live = live_config()
        isolated = TrustsRegistry()
        live.registries[HOST] = isolated
        self.assertFalse(isolated.frozen)
        with override_apps_ready(False):
            handle = live.configured_backend()
            self.assertIs(handle.registry, isolated)
            self.assertFalse(isolated.frozen)
            _contribute_document(isolated)
            alias = live.registry
            self.assertIs(alias, isolated)
            self.assertFalse(isolated.frozen)
        handle = live.configured_backend()
        self.assertIs(handle.registry, isolated)
        self.assertTrue(isolated.frozen)
        with self.assertRaises(TrustsConfigurationError):
            _contribute_document(isolated)
        self.assertEqual(len(isolated.plan_for(Document).records), 1)

    def test_multi_path_reversed_duplicate_and_late_observed_path(self):
        live = live_config()
        document = implementation_for_path(DOCUMENT)
        with override_settings(AUTHENTICATION_BACKENDS=(DOCUMENT, HOST)):
            handles = (
                document.configured_backend(),
                live.configured_backend(),
            )
            self.assertEqual(
                [handle.path for handle in handles], [DOCUMENT, HOST],
            )
            self.assertTrue(handles[0].registry.frozen)
            self.assertTrue(handles[1].registry.frozen)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, HOST)):
            handle = live.configured_backend()
            self.assertEqual(handle.path, HOST)
            self.assertTrue(handle.registry.frozen)

    def test_ready_does_not_replace_stored_objects_when_freezing(self):
        live = live_config()
        store = live.registries
        first = live.registries[HOST]
        live.ready()
        self.assertIs(live.registries, store)
        self.assertIs(live.registries[HOST], first)
        self.assertTrue(first.frozen)

    def test_late_registry_assignment_freezes_replacement(self):
        live = live_config()
        replacement = TrustsRegistry()
        self.assertFalse(replacement.frozen)
        live.registry = replacement
        self.assertTrue(replacement.frozen)
        self.assertIs(live.registries[HOST], replacement)
        with self.assertRaises(TrustsConfigurationError) as ctx:
            _contribute_document(replacement)
        self.assertIn('frozen', str(ctx.exception).lower())
        self.assertEqual(replacement.records, ())

    def test_assignment_before_ready_stays_writable_then_freezes_on_read(self):
        live = live_config()
        replacement = TrustsRegistry()
        with override_apps_ready(False):
            live.registry = replacement
            self.assertIs(live.registries[HOST], replacement)
            self.assertFalse(replacement.frozen)
            _contribute_document(replacement)
            self.assertFalse(replacement.frozen)
        handle = live.configured_backend()
        self.assertIs(handle.registry, replacement)
        self.assertTrue(replacement.frozen)
        before = replacement.records
        with self.assertRaises(TrustsConfigurationError):
            _contribute_document(replacement)
        self.assertEqual(replacement.records, before)

    def test_standalone_appconfig_does_not_auto_freeze(self):
        from tests.core.test_issue108 import HostImplConfig, _bind

        isolated = _bind(HostImplConfig, ready=False)
        self.assertFalse(isolated._apps_instance_ready())
        first = isolated._ensure(HOST)
        self.assertFalse(first.frozen)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            isolated.ready()
        self.assertFalse(first.frozen)


class SentinelAfterFreezeTest(
    KernelHostRequiredMixin, _LiveRegistryRestoreMixin, SimpleTestCase,
):
    def test_same_instance_reentry_is_noop_after_freeze(self):
        live = live_config()
        handle = live.configured_backend()
        self.assertTrue(handle.registry.frozen)
        before = handle.registry.records
        with patch.object(
            handle.registry, 'register', wraps=handle.registry.register,
        ) as register:
            live.ready()
        register.assert_not_called()
        self.assertEqual(handle.registry.records, before)

    def test_package_ready_after_supported_read_cannot_mutate_new_registry(self):
        live = live_config()
        isolated = install_writable_registry(live, HOST)
        live.configured_backend()
        self.assertTrue(isolated.frozen)
        live.ready()
        self.assertEqual(isolated.records, ())
