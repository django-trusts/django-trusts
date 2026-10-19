"""#89: build-on-demand / projection lifecycle on standalone and live registries.

Constructing a catalog freezes that class's recorder. A later
``register`` on the frozen recorder is refused. That freeze-at-build
rule still needs confirmation.

The catalog stores the built registry. There is no path dict on the
owner. Registration after the catalog is built is refused.

Missing-declaration E003 on Content/Junction stays on Zero ``tests/legacy/``.
"""
from unittest.mock import patch
from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.backends import ModelBackend
from django.test import SimpleTestCase, TestCase, override_settings
from tests.apps import configured_catalog, install_writable_registry, live_config, override_apps_ready
from tests.core import KernelHostRequiredMixin
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentGrant
from trusts.apps import implementation_for_path
from trusts.plan.relations import PlanQueryCompiler
from trusts.compile.nodes import Ref
from trusts.errors import TrustsConfigurationError
from trusts.backends import TrustModelBackendMixin
from trusts.compile.factory import RegistryFactory
HOST = HOST_BACKEND
DOCUMENT = DOCUMENT_BACKEND
MIXIN = 'tests.backends.MixinOnlyBackend'

def _contribute_document(registry):
    j = Ref(DocumentGrant)
    registry.register(content=j.document, user=j.user, permission=j.permission)

def _contribute_recorder(recorder):
    recorder.register(
        trust=DocumentGrant, user='user', permission='permission', content='document',
    )

class StandaloneIndependenceTest(SimpleTestCase):

    def test_standalone_stays_writable_after_global_ready(self):
        self.assertTrue(apps.ready)
        first = RegistryFactory()
        second = RegistryFactory()
        self.assertEqual(first.build_registry().records, ())
        _contribute_document(second)
        self.assertEqual(len(second.plan_for(Document).records), 1)
        _contribute_document(first)
        self.assertEqual(len(first.records), 1)
        self.assertEqual(first.build_registry().records, first.records)
        self.assertIsNot(first.records[0], second.records[0])

    def test_build_is_repeatable_and_register_does_not_inspect_apps_ready(self):
        registry = RegistryFactory()
        _contribute_document(registry)
        before = registry.records
        first_build = registry.build_registry()
        second_build = registry.build_registry()
        self.assertIsNot(first_build, second_build)
        self.assertEqual(first_build.records, before)
        self.assertEqual(second_build.records, before)
        self.assertTrue(apps.ready)
        with patch.object(apps, 'ready', True):
            with self.assertRaises(TrustsConfigurationError):
                registry.register(content=Ref(DocumentGrant).document, user=Ref(DocumentGrant).user, permission=Ref(DocumentGrant).permission)
        self.assertEqual(registry.records, before)
        self.assertIs(registry.plan_for(Document).records[0], before[0])

class RegisterAfterBuildLeavesRecordsUnchangedTest(SimpleTestCase):

    def test_valid_duplicate_conflict_and_malformed_all_raise(self):
        registry = RegistryFactory()
        j = Ref(DocumentGrant)
        registry.register(content=j.document, user=j.user, permission=j.permission)
        before = registry.records
        registry.build_registry()
        attempts = (dict(content=j.document, user=j.user, permission=j.permission), dict(content=j.document, user=j.permission, permission=j.user), dict(content='not-a-ref', user=j.user, permission=j.permission))
        for kwargs in attempts:
            with self.assertRaises(TrustsConfigurationError) as ctx:
                registry.register(**kwargs)
            self.assertNotIn('frozen', str(ctx.exception).lower())
        self.assertEqual(registry.records, before)
        self.assertEqual(len(registry.plan_for(Document).records), 1)

class BuiltPlanProjectionsTest(KernelHostRequiredMixin, TestCase):

    def test_built_plan_still_projects(self):
        registry = RegistryFactory()
        _contribute_document(registry)
        before = registry.plan_for(Document)
        registry.build_registry()
        plan = registry.plan_for(Document)
        self.assertEqual(plan.records, before.records)
        user = get_user_model()(pk=1)
        permission = Permission(pk=1)
        exists = plan.content_exists(user, permission)
        self.assertIsNotNone(exists)
        qs = Document.objects.all()
        filtered = registry.filter_authorized(qs, user, permission)
        self.assertIs(filtered.model, Document)

class _CatalogRestoreMixin(object):

    def setUp(self):
        super().setUp()
        from trusts.apps import catalogs
        self._saved_catalogs = dict(catalogs)

    def tearDown(self):
        from trusts.apps import catalogs
        catalogs.clear()
        catalogs.update(self._saved_catalogs)
        super().tearDown()

class LiveBuildLifecycleTest(KernelHostRequiredMixin, _CatalogRestoreMixin, SimpleTestCase):

    def test_rows_before_ready_survive_and_later_register_is_refused(self):
        class _BeforeReady(TrustModelBackendMixin, ModelBackend):
            pass

        backend = _BeforeReady()
        recorder = backend.get_registry()
        _contribute_recorder(recorder)
        catalog = backend.ready()
        self.assertEqual(len(catalog.registry.records), 1)
        self.assertTrue(recorder.frozen)
        with self.assertRaises(TrustsConfigurationError):
            _contribute_recorder(recorder)
        self.assertEqual(len(catalog.registry.records), 1)

    def test_multi_path_reversed_duplicate_and_late_observed_path(self):
        live = live_config()
        document = implementation_for_path(DOCUMENT)
        with override_settings(AUTHENTICATION_BACKENDS=(DOCUMENT, HOST)):
            catalogs = (configured_catalog(document), configured_catalog(live))
            self.assertEqual([catalog.path for catalog in catalogs], [DOCUMENT, HOST])
            self.assertIs(catalogs[0].registry.build_registry(), catalogs[0].registry)
            self.assertIs(catalogs[1].registry.build_registry(), catalogs[1].registry)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, HOST)):
            catalog = configured_catalog(live)
            self.assertEqual(catalog.path, HOST)
            self.assertIsNotNone(catalog.registry)

    def test_ready_does_not_replace_stored_objects(self):
        from tests.backends import HostTrustModelBackend
        from trusts.apps import catalogs
        live = live_config()
        first = catalogs[HostTrustModelBackend]
        live.ready()
        self.assertIs(catalogs[HostTrustModelBackend], first)
        self.assertFalse(hasattr(live, 'registries'))

    def test_late_registry_assignment_stays_writable(self):
        class _LateAssign(TrustModelBackendMixin, ModelBackend):
            pass

        backend = _LateAssign()
        recorder = backend.get_registry()
        self.assertFalse(recorder.frozen)
        _contribute_recorder(recorder)
        self.assertEqual(len(recorder.principals[Document]), 1)
        catalog = backend.ready()
        self.assertEqual(len(catalog.registry.records), 1)
        self.assertTrue(recorder.frozen)

    def test_assignment_before_ready_stays_writable_on_read(self):
        class _OpenThenReady(TrustModelBackendMixin, ModelBackend):
            pass

        backend = _OpenThenReady()
        recorder = backend.get_registry()
        with override_apps_ready(False):
            self.assertFalse(recorder.frozen)
            _contribute_recorder(recorder)
        catalog = backend.ready()
        self.assertEqual(len(catalog.registry.records), 1)
        with self.assertRaises(TrustsConfigurationError):
            _contribute_recorder(recorder)
        self.assertEqual(len(catalog.registry.records), 1)
        self.assertEqual(len(recorder.principals[Document]), 1)

    def test_standalone_appconfig_remains_writable_after_ready(self):
        from tests.backends import HostTrustModelBackend
        from tests.core.test_issue108 import HostImplConfig, _bind
        from trusts.apps import catalogs
        isolated = _bind(HostImplConfig, ready=False)
        self.assertFalse(isolated.apps.ready)
        first = catalogs[HostTrustModelBackend]
        private = RegistryFactory()
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            isolated.ready()
        self.assertIs(catalogs[HostTrustModelBackend], first)
        _contribute_document(private)
        self.assertEqual(len(private.records), 1)

class SentinelAfterFirstReadTest(KernelHostRequiredMixin, _CatalogRestoreMixin, SimpleTestCase):

    def test_same_instance_reentry_is_noop_after_first_read(self):
        live = live_config()
        catalog = configured_catalog(live)
        before = catalog.registry.records
        live.ready()
        self.assertEqual(catalog.registry.records, before)
        self.assertIs(configured_catalog(live), catalog)

    def test_package_ready_after_supported_read_leaves_registry_writable(self):
        from tests.backends import HostTrustModelBackend
        from trusts.apps import catalogs
        live = live_config()
        catalog = catalogs[HostTrustModelBackend]
        recorder = HostTrustModelBackend().get_registry()
        self.assertTrue(recorder.frozen)
        before = catalog.registry.records
        live.ready()
        self.assertIs(catalogs[HostTrustModelBackend], catalog)
        self.assertEqual(catalog.registry.records, before)
        with self.assertRaises(TrustsConfigurationError):
            recorder.register(
                trust=DocumentGrant, user='user',
                permission='permission', content='document',
            )

class _LateBackend(TrustModelBackendMixin, ModelBackend):
    """A class whose recorder has not been built yet."""

class BackendQuestionAfterLateRegistrationTest(SimpleTestCase):
    """Freeze happens when the catalog is constructed."""

    def test_register_after_build_is_refused(self):
        from trusts.errors import TrustsConfigurationError
        backend = _LateBackend()
        recorder = backend.get_registry()
        catalog = backend.ready()
        self.assertIs(catalog.registry, backend.registry)
        self.assertTrue(recorder.frozen)
        with self.assertRaisesRegex(TrustsConfigurationError, 'register refused: this recorder is frozen'):
            recorder.register(trust=DocumentGrant, user='user', permission='permission', content='document')
        self.assertEqual(catalog.registry.records, ())

class HandleBuildRegistrySignalTest(SimpleTestCase):
    """A configured path holds a registry. The registry builds itself."""

    def test_factory_builds_a_fresh_registry(self):
        registry = RegistryFactory(path='tests.core.builder')
        handle = registry
        first = handle.build_registry()
        second = handle.build_registry()
        self.assertIsNot(first, second)
        self.assertEqual(first.records, ())
        _contribute_document(registry)
        self.assertEqual(handle.build_registry().records, registry.records)
        self.assertEqual(first.records, ())
