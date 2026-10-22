"""#89: build-on-demand / projection lifecycle on standalone and live registries.

Constructing a catalog freezes that class's recorder. A later
``register`` on the frozen recorder is refused. That freeze-at-build
rule still needs confirmation.

The catalog stores the built registry. There is no path dict on the
owner. Registration after the catalog is built is refused.

Missing-declaration E003 on Content/Junction stays on Zero ``tests/legacy/``.
"""
from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.auth.backends import ModelBackend
from django.test import SimpleTestCase, TestCase, override_settings
from tests.support import (
    configured_catalog,
    sweep_listed_backends,
    built_catalog,
    compiler,
)
from tests.core import KernelHostRequiredMixin
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentGrant

from trusts.compile.nodes import Ref
from trusts.errors import TrustsConfigurationError
from trusts.backends import TrustModelBackendMixin
HOST = HOST_BACKEND
DOCUMENT = DOCUMENT_BACKEND
MIXIN = 'tests.backends.MixinOnlyBackend'

def _contribute_document(registry):
    j = Ref(DocumentGrant)
    registry.register_relation(content=j.document, user=j.user, permission=j.permission)

def _contribute_recorder(recorder):
    recorder.register(
        trust=DocumentGrant, user='user', permission='permission', content='document',
    )

class StandaloneIndependenceTest(SimpleTestCase):

    def test_standalone_stays_writable_after_global_ready(self):
        self.assertTrue(apps.ready)
        first = compiler()
        second = compiler()
        self.assertEqual(first.records, ())
        _contribute_document(second)
        self.assertEqual(len(built_catalog(second).plan_for(Document).records), 1)
        _contribute_document(first)
        self.assertEqual(len(first.records), 1)
        self.assertEqual(built_catalog(first).records, first.records)
        self.assertIsNot(first.records[0], second.records[0])

    def test_build_is_repeatable_and_register_after_build_is_refused(self):
        registry = compiler()
        _contribute_document(registry)
        before = registry.records
        first_build = built_catalog(registry)
        second_build = built_catalog(registry)
        self.assertIs(first_build, second_build)
        self.assertEqual(first_build.records, before)
        self.assertEqual(second_build.records, before)
        self.assertTrue(apps.ready)
        with self.assertRaises(TrustsConfigurationError):
            registry.register_relation(
                content=Ref(DocumentGrant).document,
                user=Ref(DocumentGrant).user,
                permission=Ref(DocumentGrant).permission,
            )
        self.assertEqual(registry.records, before)
        self.assertIs(built_catalog(registry).plan_for(Document).records[0], before[0])

class RegisterAfterBuildLeavesRecordsUnchangedTest(SimpleTestCase):

    def test_valid_duplicate_conflict_and_malformed_all_raise(self):
        registry = compiler()
        j = Ref(DocumentGrant)
        registry.register_relation(content=j.document, user=j.user, permission=j.permission)
        before = registry.records
        attempts = (dict(content=j.document, user=j.user, permission=j.permission), dict(content=j.document, user=j.permission, permission=j.user), dict(content='not-a-ref', user=j.user, permission=j.permission))
        for kwargs in attempts:
            with self.assertRaises(TrustsConfigurationError) as ctx:
                registry.register_relation(**kwargs)
            self.assertNotIn('frozen', str(ctx.exception).lower())
        self.assertEqual(registry.records, before)
        self.assertEqual(len(built_catalog(registry).plan_for(Document).records), 1)

class BuiltPlanProjectionsTest(KernelHostRequiredMixin, TestCase):

    def test_built_plan_still_projects(self):
        registry = compiler()
        _contribute_document(registry)
        before = built_catalog(registry).plan_for(Document)
        built_catalog(registry)
        plan = built_catalog(registry).plan_for(Document)
        self.assertEqual(plan.records, before.records)
        user = get_user_model()(pk=1)
        permission = Permission(pk=1)
        exists = plan.content_exists(user, permission)
        self.assertIsNotNone(exists)
        qs = Document.objects.all()
        filtered = built_catalog(registry).filter_authorized(qs, user, permission)
        self.assertIs(filtered.model, Document)

class _CatalogRestoreMixin(object):

    def setUp(self):
        super().setUp()
        from tests.support import snapshot_config_catalogs
        self._saved_catalogs = snapshot_config_catalogs()

    def tearDown(self):
        from tests.support import restore_config_catalogs
        restore_config_catalogs(self._saved_catalogs)
        super().tearDown()

class LiveBuildLifecycleTest(KernelHostRequiredMixin, _CatalogRestoreMixin, SimpleTestCase):

    def test_rows_before_ready_survive_and_later_register_is_refused(self):
        backend = DocumentBackend()
        registry = backend.get_registry()
        catalog = configured_catalog(DOCUMENT)
        self.assertIsNotNone(catalog)
        before = catalog.records
        with self.assertRaises(TrustsConfigurationError):
            _contribute_recorder(registry)
        self.assertEqual(catalog.records, before)

    def test_catalog_paths_are_the_owning_config_classes(self):
        from django.apps import apps

        document = configured_catalog(DOCUMENT)
        host = configured_catalog(HOST)
        self.assertEqual(document.path, apps.get_app_config('myapp').catalog_path())
        self.assertEqual(host.path, apps.get_app_config('trusts_kernel_host').catalog_path())
        self.assertIsInstance(document.records, tuple)
        self.assertIsInstance(host.records, tuple)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, HOST)):
            sweep_listed_backends()
        self.assertIs(
            configured_catalog(HOST),
            apps.get_app_config('trusts_kernel_host').catalog,
        )

    def test_ready_does_not_replace_stored_objects(self):
        from django.apps import apps

        live = apps.get_app_config('trusts_kernel_host')
        first = configured_catalog(HOST)
        live.ready()
        rebuilt = configured_catalog(HOST)
        self.assertEqual(rebuilt.records, first.records)
        self.assertEqual(rebuilt.path, first.path)
        self.assertIs(rebuilt, first)
        self.assertFalse(hasattr(live, 'registries'))

    def test_registration_does_not_resolve_the_user_model(self):
        from django.contrib.auth import get_user_model
        from trusts.apps import Recorder
        from trusts.compile.factory import Compiler
        from trusts.compile.listener import RegistrationListener

        log = Recorder(RegistrationListener())
        _contribute_recorder(log)
        built_from = Compiler(
            user_model=get_user_model(),
            query_compiler=Compiler.default_query_compiler(),
            path='tests.core.fresh89',
            family='relationship',
        )
        log.freeze()
        log.play(built_from)
        built = built_from.compile()
        self.assertIs(built.records[0].root, DocumentGrant)
        with self.assertRaises(TrustsConfigurationError):
            _contribute_recorder(log)
        self.assertIs(built_from.compile(), built)

    def test_backend_in_a_ready_app_shares_that_recorder(self):
        from django.apps import apps
        from tests.backends import MixinOnlyBackend

        owner = apps.get_app_config('trusts_tests')
        backend = MixinOnlyBackend()
        self.assertIs(backend.get_registry(), owner.recorder)
        with self.assertRaises(TrustsConfigurationError):
            _contribute_recorder(backend.get_registry())

    def test_standalone_factory_stays_writable_after_host_ready(self):
        from django.apps import apps

        first = configured_catalog(HOST)
        private = compiler()
        apps.get_app_config('trusts_kernel_host').ready()
        rebuilt = configured_catalog(HOST)
        self.assertEqual(rebuilt.records, first.records)
        self.assertIs(rebuilt, first)
        _contribute_document(private)
        self.assertEqual(len(private.records), 1)

class SentinelAfterFirstReadTest(KernelHostRequiredMixin, _CatalogRestoreMixin, SimpleTestCase):

    def test_same_instance_reentry_is_noop_after_first_read(self):
        from django.apps import apps

        live = apps.get_app_config('trusts_kernel_host')
        catalog = configured_catalog(HOST)
        before = catalog.records
        live.ready()
        self.assertEqual(catalog.records, before)
        rebuilt = configured_catalog(HOST)
        self.assertEqual(rebuilt.records, before)
        self.assertEqual(rebuilt.path, catalog.path)
        self.assertIs(rebuilt, catalog)

    def test_second_ready_leaves_the_built_catalog_in_place(self):
        from django.apps import apps
        from tests.kernel_host.backends import HostTrustModelBackend

        live = apps.get_app_config('trusts_kernel_host')
        catalog = configured_catalog(HOST)
        registry = HostTrustModelBackend().get_registry()
        before = catalog.records
        live.ready()
        rebuilt = configured_catalog(HOST)
        self.assertEqual(catalog.records, before)
        self.assertEqual(rebuilt.records, before)
        self.assertEqual(rebuilt.path, catalog.path)
        self.assertIs(rebuilt, catalog)
        with self.assertRaises(TrustsConfigurationError):
            registry.register(
                trust=DocumentGrant, user='user',
                permission='permission', content='document',
            )

class _LateBackend(TrustModelBackendMixin, ModelBackend):
    """A class whose recorder has not been built yet."""

class BackendQuestionAfterLateRegistrationTest(SimpleTestCase):
    """Freeze happens when the catalog is constructed."""

    def test_register_after_build_is_refused(self):
        from trusts.errors import TrustsConfigurationError
        backend = DocumentBackend()
        registry = backend.get_registry()
        catalog = configured_catalog(DOCUMENT)
        self.assertIsNotNone(catalog)
        before = catalog.records
        with self.assertRaisesRegex(TrustsConfigurationError, 'register refused: this registry is frozen'):
            registry.register(trust=DocumentGrant, user='user', permission='permission', content='document')
        self.assertEqual(catalog.records, before)

    def test_frozen_register_names_the_built_catalog(self):
        registry = DocumentBackend().get_registry()
        with self.assertRaises(TrustsConfigurationError) as caught:
            registry.register(trust=DocumentGrant, user='user', permission='permission', content='document')
        self.assertEqual(
            str(caught.exception),
            'register refused: this registry is frozen. The catalog is already built.',
        )
        self.assertNotIn('recorder', str(caught.exception))

class HandleBuildRegistrySignalTest(SimpleTestCase):
    """A configured path holds a registry. The registry builds itself."""

    def test_factory_builds_a_fresh_registry(self):
        registry = compiler(path='tests.core.builder')
        handle = registry
        first = built_catalog(handle)
        second = built_catalog(handle)
        self.assertIs(first, second)
        self.assertEqual(first.records, ())
        fresh = compiler(path='tests.core.builder')
        _contribute_document(fresh)
        self.assertEqual(built_catalog(fresh).records, fresh.records)
        self.assertEqual(first.records, ())
