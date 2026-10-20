"""#194: protected family factories and family-local Core aggregates."""
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest
from django.test import SimpleTestCase, TestCase, override_settings
import tests as tests_module
from tests.support import live_config, override_apps_ready, built_catalog, bound_handle, replay_recorder, configured_catalog
from tests.backends import MixinOnlyBackend
from tests.core import KernelHostRequiredMixin
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentAltGrant, DocumentGrant
from trusts.apps import TrustsImplementationConfig
from trusts.backends import TrustModelBackendMixin, catalogs
from trusts.plan.contents import relationship_family
from tests.support import scoped_permitted_content as filter_by_permitted_content
from trusts.plan.relations import QueryCompiler
from trusts.plan.relations import PlanQueryCompiler
from trusts.errors import TrustsConfigurationError
from trusts.compile.factory import RegistryFactory
from trusts.plan.contents import granted
from trusts.plan.aggregates import _compiler_applies
from trusts.decorators import _declared_authorization_guards, authorization_required
HOST = HOST_BACKEND
DOCUMENT = DOCUMENT_BACKEND
MIXIN = 'tests.backends.MixinOnlyBackend'
PERM = 'myapp.change_document'

class FoldFamilyConfig(TrustsImplementationConfig):
    name = 'tests'
    label = 'trusts_impl_194_fold'

class RecordingRegistry(RegistryFactory):
    created = True

class RecordingConfig(TrustsImplementationConfig):
    name = 'tests'
    label = 'trusts_impl_194_record'

class _NeverAppliesCompiler(PlanQueryCompiler):

    def applies(self, plan):
        return False

class _AppsView(object):

    def __init__(self, configs, ready=True):
        self._configs = list(configs)
        self.ready = ready

    def get_app_configs(self):
        return tuple(self._configs)

def _bind(config_cls, configs=None, ready=True):
    config = config_cls('tests', tests_module)
    view = _AppsView(configs if configs is not None else [config], ready=ready)
    config.apps = view
    if configs is None:
        view._configs = [config]
    return config

def _permission(model, codename, name):
    ct = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(content_type=ct, codename=codename, defaults={'name': name})
    return permission

def _request(user):
    request = HttpRequest()
    request.user = user
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request

class ProtectedFactorySurfaceTest(SimpleTestCase):

    def test_default_family_and_factories_are_protected(self):
        self.assertEqual(TrustModelBackendMixin.family, 'relationship')
        self.assertFalse(hasattr(TrustsImplementationConfig, '_authorization_family'))
        self.assertFalse(hasattr(TrustsImplementationConfig, 'authorization_family'))
        self.assertFalse(hasattr(TrustsImplementationConfig, '_create_registry'))
        self.assertFalse(hasattr(TrustsImplementationConfig, '_create_handle'))
        self.assertTrue(callable(QueryCompiler().applies))
        self.assertTrue(callable(PlanQueryCompiler().applies))

    def test_relationship_applies_is_records_only(self):
        compiler = PlanQueryCompiler()
        protocol = QueryCompiler()
        empty = type('Plan', (), {'records': (), 'delegations': ()})()
        filled = type('Plan', (), {'records': (object(),), 'delegations': (), 'strategy': object()})()
        strategy_only = type('Plan', (), {'records': (), 'delegations': (), 'strategy': object()})()
        self.assertFalse(compiler.applies(empty))
        self.assertFalse(protocol.applies(empty))
        self.assertTrue(compiler.applies(filled))
        self.assertTrue(protocol.applies(filled))
        self.assertFalse(compiler.applies(strategy_only))
        self.assertFalse(protocol.applies(strategy_only))
        self.assertFalse(_compiler_applies(compiler, strategy_only))

    def test_ready_stores_the_built_registry_on_the_catalog(self):
        from tests.backends import HostTrustModelBackend
        catalog = HostTrustModelBackend().get_catalog()
        self.assertIs(catalogs[HostTrustModelBackend], catalog)
        self.assertIsInstance(catalog.records, tuple)

    def test_unowned_factory_defaults_to_relationship_family(self):
        built = built_catalog(RegistryFactory(path=MIXIN))
        self.assertEqual(built.family, 'relationship')
        self.assertEqual(relationship_family((built,)), (built,))

class FamilyLocalAggregateTest(KernelHostRequiredMixin, TestCase):

    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.alice = User.objects.create_user('alice-194', password='x')
        self.change = _permission(Document, 'change_document', 'Can change document')
        self.rel_doc = Document.objects.create(title='rel-194')
        self.fold_doc = Document.objects.create(title='fold-194')
        DocumentGrant.objects.create(document=self.rel_doc, user=self.alice, permission=self.change)
        DocumentAltGrant.objects.create(document=self.fold_doc, user=self.alice, permission=self.change)
        self.rel_handle = catalogs[DocumentBackend]
        self.fold_registry = RegistryFactory(path=MIXIN, family='ordered_fold')
        self.fold_handle = self.fold_registry
        self.fold_handle.register_public(trust=DocumentAltGrant, user='user', permission='permission', content='document')
        self.fold_owner = _bind(FoldFamilyConfig, ready=False)
        from tests.backends import MixinOnlyBackend
        self._saved_fold_catalog = catalogs.get(MixinOnlyBackend)
        self.fold_handle = built_catalog(self.fold_registry)
        catalogs[MixinOnlyBackend] = self.fold_handle
        self.mixin = MixinOnlyBackend()
        self.document_backend = DocumentBackend()

    def tearDown(self):
        from tests.backends import MixinOnlyBackend
        from trusts.backends import catalogs
        if self._saved_fold_catalog is None:
            catalogs.pop(MixinOnlyBackend, None)
        else:
            catalogs[MixinOnlyBackend] = self._saved_fold_catalog
        super().tearDown()

    def _family_patches(self):
        return override_settings(AUTHENTICATION_BACKENDS=(HOST, DOCUMENT, MIXIN))

    def test_fold_family_handle_is_omitted_from_core_aggregates(self):
        settings = self._family_patches()
        with settings:
            rel_only = granted(self.rel_handle, Document.objects.all(), self.alice, self.change)
            fold_only = granted(self.fold_handle, Document.objects.all(), self.alice, self.change)
            self.assertIsNotNone(rel_only)
            self.assertIsNone(fold_only)
            mixed = rel_only if fold_only is None else rel_only | fold_only
            self.assertIsNotNone(mixed)
            with self.assertNumQueries(1):
                self.assertEqual(set(Document.objects.filter(mixed).values_list('pk', flat=True)), {self.rel_doc.pk})
            rel_scopes = filter_by_permitted_content(Document.objects.all(), self.alice, self.change, content=self.rel_doc, registry=self.rel_handle)
            fold_scopes = filter_by_permitted_content(Document.objects.all(), self.alice, self.change, content=self.fold_doc, registry=self.fold_handle)
            self.assertEqual(list(rel_scopes), [])
            self.assertEqual(list(fold_scopes), [])
            from trusts.query import relationship_catalogs
            listed = relationship_catalogs()
            self.assertIn(catalogs[DocumentBackend], listed)
            self.assertNotIn(catalogs[MixinOnlyBackend], listed)
            self.assertEqual(catalogs[MixinOnlyBackend].path, MIXIN)
            self.assertEqual(catalogs[MixinOnlyBackend].family, 'ordered_fold')
            with self.assertNumQueries(1):
                authorized = set(Document.objects.authorized(self.alice, self.change).values_list('pk', flat=True))
            self.assertEqual(authorized, {self.rel_doc.pk})
            self.assertNotIn(self.fold_doc.pk, authorized)

            @authorization_required(Document, PERM)
            def _guard(request, pk):
                return 'ok'
            entry = (Document, PERM, ())
            self.addCleanup(lambda: _declared_authorization_guards.remove(entry) if entry in _declared_authorization_guards else None)
            self.assertEqual(_guard(_request(self.alice), pk=self.rel_doc.pk), 'ok')
            with self.assertRaises(PermissionDenied):
                _guard(_request(self.alice), pk=self.fold_doc.pk)

    def test_mixin_own_handle_still_evaluates_fold_family_path(self):
        settings = self._family_patches()
        with settings:
            with self.assertNumQueries(1):
                self.assertTrue(self.mixin.has_perm(self.alice, PERM, self.fold_doc))
            with self.assertNumQueries(1):
                self.assertFalse(self.document_backend.has_perm(self.alice, PERM, self.fold_doc))
            with self.assertNumQueries(1):
                self.assertEqual(self.mixin.get_all_permissions(self.alice, self.fold_doc), {PERM})
            with self.assertNumQueries(1):
                self.assertEqual(set(Document.objects.authorized(self.alice, self.change).values_list('pk', flat=True)), {self.rel_doc.pk})

class MixinAppliesHookTest(KernelHostRequiredMixin, TestCase):

    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.alice = User.objects.create_user('alice-194a', password='x')
        self.change = _permission(Document, 'change_document', 'Can change document')
        self.doc = Document.objects.create(title='applies-194')
        DocumentGrant.objects.create(document=self.doc, user=self.alice, permission=self.change)
        self.backend = DocumentBackend()

    def test_inapplicable_compiler_is_zero_sql(self):
        from tests.myapp.apps import DOCUMENT_BACKEND
        import trusts.plan.standards as standards

        factory = RegistryFactory(
            compiler=_NeverAppliesCompiler(),
            path=DOCUMENT_BACKEND,
            family=DocumentBackend.family,
            user_model=standards.user_model,
        )
        replay_recorder(factory, DocumentBackend)
        with bound_handle(self.backend, factory):
            with self.assertNumQueries(0):
                self.assertFalse(self.backend.has_perm(self.alice, PERM, self.doc))
                self.assertEqual(self.backend.get_all_permissions(self.alice, self.doc), set())

    def test_relationship_applies_keeps_live_grant(self):
        with self.assertNumQueries(1):
            self.assertTrue(self.backend.has_perm(self.alice, PERM, self.doc))

class FactoryBuildOwnershipTest(KernelHostRequiredMixin, SimpleTestCase):

    def test_standalone_factory_rebuilds_and_a_published_registry_does_not(self):
        from tests.backends import HostTrustModelBackend
        isolated = RegistryFactory()
        first_build = built_catalog(isolated)
        second_build = built_catalog(isolated)
        self.assertIsNot(first_build, second_build)
        from tests.myapp.models import DocumentGrant
        from trusts.compile.nodes import Ref
        fresh = RegistryFactory()
        j = Ref(DocumentGrant)
        fresh.register(content=j.document, user=j.user, permission=j.permission)
        self.assertEqual(built_catalog(fresh).records, fresh.records)
        published = catalogs[HostTrustModelBackend]
        self.assertIsInstance(published.records, tuple)

    def test_unconfigured_path_still_fails_loud(self):
        with self.assertRaises(TrustsConfigurationError) as ctx:
            configured_catalog(MIXIN)
        self.assertIn(MIXIN, str(ctx.exception))
