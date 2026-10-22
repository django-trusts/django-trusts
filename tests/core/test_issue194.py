"""#194: protected family factories and family-local Core aggregates."""
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.checks import run_checks
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest
from django.test import SimpleTestCase, TestCase, override_settings
import tests as tests_module
from tests.support import built_catalog, bound_handle, replay_recorder, config_for_class, compiler
from tests.backends import MixinOnlyBackend
from tests.core import KernelHostRequiredMixin
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentAltGrant, DocumentGrant
from trusts.apps import TrustsConfigMixin, installed_catalogs
from tests.support import scoped_permitted_content as filter_by_permitted_content
from trusts.plan.relations import PlanQueryCompiler
from trusts.compile.factory import Compiler
from trusts.plan.contents import granted
from trusts.decorators import _declared_authorization_guards, authorization_required
HOST = HOST_BACKEND
DOCUMENT = DOCUMENT_BACKEND
MIXIN = 'tests.backends.MixinOnlyBackend'
PERM = 'myapp.change_document'

class FoldFamilyConfig(TrustsConfigMixin):
    name = 'tests'
    label = 'trusts_impl_194_fold'

class RecordingRegistry(Compiler):
    created = True

class RecordingConfig(TrustsConfigMixin):
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


    def test_relationship_applies_is_records_only(self):
        compiler = PlanQueryCompiler()
        empty = type('Plan', (), {'records': (), 'delegations': ()})()
        filled = type('Plan', (), {'records': (object(),), 'delegations': (), 'strategy': object()})()
        strategy_only = type('Plan', (), {'records': (), 'delegations': (), 'strategy': object()})()
        self.assertFalse(compiler.applies(empty))
        self.assertTrue(compiler.applies(filled))
        self.assertFalse(compiler.applies(strategy_only))

    def test_ready_stores_the_built_registry_on_the_catalog(self):
        from django.contrib.auth.models import AnonymousUser
        from tests.kernel_host.backends import HostTrustModelBackend
        from trusts.backends import policy_document

        self.assertFalse(HostTrustModelBackend().has_perm(
            AnonymousUser(), 'auth.view_user', None,
        ))
        document = policy_document()
        self.assertEqual(document['schema_version'], 1)
        self.assertTrue(document['backends'])

    def test_unowned_factory_defaults_to_relationship_family(self):
        built = built_catalog(compiler(path=MIXIN))
        self.assertEqual(built.family, 'relationship')

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
        self.rel_handle = DocumentBackend().catalog
        self.fold_registry = compiler(path=MIXIN, family='ordered_fold')
        self.fold_handle = self.fold_registry
        self.fold_handle.register(trust=DocumentAltGrant, user='user', permission='permission', content='document')
        self.fold_owner = _bind(FoldFamilyConfig, ready=False)
        self._fold_config = config_for_class(MixinOnlyBackend)
        self._saved_fold_catalog = self._fold_config.catalog
        self.fold_handle = built_catalog(self.fold_registry)
        self._fold_config.catalog = self.fold_handle
        self.mixin = MixinOnlyBackend()
        self.document_backend = DocumentBackend()

    def tearDown(self):
        self._fold_config.catalog = self._saved_fold_catalog
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
            listed = installed_catalogs()
            self.assertIn(DocumentBackend().catalog, listed)
            self.assertIn(self.fold_handle, listed)
            self.assertEqual(self.fold_handle.path, MIXIN)
            self.assertEqual(self.fold_handle.family, 'ordered_fold')
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
        from django.contrib.auth import get_user_model
        from tests.myapp.apps import DOCUMENT_BACKEND

        factory = compiler(
            query_compiler=_NeverAppliesCompiler(),
            path=DOCUMENT_BACKEND,
            family=TrustsConfigMixin.family,
            user_model=get_user_model(),
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
        from tests.kernel_host.backends import HostTrustModelBackend
        isolated = compiler()
        first_build = built_catalog(isolated)
        second_build = built_catalog(isolated)
        self.assertIs(first_build, second_build)
        from tests.myapp.models import DocumentGrant
        from trusts.compile.nodes import Ref
        fresh = compiler()
        j = Ref(DocumentGrant)
        fresh.register_relation(content=j.document, user=j.user, permission=j.permission)
        self.assertEqual(built_catalog(fresh).records, fresh.records)
        published = HostTrustModelBackend().catalog
        self.assertIsInstance(published.records, tuple)

    def test_unconfigured_path_still_fails_loud(self):
        outside = 'tests.gh_permissions.backends.OutsideBackend'
        with override_settings(AUTHENTICATION_BACKENDS=(HOST_BACKEND, outside)):
            messages = [
                message for message in run_checks()
                if getattr(message, 'id', None) == 'trusts.E012'
            ]
        self.assertEqual(
            [message.msg for message in messages],
            ['App gh_permissions must extend TrustsConfigMixin.'],
        )
