"""#75: path-scoped registry, compiler protocol, and two-path aggregation.

Live one-path Trust/Content auth stays on Zero ``tests/legacy/``.
Generic multi-path contracts use KernelHost + DocumentConfig.
"""
from unittest.mock import patch
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.checks import Error, run_checks
from django.db.models.query import QuerySet
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import isolate_apps
from tests.core import KernelHostRequiredMixin
from tests.apps import configured_catalog, TestsConfig, install_writable_registry, isolate_live_registry, live_config, override_apps_ready, built_registries
from tests.backends import HostTrustModelBackend, MalformedCompilerBackend, MixinOnlyBackend, MissingCompilerBackend, RaisingCompilerBackend
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.models import Document, DocumentGrant
from trusts.apps import implementation_for_path
from trusts.plan.aggregates import compiler_for_class
from trusts.apps import catalogs
from trusts.backends import TrustModelBackendMixin
from trusts.inspect.checks import CHECK_ID_MISSING_COMPILER, check_query_compilers
from trusts.plan.relations import PlanQueryCompiler
from trusts.errors import TrustsCompilerError, TrustsConfigurationError
from trusts.compile.factory import RegistryFactory
from trusts.plan.contents import granted
import tests as tests_module
HOST = HOST_BACKEND
DOCUMENT = DOCUMENT_BACKEND
MIXIN = 'tests.backends.MixinOnlyBackend'
ALIASED = 'tests.backends.AliasedTrustModelBackend'
MISSING = 'tests.backends.MissingCompilerBackend'
MALFORMED = 'tests.backends.MalformedCompilerBackend'
RAISING = 'tests.backends.RaisingCompilerBackend'

def _pks(qs):
    return set(qs.values_list('pk', flat=True))

def _change_document():
    ct = ContentType.objects.get_for_model(Document)
    permission, _created = Permission.objects.get_or_create(content_type=ct, codename='change_document', defaults={'name': 'Can change document'})
    return permission

def _contribute_document(registry):
    from trusts.compile.nodes import Ref
    j = Ref(DocumentGrant)
    registry.register(content=j.document, user=j.user, permission=j.permission)

def _evaluate(handle, queryset, user, permission):
    built = handle.build_registry()
    plan = built.plan_for(queryset, user=user, permission=permission)
    compiler = built.compiler if built.compiler is not None else PlanQueryCompiler()
    return compiler.complete_exists(plan, queryset, user, permission)

class PathScopedRegistryStoreTest(KernelHostRequiredMixin, SimpleTestCase):

    def test_one_path_registry_alias_is_exact_store(self):
        live = live_config()
        catalog = configured_catalog(live)
        self.assertEqual(catalog.path, HOST)
        self.assertIs(catalog, catalogs[HostTrustModelBackend])
        self.assertIs(catalog.registry.compiler, HostTrustModelBackend.query_compiler)
        self.assertIsInstance(catalog.registry.compiler, PlanQueryCompiler)

    def test_duplicate_identical_paths_dedupe(self):
        live = live_config()
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, HOST)):
            paths = live._configured_trusts_paths()
            self.assertEqual(paths, (HOST,))
            self.assertIs(catalogs[HostTrustModelBackend], configured_catalog(live))
            self.assertEqual(configured_catalog(live).path, HOST)

    def test_same_class_alias_is_ambiguity_error(self):
        live = live_config()
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, ALIASED)):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                live._configured_trusts_paths()
            self.assertIn('multiple paths', str(ctx.exception))
            with self.assertRaises(TrustsConfigurationError):
                configured_catalog(live)
            with self.assertRaises(TrustsConfigurationError):
                live.path_for_class(HostTrustModelBackend)

    def test_unconfigured_path_fails_loud(self):
        live = live_config()
        with self.assertRaises(TrustsConfigurationError) as ctx:
            configured_catalog(live, MIXIN)
        self.assertIn(MIXIN, str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError):
            live.path_for_class(MixinOnlyBackend)
        with self.assertRaises(TrustsConfigurationError):
            live.path_for_backend(MixinOnlyBackend())

    def test_zero_and_multiple_alias_access_fail(self):
        live = live_config()
        with override_settings(AUTHENTICATION_BACKENDS=('django.contrib.auth.backends.ModelBackend',)):
            self.assertEqual(live._configured_trusts_paths(), ())
            with self.assertRaises(TrustsConfigurationError):
                configured_catalog(live)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, DOCUMENT)):
            self.assertEqual(configured_catalog(live).path, HOST)
            handle_doc = configured_catalog(live, DOCUMENT)
            self.assertEqual(handle_doc.path, DOCUMENT)
            from tests.myapp.backends import DocumentBackend
            self.assertIs(handle_doc, catalogs[DocumentBackend])

    def test_ready_does_not_replace_store_or_registry(self):
        live = live_config()
        first = catalogs[HostTrustModelBackend]
        live.ready()
        self.assertIs(catalogs[HostTrustModelBackend], first)
        self.assertIs(catalogs[HostTrustModelBackend].registry, first.registry)

    def test_compiler_is_class_owned_not_instance_state(self):
        first = HostTrustModelBackend()
        second = HostTrustModelBackend()
        self.assertIs(first.query_compiler, HostTrustModelBackend.query_compiler)
        self.assertIs(second.query_compiler, first.query_compiler)
        self.assertIs(MixinOnlyBackend.query_compiler, TrustModelBackendMixin.query_compiler)
        self.assertIsInstance(TrustModelBackendMixin.query_compiler, PlanQueryCompiler)
        self.assertIs(compiler_for_class(HostTrustModelBackend), HostTrustModelBackend.query_compiler)
        self.assertIs(compiler_for_class(MixinOnlyBackend), MixinOnlyBackend.query_compiler)

@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes', attr_name='isolated_apps')
class IsolatedAppsPathStoreTest(SimpleTestCase):

    def test_isolate_apps_without_owner_does_not_donate(self):
        before = catalogs[HostTrustModelBackend].registry.records
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertIsNone(getattr(contributor, '_trusts_tup_category_registry_id', None))
        self.assertEqual(catalogs[HostTrustModelBackend].registry.records, before)

class ContributionPathTest(KernelHostRequiredMixin, SimpleTestCase):

    def test_explicit_path_contribution_writes_one_registry(self):
        host = live_config()
        document = implementation_for_path(DOCUMENT)
        self.assertTrue(configured_catalog(document).registry.plan_for(Document).records)
        self.assertFalse(configured_catalog(host).registry.plan_for(Document).records)

    def test_omitted_ambiguous_path_fails_before_writing(self):
        from tests.core.test_issue108 import HostImplConfig, _bind

        class DualImpl(HostImplConfig):
            label = 'trusts_impl_dual'
            trusts_backend_paths = (HOST, MIXIN)
        dual = _bind(DualImpl, ready=False)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, MIXIN)):
            with self.assertRaises(TrustsConfigurationError):
                configured_catalog(dual)

    def test_no_mixin_fan_out(self):
        live = live_config()
        with self.assertRaises(TrustsConfigurationError):
            configured_catalog(live, MIXIN)
        self.assertFalse(hasattr(live, 'registries'))

class _LiveRegistryRestoreMixin(object):

    def setUp(self):
        super().setUp()

    def tearDown(self):
        super().tearDown()

class CompilerProtocolTest(KernelHostRequiredMixin, _LiveRegistryRestoreMixin, SimpleTestCase):

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
        with override_settings(AUTHENTICATION_BACKENDS=(MISSING,), SILENCED_SYSTEM_CHECKS=['trusts.E004', 'fields.W342']):
            messages = check_query_compilers(None)
            self.assertTrue(messages)
            self.assertTrue(all((m.is_silenced() for m in messages)))
            with self.assertRaises(TrustsCompilerError):
                compiler_for_class(MissingCompilerBackend)

    def test_broken_second_path_is_not_omitted(self):
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, MISSING)):
            errors = [m for m in check_query_compilers(None) if m.id == CHECK_ID_MISSING_COMPILER]
            self.assertEqual(len(errors), 1)

    def test_raising_compiler_propagates(self):
        User = get_user_model()
        registry = RegistryFactory(compiler=RaisingCompilerBackend.query_compiler)
        handle = [registry, setattr(registry, 'path', RAISING)][0]
        _contribute_document(handle)
        with self.assertRaises(RuntimeError) as ctx:
            granted(built_registries((handle,)), Document, User(), Permission(), kind='complete')
        self.assertIn('compiler exploded', str(ctx.exception))

class CompilerCheckQueryCountTest(TestCase):

    def test_e004_check_issues_zero_sql(self):
        with override_settings(AUTHENTICATION_BACKENDS=(MISSING, HOST)):
            with self.assertNumQueries(0):
                check_query_compilers(None)

class TwoPathAuthorizationTest(KernelHostRequiredMixin, TestCase):

    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.alice = User.objects.create_user('alice-75', password='x')
        self.bob = User.objects.create_user('bob-75', password='x')
        self.change = _change_document()
        self.doc_a = Document.objects.create(title='a')
        self.doc_b = Document.objects.create(title='b')
        DocumentGrant.objects.create(document=self.doc_a, user=self.alice, permission=self.change)
        self.host = configured_catalog(live_config()).registry
        self.document = configured_catalog(implementation_for_path(DOCUMENT)).registry

    def test_grant_only_through_document_path(self):
        self.assertFalse(self.host.build_registry().plan_for(Document).records)
        self.assertTrue(self.document.build_registry().plan_for(Document).records)
        qs = Document.objects.all()
        pred_host = _evaluate(self.host, qs, self.alice, self.change)
        pred_doc = _evaluate(self.document, qs, self.alice, self.change)
        self.assertIsNone(pred_host)
        self.assertIsNotNone(pred_doc)
        self.assertEqual(_pks(qs.filter(pred_doc)), {self.doc_a.pk})
        permitted = Document.objects.authorized(self.alice, self.change)
        self.assertIsInstance(permitted, QuerySet)
        self.assertIsNone(permitted._result_cache)
        with self.assertNumQueries(1):
            self.assertEqual(_pks(permitted), {self.doc_a.pk})

    def test_grant_through_neither(self):
        self.assertFalse(Document.objects.authorized(self.bob, self.change).exists())

    def test_aggregate_ors_both_complete_proofs_in_one_statement(self):
        isolated = RegistryFactory()
        _contribute_document(isolated)
        extra = [isolated, setattr(isolated, 'path', MIXIN)][0]
        qs = Document.objects.all()
        pred = granted(built_registries((self.host, self.document, extra)), qs, self.alice, self.change, kind='complete')
        self.assertIsNotNone(pred)
        with self.assertNumQueries(1):
            self.assertEqual(_pks(qs.filter(pred).distinct()), {self.doc_a.pk})

    def test_failed_ceiling_cannot_use_other_path_fragment(self):
        qs = Document.objects.all()
        pred_host = _evaluate(self.host, qs, self.alice, self.change)
        pred_doc = _evaluate(self.document, qs, self.bob, self.change)
        self.assertIsNone(pred_host)
        self.assertEqual(_pks(qs.filter(pred_doc)), set())

    def test_different_terminals_route_only_through_applicable_handles(self):
        from tests.models import Organization
        self.assertTrue(self.document.build_registry().plan_for(Document).records)
        self.assertFalse(self.document.build_registry().plan_for(Organization).records)
        self.assertFalse(self.host.build_registry().plan_for(Document).records)
        self.assertEqual(_pks(Document.objects.authorized(self.alice, self.change)), {self.doc_a.pk})
        self.assertFalse(Organization.objects.all().none().exists())

class CompilerIsolationTest(KernelHostRequiredMixin, TestCase):

    def test_raising_compiler_is_not_caught_by_aggregate(self):
        User = get_user_model()
        live = live_config()
        registry = RegistryFactory(compiler=RaisingCompilerBackend.query_compiler)
        handle = [registry, setattr(registry, 'path', RAISING)][0]
        _contribute_document(handle)
        with self.assertRaises(RuntimeError) as ctx:
            granted(built_registries((configured_catalog(live).registry, handle)), Document, User(), Permission(), kind='complete')
        self.assertIn('compiler exploded', str(ctx.exception))

    def test_mixin_only_alone_does_not_inherit_document_plan(self):
        live = live_config()
        self.assertFalse(configured_catalog(live).registry.plan_for(Document).records)
        self.assertTrue(configured_catalog(implementation_for_path(DOCUMENT)).registry.plan_for(Document).records)
