"""#75: path-scoped registry, compiler protocol, and two-path aggregation.

Live one-path Trust/Content auth stays on Zero ``tests/legacy/``.
Generic multi-path contracts use KernelHost + DocumentConfig.
"""
from django.contrib.auth import get_user_model
from django.core.checks import run_checks
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db.models.query import QuerySet
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import isolate_apps
from tests.core import KernelHostRequiredMixin
from tests.apps import TestsConfig
from tests.support import (
    built_catalog,
    configured_catalog,
    sweep_listed_backends,
    compiler,
)
from tests.kernel_host.backends import HostTrustModelBackend
from tests.backends import RaisingCompilerBackend
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.models import Document, DocumentGrant

from trusts.plan.relations import PlanQueryCompiler
from trusts.plan.contents import granted
import tests as tests_module
HOST = HOST_BACKEND
DOCUMENT = DOCUMENT_BACKEND
MIXIN = 'tests.backends.MixinOnlyBackend'
OUTSIDE = 'tests.gh_permissions.backends.OutsideBackend'
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
    registry.register_relation(content=j.document, user=j.user, permission=j.permission)

def _evaluate(handle, queryset, user, permission):
    plan = handle.plan_for(queryset, user=user, permission=permission)
    compiler = handle.compiler
    return compiler.complete_exists(plan, queryset, user, permission)

class PathScopedRegistryStoreTest(KernelHostRequiredMixin, SimpleTestCase):

    def test_one_path_registry_alias_is_exact_store(self):
        from django.apps import apps

        catalog = configured_catalog(HOST)
        self.assertEqual(
            catalog.path,
            apps.get_app_config('trusts_kernel_host').catalog_path(),
        )
        self.assertIs(catalog, HostTrustModelBackend().catalog)
        self.assertIsInstance(catalog.compiler, PlanQueryCompiler)

    def test_duplicate_identical_paths_do_not_raise(self):
        from django.apps import apps

        with override_settings(AUTHENTICATION_BACKENDS=(HOST, HOST)):
            sweep_listed_backends()
        self.assertEqual(
            configured_catalog(HOST).path,
            apps.get_app_config('trusts_kernel_host').catalog_path(),
        )


    def test_document_and_host_catalogs_use_config_paths(self):
        from django.apps import apps
        from tests.myapp.backends import DocumentBackend

        self.assertEqual(
            configured_catalog(HOST).path,
            apps.get_app_config('trusts_kernel_host').catalog_path(),
        )
        handle_doc = configured_catalog(DOCUMENT)
        self.assertEqual(
            handle_doc.path,
            apps.get_app_config('myapp').catalog_path(),
        )
        self.assertIs(handle_doc, DocumentBackend().catalog)

    def test_ready_does_not_replace_store_or_registry(self):
        from django.apps import apps

        live = apps.get_app_config('trusts_kernel_host')
        first = HostTrustModelBackend().catalog
        live.ready()
        rebuilt = HostTrustModelBackend().catalog
        self.assertEqual(rebuilt.records, first.records)
        self.assertEqual(rebuilt.path, first.path)
        self.assertIs(rebuilt, first)

    def test_live_catalog_stores_an_explicit_plan_compiler(self):
        catalog = HostTrustModelBackend().catalog
        self.assertIsInstance(catalog.compiler, PlanQueryCompiler)

@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes', attr_name='isolated_apps')
class IsolatedAppsPathStoreTest(SimpleTestCase):

    def test_isolate_apps_without_owner_does_not_donate(self):
        before = HostTrustModelBackend().catalog.records
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertIsNone(getattr(contributor, '_trusts_tup_category_registry_id', None))
        self.assertEqual(HostTrustModelBackend().catalog.records, before)

class ContributionPathTest(KernelHostRequiredMixin, SimpleTestCase):

    def test_explicit_path_contribution_writes_one_registry(self):
        self.assertTrue(configured_catalog(DOCUMENT).plan_for(Document).records)
        self.assertFalse(configured_catalog(HOST).plan_for(Document).records)

    def test_omitted_ambiguous_path_fails_before_writing(self):
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, OUTSIDE)):
            messages = run_checks()
        self.assertTrue(any(
            getattr(message, 'id', None) == 'trusts.E012'
            for message in messages
        ))

    def test_no_mixin_fan_out(self):
        from django.apps import apps

        live = apps.get_app_config('trusts_kernel_host')
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, OUTSIDE)):
            run_checks()
        self.assertFalse(hasattr(live, 'registries'))
        self.assertFalse(hasattr(live, 'trusts_backend_paths'))

class _LiveRegistryRestoreMixin(object):

    def setUp(self):
        super().setUp()

    def tearDown(self):
        super().tearDown()

class CompilerProtocolTest(KernelHostRequiredMixin, _LiveRegistryRestoreMixin, SimpleTestCase):

    def test_raising_compiler_propagates(self):
        User = get_user_model()
        registry = compiler(query_compiler=RaisingCompilerBackend.query_compiler)
        registry.path = RAISING
        handle = registry
        _contribute_document(handle)
        with self.assertRaises(RuntimeError) as ctx:
            granted(built_catalog(handle), Document, User(), Permission(), kind='complete')
        self.assertIn('compiler exploded', str(ctx.exception))

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
        self.host = configured_catalog(HOST)
        self.document = configured_catalog(DOCUMENT)

    def test_grant_only_through_document_path(self):
        self.assertFalse(self.host.plan_for(Document).records)
        self.assertTrue(self.document.plan_for(Document).records)
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
        isolated = compiler()
        _contribute_document(isolated)
        isolated.path = MIXIN
        extra = isolated
        qs = Document.objects.all()
        parts = [
            granted(registry, qs, self.alice, self.change, kind='complete')
            for registry in (self.host, self.document, built_catalog(extra))
        ]
        pred = None
        for part in parts:
            if part is None:
                continue
            pred = part if pred is None else pred | part
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
        self.assertTrue(self.document.plan_for(Document).records)
        self.assertFalse(self.document.plan_for(Organization).records)
        self.assertFalse(self.host.plan_for(Document).records)
        self.assertEqual(_pks(Document.objects.authorized(self.alice, self.change)), {self.doc_a.pk})
        self.assertFalse(Organization.objects.all().none().exists())

class CompilerIsolationTest(KernelHostRequiredMixin, TestCase):

    def test_raising_compiler_is_not_caught_by_aggregate(self):
        User = get_user_model()
        registry = compiler(query_compiler=RaisingCompilerBackend.query_compiler)
        registry.path = RAISING
        handle = registry
        _contribute_document(handle)
        with self.assertRaises(RuntimeError) as ctx:
            granted(configured_catalog(HOST), Document, User(), Permission(), kind='complete')
            granted(built_catalog(handle), Document, User(), Permission(), kind='complete')
        self.assertIn('compiler exploded', str(ctx.exception))

    def test_mixin_only_alone_does_not_inherit_document_plan(self):
        self.assertFalse(configured_catalog(HOST).plan_for(Document).records)
        self.assertTrue(configured_catalog(DOCUMENT).plan_for(Document).records)
