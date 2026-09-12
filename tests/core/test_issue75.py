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
from tests.apps import (
    TestsConfig,
    install_writable_registry,
    isolate_live_registry,
    live_config,
    override_apps_ready,
)
from tests.backends import (
    HostTrustModelBackend,
    MalformedCompilerBackend,
    MixinOnlyBackend,
    MissingCompilerBackend,
    RaisingCompilerBackend,
)
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.models import Document, DocumentGrant
from trusts.apps import implementation_for_path
from trusts.backends import TrustModelBackendMixin
from trusts.checks import CHECK_ID_MISSING_COMPILER, check_query_compilers
from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    TrustsCompilerError,
    TrustsConfigurationError,
    TrustsRegistry,
    compiler_for_class,
    granted,
)
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
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename='change_document',
        defaults={'name': 'Can change document'},
    )
    return permission


def _contribute_document(registry):
    from trusts.core import Ref

    j = Ref(DocumentGrant)
    registry.register(
        content=j.document,
        user=j.user,
        permission=j.permission,
    )


def _evaluate(handle, queryset, user, permission):
    plan = handle.registry.plan_for(
        queryset, user=user, permission=permission,
    )
    return handle.compiler.complete_exists(plan, queryset, user, permission)


class PathScopedRegistryStoreTest(KernelHostRequiredMixin, SimpleTestCase):
    def test_one_path_registry_alias_is_exact_store(self):
        live = live_config()
        handle = live.configured_backend()
        self.assertEqual(handle.path, HOST)
        self.assertIs(handle.registry, live.registry)
        self.assertIs(live.registry, live.registries[HOST])
        self.assertIsInstance(handle, BackendHandle)
        self.assertIs(handle.compiler, HostTrustModelBackend.query_compiler)
        self.assertIsInstance(handle.compiler, PlanQueryCompiler)

    def test_duplicate_identical_paths_dedupe(self):
        live = live_config()
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, HOST)):
            paths = live._configured_trusts_paths()
            self.assertEqual(paths, (HOST,))
            self.assertIs(live.registry, live.registries[HOST])
            handle = live.configured_backend()
            self.assertEqual(handle.path, HOST)

    def test_same_class_alias_is_ambiguity_error(self):
        live = live_config()
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, ALIASED)):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                live._configured_trusts_paths()
            self.assertIn('multiple paths', str(ctx.exception))
            with self.assertRaises(TrustsConfigurationError):
                live.configured_backend()
            with self.assertRaises(TrustsConfigurationError):
                live.registry

    def test_unconfigured_path_fails_loud(self):
        live = live_config()
        with self.assertRaises(TrustsConfigurationError) as ctx:
            live.configured_backend(MIXIN)
        self.assertIn(MIXIN, str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError):
            live.path_for_class(MixinOnlyBackend)
        with self.assertRaises(TrustsConfigurationError):
            live.path_for_backend(MixinOnlyBackend())

    def test_zero_and_multiple_alias_access_fail(self):
        live = live_config()
        with override_settings(AUTHENTICATION_BACKENDS=(
            'django.contrib.auth.backends.ModelBackend',
        )):
            self.assertEqual(live._configured_trusts_paths(), ())
            with self.assertRaises(TrustsConfigurationError):
                live.registry
            with self.assertRaises(TrustsConfigurationError):
                live.configured_backend()
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, DOCUMENT)):
            # KernelHost owns only HOST, so the one-path alias still works.
            self.assertIs(live.configured_backend().path, HOST)
            handle_doc = live.configured_backend(DOCUMENT)
            self.assertEqual(handle_doc.path, DOCUMENT)
            self.assertIs(
                handle_doc.registry,
                implementation_for_path(DOCUMENT).registries[DOCUMENT],
            )

    def test_ready_does_not_replace_store_or_registry(self):
        live = live_config()
        store = live.registries
        first = live.registry
        live.ready()
        self.assertIs(live.registries, store)
        self.assertIs(live.registry, first)
        self.assertIs(live.registries[HOST], first)

    def test_compiler_is_class_owned_not_instance_state(self):
        first = HostTrustModelBackend()
        second = HostTrustModelBackend()
        self.assertIs(first.query_compiler, HostTrustModelBackend.query_compiler)
        self.assertIs(second.query_compiler, first.query_compiler)
        self.assertIs(
            MixinOnlyBackend.query_compiler,
            TrustModelBackendMixin.query_compiler,
        )
        self.assertIsInstance(
            TrustModelBackendMixin.query_compiler, PlanQueryCompiler,
        )
        self.assertIs(
            compiler_for_class(HostTrustModelBackend),
            HostTrustModelBackend.query_compiler,
        )
        self.assertIs(
            compiler_for_class(MixinOnlyBackend),
            MixinOnlyBackend.query_compiler,
        )


@isolate_apps(
    'tests',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    attr_name='isolated_apps',
)
class IsolatedAppsPathStoreTest(SimpleTestCase):
    def test_isolate_apps_without_owner_does_not_donate(self):
        live = live_config()
        before = live.registry.records
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertIsNone(
            getattr(contributor, '_trusts_tup_category_registry_id', None)
        )
        self.assertEqual(live.registry.records, before)


class ContributionPathTest(KernelHostRequiredMixin, SimpleTestCase):
    def test_explicit_path_contribution_writes_one_registry(self):
        host = live_config()
        document = implementation_for_path(DOCUMENT)
        self.assertTrue(document.registry.plan_for(Document).records)
        self.assertFalse(host.registry.plan_for(Document).records)

    def test_omitted_ambiguous_path_fails_before_writing(self):
        from tests.core.test_issue108 import HostImplConfig, _bind

        class DualImpl(HostImplConfig):
            label = 'trusts_impl_dual'
            trusts_backend_paths = (HOST, MIXIN)

        dual = _bind(DualImpl, ready=False)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, MIXIN)):
            with self.assertRaises(TrustsConfigurationError):
                dual.registry

    def test_no_mixin_fan_out(self):
        live = live_config()
        with self.assertRaises(TrustsConfigurationError):
            live.configured_backend(MIXIN)
        self.assertNotIn(MIXIN, live.registries)


class _LiveRegistryRestoreMixin(object):
    def setUp(self):
        super().setUp()
        self.live = live_config()
        self.saved_registries = dict(self.live.registries)

    def tearDown(self):
        self.live.registries.clear()
        self.live.registries.update(self.saved_registries)
        super().tearDown()


class CompilerProtocolTest(
    KernelHostRequiredMixin, _LiveRegistryRestoreMixin, SimpleTestCase,
):
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
                compiler_for_class(MissingCompilerBackend)

    def test_broken_second_path_is_not_omitted(self):
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, MISSING)):
            errors = [
                m for m in check_query_compilers(None)
                if m.id == CHECK_ID_MISSING_COMPILER
            ]
            self.assertEqual(len(errors), 1)

    def test_raising_compiler_propagates(self):
        User = get_user_model()
        handle = BackendHandle(
            path=RAISING,
            registry=TrustsRegistry(),
            compiler=RaisingCompilerBackend.query_compiler,
        )
        _contribute_document(handle.registry)
        with self.assertRaises(RuntimeError) as ctx:
            granted(
                (handle,), Document, User(),
                Permission(), kind='complete',
            )
        self.assertIn('compiler exploded', str(ctx.exception))


class CompilerCheckQueryCountTest(TestCase):
    def test_e004_check_issues_zero_sql(self):
        with override_settings(AUTHENTICATION_BACKENDS=(MISSING, HOST)):
            with self.assertNumQueries(0):
                check_query_compilers(None)


class TwoPathAuthorizationTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        User = get_user_model()
        self.alice = User.objects.create_user('alice-75', password='x')
        self.bob = User.objects.create_user('bob-75', password='x')
        self.change = _change_document()
        self.doc_a = Document.objects.create(title='a')
        self.doc_b = Document.objects.create(title='b')
        DocumentGrant.objects.create(
            document=self.doc_a, user=self.alice, permission=self.change,
        )
        self.host = live_config().configured_backend()
        self.document = implementation_for_path(DOCUMENT).configured_backend()

    def test_grant_only_through_document_path(self):
        self.assertFalse(self.host.registry.plan_for(Document).records)
        self.assertTrue(self.document.registry.plan_for(Document).records)
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
        self.assertFalse(
            Document.objects.authorized(self.bob, self.change).exists()
        )

    def test_aggregate_ors_both_complete_proofs_in_one_statement(self):
        isolated = TrustsRegistry()
        _contribute_document(isolated)
        extra = BackendHandle(
            path=MIXIN,
            registry=isolated,
            compiler=PlanQueryCompiler(),
        )
        qs = Document.objects.all()
        pred = granted(
            (self.host, self.document, extra),
            qs, self.alice, self.change, kind='complete',
        )
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

        self.assertTrue(self.document.registry.plan_for(Document).records)
        self.assertFalse(self.document.registry.plan_for(Organization).records)
        self.assertFalse(self.host.registry.plan_for(Document).records)
        self.assertEqual(
            _pks(Document.objects.authorized(self.alice, self.change)),
            {self.doc_a.pk},
        )
        self.assertFalse(
            Organization.objects.all().none().exists()
        )


class CompilerIsolationTest(KernelHostRequiredMixin, TestCase):
    def test_raising_compiler_is_not_caught_by_aggregate(self):
        User = get_user_model()
        live = live_config()
        handle = BackendHandle(
            path=RAISING,
            registry=TrustsRegistry(),
            compiler=RaisingCompilerBackend.query_compiler,
        )
        _contribute_document(handle.registry)
        with self.assertRaises(RuntimeError) as ctx:
            granted(
                (live.configured_backend(), handle),
                Document, User(), Permission(), kind='complete',
            )
        self.assertIn('compiler exploded', str(ctx.exception))

    def test_mixin_only_alone_does_not_inherit_document_plan(self):
        live = live_config()
        self.assertFalse(live.registry.plan_for(Document).records)
        self.assertTrue(
            implementation_for_path(DOCUMENT).registry.plan_for(Document).records
        )
