"""#89: build-on-demand / projection lifecycle on standalone and live registries.

Registration stays open: a backend question builds a fresh registry
from the builder's current records, so registering after a build (or
after a first live read) takes effect on the next build / question.

Missing-declaration E003 on Content/Junction stays on Zero ``tests/legacy/``.
"""

from unittest.mock import patch

from django.apps import apps
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.test import SimpleTestCase, TestCase, override_settings

from tests.apps import install_writable_registry, live_config, override_apps_ready
from tests.core import KernelHostRequiredMixin
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.backends import HostTrustModelBackend
from tests.myapp.backends import DocumentBackend
from trusts.backends import registries as backend_registries
from tests.myapp.models import Document, DocumentGrant
from trusts.apps import implementation_for_path
from tests.apps import backend_handle
from trusts.plan.relations import PlanQueryCompiler
from trusts.compile.nodes import Ref
from trusts.errors import TrustsConfigurationError
from trusts.compile.factory import TrustsCompiler


HOST = HOST_BACKEND
DOCUMENT = DOCUMENT_BACKEND


def _host_handle():
    return backend_handle(
        path=HOST, registry=HostTrustModelBackend().get_registry(),
        compiler=PlanQueryCompiler(),
    )


def _document_handle():
    return backend_handle(
        path=DOCUMENT, registry=DocumentBackend().get_registry(),
        compiler=PlanQueryCompiler(),
    )
MIXIN = 'tests.backends.MixinOnlyBackend'


def _contribute_document(registry):
    j = Ref(DocumentGrant)
    registry.register(
        content=j.document,
        user=j.user,
        permission=j.permission,
    )


class StandaloneIndependenceTest(SimpleTestCase):
    def test_standalone_stays_writable_after_global_ready(self):
        self.assertTrue(apps.ready)
        first = TrustsCompiler()
        second = TrustsCompiler()
        self.assertEqual(first.build_compiled().records, ())
        _contribute_document(second)
        self.assertEqual(len(second.plan_for(Document).records), 1)
        # Building ``first`` did not close it: a late registration is
        # stored and visible in its next build, independent of second.
        _contribute_document(first)
        self.assertEqual(len(first.records), 1)
        self.assertEqual(first.build_compiled().records, first.records)
        self.assertIsNot(first.records[0], second.records[0])

    def test_build_is_repeatable_and_register_does_not_inspect_apps_ready(self):
        registry = TrustsCompiler()
        _contribute_document(registry)
        before = registry.records
        first_build = registry.build_compiled()
        second_build = registry.build_compiled()
        self.assertIsNot(first_build, second_build)
        self.assertEqual(first_build.records, before)
        self.assertEqual(second_build.records, before)
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


class RegisterAfterBuildLeavesRecordsUnchangedTest(SimpleTestCase):
    def test_valid_duplicate_conflict_and_malformed_all_raise(self):
        registry = TrustsCompiler()
        j = Ref(DocumentGrant)
        registry.register(
            content=j.document,
            user=j.user,
            permission=j.permission,
        )
        before = registry.records
        registry.build_compiled()
        attempts = (
            dict(content=j.document, user=j.user, permission=j.permission),
            dict(content=j.document, user=j.permission, permission=j.user),
            dict(content='not-a-ref', user=j.user, permission=j.permission),
        )
        for kwargs in attempts:
            with self.assertRaises(TrustsConfigurationError) as ctx:
                registry.register(**kwargs)
            self.assertNotIn('frozen', str(ctx.exception).lower())
        self.assertEqual(registry.records, before)
        self.assertEqual(len(registry.plan_for(Document).records), 1)


class BuiltPlanProjectionsTest(KernelHostRequiredMixin, TestCase):
    def test_built_plan_still_projects(self):
        registry = TrustsCompiler()
        _contribute_document(registry)
        before = registry.plan_for(Document)
        registry.build_compiled()
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
        self.saved_registries = dict(backend_registries)

    def tearDown(self):
        backend_registries.clear()
        backend_registries.update(self.saved_registries)
        super().tearDown()


class LiveBuildLifecycleTest(
    KernelHostRequiredMixin, _LiveRegistryRestoreMixin, SimpleTestCase,
):
    def test_writable_during_contributor_ready_and_after_first_read(self):
        live = live_config()
        isolated = TrustsCompiler()
        backend_registries[HostTrustModelBackend] = isolated
        with override_apps_ready(False):
            handle = _host_handle()
            self.assertIs(handle.registry, isolated)
            _contribute_document(isolated)
            alias = HostTrustModelBackend().get_registry()
            self.assertIs(alias, isolated)
        handle = _host_handle()
        self.assertIs(handle.registry, isolated)
        self.assertEqual(handle.build_compiled().records, isolated.records)
        # First live read did not close registration: a duplicate is
        # rejected as a duplicate, and the stored record is unchanged.
        with self.assertRaises(TrustsConfigurationError):
            _contribute_document(isolated)
        self.assertEqual(len(isolated.plan_for(Document).records), 1)

    def test_multi_path_reversed_duplicate_and_late_observed_path(self):
        live = live_config()
        document = implementation_for_path(DOCUMENT)
        with override_settings(AUTHENTICATION_BACKENDS=(DOCUMENT, HOST)):
            handles = (_document_handle(), _host_handle())
            self.assertEqual(
                [handle.path for handle in handles], [DOCUMENT, HOST],
            )
            self.assertEqual(handles[0].build_compiled().records,
                             handles[0].registry.records)
            self.assertEqual(handles[1].build_compiled().records,
                             handles[1].registry.records)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, HOST)):
            handle = _host_handle()
            self.assertEqual(handle.path, HOST)
            self.assertIsNotNone(handle.build_compiled())

    def test_ready_does_not_replace_stored_objects(self):
        live = live_config()
        store = backend_registries
        first = backend_registries[HostTrustModelBackend]
        live.ready()
        self.assertIs(backend_registries, store)
        self.assertIs(backend_registries[HostTrustModelBackend], first)

    def test_late_registry_assignment_stays_writable(self):
        live = live_config()
        replacement = TrustsCompiler()
        backend_registries[HostTrustModelBackend] = replacement
        self.assertIs(backend_registries[HostTrustModelBackend], replacement)
        _contribute_document(replacement)
        self.assertEqual(len(replacement.records), 1)
        handle = _host_handle()
        self.assertEqual(handle.build_compiled().records, replacement.records)

    def test_assignment_before_ready_stays_writable_on_read(self):
        live = live_config()
        replacement = TrustsCompiler()
        with override_apps_ready(False):
            backend_registries[HostTrustModelBackend] = replacement
            self.assertIs(backend_registries[HostTrustModelBackend], replacement)
            _contribute_document(replacement)
        handle = _host_handle()
        self.assertIs(handle.registry, replacement)
        before = replacement.records
        self.assertEqual(handle.build_compiled().records, before)
        with self.assertRaises(TrustsConfigurationError):
            _contribute_document(replacement)
        self.assertEqual(replacement.records, before)

    def test_standalone_appconfig_remains_writable_after_ready(self):
        from tests.core.test_issue108 import HostImplConfig, _bind

        isolated = _bind(HostImplConfig, ready=False)
        self.assertFalse(isolated._apps_instance_ready())
        first = TrustsCompiler()
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            isolated.ready()
        _contribute_document(first)
        self.assertEqual(len(first.records), 1)


class SentinelAfterFirstReadTest(
    KernelHostRequiredMixin, _LiveRegistryRestoreMixin, SimpleTestCase,
):
    def test_same_instance_reentry_is_noop_after_first_read(self):
        live = live_config()
        handle = _host_handle()
        before = handle.registry.records
        with patch.object(
            handle.registry, 'register', wraps=handle.registry.register,
        ) as register:
            live.ready()
        register.assert_not_called()
        self.assertEqual(handle.registry.records, before)

    def test_package_ready_after_supported_read_leaves_registry_writable(self):
        live = live_config()
        isolated = install_writable_registry(live, HOST)
        _host_handle()
        live.ready()
        self.assertEqual(isolated.records, ())
        self.assertIs(backend_registries[HostTrustModelBackend], isolated)
        _contribute_document(isolated)
        self.assertEqual(len(isolated.records), 1)


class BackendQuestionAfterLateRegistrationTest(
    KernelHostRequiredMixin, TestCase,
):
    """A backend question after late registration sees the new record."""

    def setUp(self):
        super().setUp()
        self.config = implementation_for_path(DOCUMENT)
        self.saved_registries = dict(backend_registries)
        self.isolated = TrustsCompiler()
        backend_registries[DocumentBackend] = self.isolated

    def tearDown(self):
        backend_registries.clear()
        backend_registries.update(self.saved_registries)
        super().tearDown()

    def test_backend_question_after_late_registration_sees_it(self):
        user = get_user_model().objects.create_user(
            'late-89', password='x',
        )
        content_type = ContentType.objects.get_for_model(Document)
        permission, _created = Permission.objects.get_or_create(
            content_type=content_type,
            codename='change_document',
            defaults={'name': 'Can change document'},
        )
        document = Document.objects.create(title='late-89')
        DocumentGrant.objects.create(
            document=document, user=user, permission=permission,
        )
        backend = DocumentBackend()
        # Empty builder: the first question builds an empty registry.
        self.assertFalse(
            backend.has_perm(user, 'myapp.change_document', document),
        )
        # Late registration on the same builder: next question sees it.
        _contribute_document(self.isolated)
        self.assertTrue(
            backend.has_perm(user, 'myapp.change_document', document),
        )


class HandleBuildRegistrySignalTest(SimpleTestCase):
    """``BackendHandle.build_compiled``: fresh build, or ``None``."""

    def test_none_duck_and_fresh_builds(self):
        none_handle = backend_handle(
            path='tests.core.no-registry', registry=None,
            compiler=PlanQueryCompiler(),
        )
        self.assertIsNone(none_handle.build_compiled())

        duck = object()
        duck_handle = backend_handle(
            path='tests.core.duck', registry=duck, compiler=object(),
        )
        self.assertIs(duck_handle.build_compiled(), duck)
        self.assertFalse(duck_handle.historical_fallback)

        registry = TrustsCompiler()
        handle = backend_handle(
            path='tests.core.builder', registry=registry,
            compiler=PlanQueryCompiler(),
        )
        first = handle.build_compiled()
        second = handle.build_compiled()
        self.assertIsNot(first, second)
        self.assertEqual(first.records, ())
        _contribute_document(registry)
        self.assertEqual(handle.build_compiled().records, registry.records)
        self.assertEqual(first.records, ())
