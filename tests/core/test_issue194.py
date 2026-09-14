"""#194: protected family factories and family-local Core aggregates."""

from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.http import HttpRequest
from django.test import SimpleTestCase, TestCase, override_settings

import tests as tests_module
from tests.apps import live_config, override_apps_ready
from tests.backends import MixinOnlyBackend
from tests.core import KernelHostRequiredMixin
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentAltGrant, DocumentGrant
from trusts.apps import (
    TrustsImplementationConfig,
    _handle_authorization_family,
    _relationship_family_handles,
    _relationship_implementation_handles,
    configured_implementation_handles,
    implementation_for_path,
)
from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    QueryCompiler,
    TrustsConfigurationError,
    TrustsRegistry,
    _compiler_applies,
    common_permissions,
    filter_authorized_scopes,
    granted,
)
from trusts.decorators import (
    _declared_authorization_guards,
    authorization_required,
)


HOST = HOST_BACKEND
DOCUMENT = DOCUMENT_BACKEND
MIXIN = 'tests.backends.MixinOnlyBackend'
PERM = 'myapp.change_document'


class FoldFamilyConfig(TrustsImplementationConfig):
    name = 'tests'
    label = 'trusts_impl_194_fold'
    trusts_backend_paths = (MIXIN,)
    _authorization_family = 'ordered_fold'


class RecordingRegistry(TrustsRegistry):
    created = True


class RecordingHandle(BackendHandle):
    created = True


class RecordingConfig(TrustsImplementationConfig):
    name = 'tests'
    label = 'trusts_impl_194_record'
    trusts_backend_paths = (HOST,)

    def _create_registry(self, path):
        self.created_paths = getattr(self, 'created_paths', ()) + (path,)
        return RecordingRegistry()

    def _create_handle(self, path, registry, compiler):
        self.handle_paths = getattr(self, 'handle_paths', ()) + (path,)
        return RecordingHandle(
            path=path, registry=registry, compiler=compiler,
        )


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
    view = _AppsView(
        configs if configs is not None else [config],
        ready=ready,
    )
    config.apps = view
    if configs is None:
        view._configs = [config]
    return config


def _permission(model, codename, name):
    ct = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=ct,
        codename=codename,
        defaults={'name': name},
    )
    return permission


def _request(user):
    request = HttpRequest()
    request.user = user
    request.META['SERVER_NAME'] = 'testserver'
    request.META['SERVER_PORT'] = '80'
    return request


class ProtectedFactorySurfaceTest(SimpleTestCase):
    def test_default_family_and_factories_are_protected(self):
        self.assertEqual(
            TrustsImplementationConfig._authorization_family, 'relationship',
        )
        self.assertFalse(hasattr(TrustsImplementationConfig, 'authorization_family'))
        self.assertTrue(callable(TrustsImplementationConfig._create_registry))
        self.assertTrue(callable(TrustsImplementationConfig._create_handle))
        self.assertTrue(callable(QueryCompiler().applies))
        self.assertTrue(callable(PlanQueryCompiler().applies))

    def test_relationship_applies_is_records_only(self):
        compiler = PlanQueryCompiler()
        protocol = QueryCompiler()
        empty = type('Plan', (), {'records': ()})()
        filled = type('Plan', (), {
            'records': (object(),),
            'strategy': object(),
        })()
        strategy_only = type('Plan', (), {
            'records': (),
            'strategy': object(),
        })()
        self.assertFalse(compiler.applies(empty))
        self.assertFalse(protocol.applies(empty))
        self.assertTrue(compiler.applies(filled))
        self.assertTrue(protocol.applies(filled))
        self.assertFalse(compiler.applies(strategy_only))
        self.assertFalse(protocol.applies(strategy_only))
        self.assertFalse(_compiler_applies(compiler, strategy_only))

    def test_ensure_and_configured_backend_use_factories(self):
        config = _bind(RecordingConfig, ready=False)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            first = config._ensure(HOST)
            self.assertIsInstance(first, RecordingRegistry)
            self.assertEqual(config.created_paths, (HOST,))
            self.assertIs(config._ensure(HOST), first)
            self.assertEqual(config.created_paths, (HOST,))
            handle = config.configured_backend(HOST)
            self.assertIsInstance(handle, RecordingHandle)
            self.assertTrue(handle.created)
            self.assertIs(handle.registry, first)
            self.assertEqual(config.handle_paths, (HOST,))
            self.assertFalse(first.frozen)
            config.apps.ready = True
            live = config.configured_backend(HOST)
            self.assertIs(live.registry, first)
            self.assertTrue(first.frozen)
            self.assertIsInstance(live, RecordingHandle)

    def test_unowned_handle_defaults_to_relationship_family(self):
        handle = BackendHandle(
            path=MIXIN,
            registry=TrustsRegistry(),
            compiler=PlanQueryCompiler(),
        )
        self.assertEqual(_handle_authorization_family(handle), 'relationship')
        self.assertEqual(_relationship_family_handles((handle,)), (handle,))


class FamilyLocalAggregateTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.alice = User.objects.create_user('alice-194', password='x')
        self.change = _permission(Document, 'change_document', 'Can change document')
        self.rel_doc = Document.objects.create(title='rel-194')
        self.fold_doc = Document.objects.create(title='fold-194')
        DocumentGrant.objects.create(
            document=self.rel_doc, user=self.alice, permission=self.change,
        )
        DocumentAltGrant.objects.create(
            document=self.fold_doc, user=self.alice, permission=self.change,
        )
        self.rel_owner = implementation_for_path(DOCUMENT)
        self.rel_handle = self.rel_owner.configured_backend()
        self.fold_registry = TrustsRegistry()
        self.fold_handle = BackendHandle(
            path=MIXIN,
            registry=self.fold_registry,
            compiler=PlanQueryCompiler(),
        )
        self.fold_handle.register(
            trust=DocumentAltGrant,
            user='user',
            permission='permission',
            content='document',
        )
        self.fold_owner = _bind(FoldFamilyConfig, ready=False)
        self.fold_owner.registries[MIXIN] = self.fold_registry
        self.fold_owner.apps._configs = [self.rel_owner, self.fold_owner]
        self.mixin = MixinOnlyBackend()
        self.document_backend = DocumentBackend()

    def _family_patches(self):
        return (
            patch(
                'trusts.apps.implementation_configs',
                return_value=(self.rel_owner, self.fold_owner),
            ),
            patch(
                'trusts.apps.configured_implementation_handles',
                return_value=(self.rel_handle, self.fold_handle),
            ),
            override_settings(AUTHENTICATION_BACKENDS=(
                HOST, DOCUMENT, MIXIN,
            )),
        )

    def test_fold_family_handle_is_omitted_from_core_aggregates(self):
        impl, listed, settings = self._family_patches()
        with impl, listed, settings:
            rel_only = granted(
                (self.rel_handle,), Document.objects.all(),
                self.alice, self.change,
            )
            fold_only = granted(
                (self.fold_handle,), Document.objects.all(),
                self.alice, self.change,
            )
            self.assertIsNotNone(rel_only)
            self.assertIsNone(fold_only)
            mixed = granted(
                (self.rel_handle, self.fold_handle),
                Document.objects.all(), self.alice, self.change,
            )
            self.assertIsNotNone(mixed)
            with self.assertNumQueries(1):
                self.assertEqual(
                    set(Document.objects.filter(mixed).values_list('pk', flat=True)),
                    {self.rel_doc.pk},
                )

            rel_perms = common_permissions(
                (self.rel_handle,), self.rel_doc, self.alice,
            )
            fold_perms = common_permissions(
                (self.fold_handle,), self.fold_doc, self.alice,
            )
            mixed_perms = common_permissions(
                (self.rel_handle, self.fold_handle),
                self.rel_doc, self.alice,
            )
            self.assertIsNotNone(rel_perms)
            self.assertIsNone(fold_perms)
            self.assertIsNotNone(mixed_perms)
            self.assertIn(
                'change_document',
                set(mixed_perms.values_list('codename', flat=True)),
            )

            rel_scopes = filter_authorized_scopes(
                Document.objects.all(), self.alice, self.change,
                content=self.rel_doc, handles=(self.rel_handle,),
            )
            fold_scopes = filter_authorized_scopes(
                Document.objects.all(), self.alice, self.change,
                content=self.fold_doc, handles=(self.fold_handle,),
            )
            self.assertEqual(list(rel_scopes), [])
            self.assertEqual(list(fold_scopes), [])
            self.assertEqual(
                [handle.path for handle in _relationship_implementation_handles()],
                [DOCUMENT],
            )
            self.assertEqual(
                [
                    handle.path
                    for handle in configured_implementation_handles()
                ],
                [DOCUMENT, MIXIN],
            )
            with self.assertNumQueries(1):
                authorized = set(
                    Document.objects.authorized(
                        self.alice, self.change,
                    ).values_list('pk', flat=True)
                )
            self.assertEqual(authorized, {self.rel_doc.pk})
            self.assertNotIn(self.fold_doc.pk, authorized)

            @authorization_required(Document, PERM)
            def _guard(request, pk):
                return 'ok'

            entry = (Document, PERM, ())
            self.addCleanup(
                lambda: _declared_authorization_guards.remove(entry)
                if entry in _declared_authorization_guards else None,
            )

            self.assertEqual(_guard(_request(self.alice), pk=self.rel_doc.pk), 'ok')
            with self.assertRaises(PermissionDenied):
                _guard(_request(self.alice), pk=self.fold_doc.pk)

    def test_mixin_own_handle_still_evaluates_fold_family_path(self):
        impl, listed, settings = self._family_patches()
        with impl, listed, settings:
            with self.assertNumQueries(1):
                self.assertTrue(
                    self.mixin.has_perm(self.alice, PERM, self.fold_doc),
                )
            with self.assertNumQueries(1):
                self.assertFalse(
                    self.document_backend.has_perm(
                        self.alice, PERM, self.fold_doc,
                    ),
                )
            with self.assertNumQueries(1):
                self.assertEqual(
                    self.mixin.get_all_permissions(self.alice, self.fold_doc),
                    {PERM},
                )
            with self.assertNumQueries(1):
                self.assertEqual(
                    set(
                        Document.objects.authorized(
                            self.alice, self.change,
                        ).values_list('pk', flat=True)
                    ),
                    {self.rel_doc.pk},
                )


class MixinAppliesHookTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        super().setUp()
        User = get_user_model()
        self.alice = User.objects.create_user('alice-194a', password='x')
        self.change = _permission(Document, 'change_document', 'Can change document')
        self.doc = Document.objects.create(title='applies-194')
        DocumentGrant.objects.create(
            document=self.doc, user=self.alice, permission=self.change,
        )
        self.backend = DocumentBackend()

    def test_inapplicable_compiler_is_zero_sql(self):
        handle = implementation_for_path(DOCUMENT).configured_backend()
        silent = BackendHandle(
            path=handle.path,
            registry=handle.registry,
            compiler=_NeverAppliesCompiler(),
        )
        with patch.object(self.backend, '_own_handle', return_value=silent):
            with self.assertNumQueries(0):
                self.assertFalse(
                    self.backend.has_perm(self.alice, PERM, self.doc),
                )
                self.assertEqual(
                    self.backend.get_all_permissions(self.alice, self.doc),
                    set(),
                )

    def test_relationship_applies_keeps_live_grant(self):
        with self.assertNumQueries(1):
            self.assertTrue(self.backend.has_perm(self.alice, PERM, self.doc))


class FactoryFreezeOwnershipTest(KernelHostRequiredMixin, SimpleTestCase):
    def test_live_configured_backend_still_freezes_factory_registry(self):
        live = live_config()
        isolated = live._create_registry(HOST)
        self.assertIsInstance(isolated, TrustsRegistry)
        self.assertFalse(isolated.frozen)
        saved = dict(live.registries)
        live.registries[HOST] = isolated
        try:
            with override_apps_ready(False):
                handle = live.configured_backend()
                self.assertIs(handle.registry, isolated)
                self.assertFalse(isolated.frozen)
            handle = live.configured_backend()
            self.assertIs(handle.registry, isolated)
            self.assertTrue(isolated.frozen)
            self.assertIsInstance(handle, BackendHandle)
            self.assertEqual(handle.path, HOST)
        finally:
            live.registries.clear()
            live.registries.update(saved)

    def test_unconfigured_path_still_fails_loud(self):
        live = live_config()
        with self.assertRaises(TrustsConfigurationError) as ctx:
            live.configured_backend(MIXIN)
        self.assertIn(MIXIN, str(ctx.exception))
