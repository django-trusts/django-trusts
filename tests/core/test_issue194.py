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
    _plan_authorization_family,
    _relationship_family_plans,
    _relationship_compiled_plans,
    configured_compiled_plans,
    implementation_for_path,
)
from trusts.plan.contents import filter_by_permitted_content
from trusts.plan.relations import QueryCompiler
from tests.apps import backend_handle
from trusts.plan.relations import PlanQueryCompiler
from trusts.errors import TrustsConfigurationError
from trusts.compile.factory import TrustsCompiler
from trusts.plan.contents import granted
from trusts.plan.aggregates import _compiler_applies, common_permissions
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
        self.assertFalse(hasattr(TrustsImplementationConfig, '_create_registry'))
        self.assertFalse(hasattr(TrustsImplementationConfig, '_create_handle'))
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

    def test_compiled_for_path_uses_per_class_registry(self):
        from tests.backends import HostTrustModelBackend
        from trusts.apps import _compiled_for_path

        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            registry = HostTrustModelBackend().get_registry()
            compiled = _compiled_for_path(HOST)
            self.assertIs(compiled.registry, compiled)
            self.assertEqual(compiled.path, HOST)
            self.assertEqual(compiled.records, registry.build_compiled().records)

    def test_unowned_handle_defaults_to_relationship_family(self):
        handle = backend_handle(
            path=MIXIN,
            registry=TrustsCompiler(),
            compiler=PlanQueryCompiler(),
        )
        self.assertEqual(_plan_authorization_family(handle), 'relationship')
        self.assertEqual(_relationship_family_plans((handle,)), (handle,))


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
        from trusts.apps import _compiled_for_path

        self.rel_handle = _compiled_for_path(DOCUMENT)
        self.fold_registry = TrustsCompiler()
        self.fold_handle = backend_handle(
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
        from trusts.backends import registries as _registries

        self._saved_mixin_registry = _registries.get(MixinOnlyBackend)
        _registries[MixinOnlyBackend] = self.fold_registry
        self.addCleanup(self._restore_mixin_registry)
        self.fold_owner.apps._configs = [self.rel_owner, self.fold_owner]
        self.mixin = MixinOnlyBackend()
        self.document_backend = DocumentBackend()

    def _restore_mixin_registry(self):
        from trusts.backends import registries as _registries

        if self._saved_mixin_registry is None:
            _registries.pop(MixinOnlyBackend, None)
        else:
            _registries[MixinOnlyBackend] = self._saved_mixin_registry

    def _family_patches(self):
        return (
            patch(
                'trusts.apps.implementation_configs',
                return_value=(self.rel_owner, self.fold_owner),
            ),
            patch(
                'trusts.apps.configured_compiled_plans',
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

            rel_scopes = filter_by_permitted_content(
                Document.objects.all(), self.alice, self.change,
                content=self.rel_doc, handles=(self.rel_handle,),
            )
            fold_scopes = filter_by_permitted_content(
                Document.objects.all(), self.alice, self.change,
                content=self.fold_doc, handles=(self.fold_handle,),
            )
            self.assertEqual(list(rel_scopes), [])
            self.assertEqual(list(fold_scopes), [])
            self.assertEqual(
                [handle.path for handle in _relationship_compiled_plans()],
                [DOCUMENT],
            )
            self.assertEqual(
                [
                    handle.path
                    for handle in configured_compiled_plans()
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
        from trusts.apps import _compiled_for_path

        handle = _compiled_for_path(DOCUMENT)
        silent = backend_handle(
            path=handle.path,
            registry=handle.registry,
            compiler=_NeverAppliesCompiler(),
        )
        with patch.object(self.backend, '_own_compiled', return_value=silent):
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


class FactoryBuildOwnershipTest(KernelHostRequiredMixin, SimpleTestCase):
    def test_live_backend_builds_compiled_on_demand(self):
        from tests.apps import isolate_live_registry
        from tests.backends import HostTrustModelBackend

        live = live_config()
        isolated = TrustsCompiler()
        saved = HostTrustModelBackend().get_registry()
        isolate_live_registry(live, isolated, HOST)
        try:
            backend = HostTrustModelBackend()
            self.assertIs(backend.get_registry()._compiler, isolated)
            first_build = backend.get_registry().build_compiled()
            second_build = backend.get_registry().build_compiled()
            self.assertIsNot(first_build, second_build)
            self.assertEqual(first_build.records, second_build.records)
            from tests.myapp.models import DocumentGrant
            from trusts.compile.nodes import Ref
            j = Ref(DocumentGrant)
            isolated.register(
                content=j.document, user=j.user, permission=j.permission,
            )
            self.assertEqual(
                backend.get_registry().build_compiled().records,
                isolated.records,
            )
            self.assertEqual(first_build.records, ())
        finally:
            isolate_live_registry(live, saved, HOST)

    def test_unconfigured_path_still_fails_loud(self):
        with self.assertRaises(TrustsConfigurationError) as ctx:
            implementation_for_path(MIXIN)
        self.assertIn(MIXIN, str(ctx.exception))
