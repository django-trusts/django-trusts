"""Held-backend reconciliation: config holds registrations AND lowered.

``configured_backend()`` is the one obtaining call. The owning config
holds ``registries[path]`` (raw ``register()`` store) and the lowered
held object in ``_lowered_by_path[path]``; every obtaining call returns
the identical held object until a new registration invalidates it.
"""

import tests as tests_module
from django.contrib.auth import get_user_model
from django.contrib.contenttypes.models import ContentType
from django.contrib.auth.models import Permission
from django.test import SimpleTestCase, TestCase, override_settings

from tests.apps import live_config
from tests.core import KernelHostRequiredMixin
from tests.kernel_host.apps import HOST_BACKEND
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.myapp.models import Document, DocumentGrant
from trusts.apps import (
    TrustsImplementationConfig,
    configured_backend as module_configured_backend,
    implementation_for_path,
)
from trusts.errors import TrustsConfigurationError
from trusts.plan.registry import HeldBackend

HOST = HOST_BACKEND
PERM = 'myapp.change_document'


class _AppsView(object):
    def __init__(self, configs, ready=True):
        self._configs = list(configs)
        self.ready = ready

    def get_app_configs(self):
        return tuple(self._configs)


def _bind(config_cls):
    config = config_cls('tests', tests_module)
    view = _AppsView([config])
    config.apps = view
    return config


class _IsolatedConfig(TrustsImplementationConfig):
    name = 'tests'
    label = 'trusts_impl_held_isolated'
    trusts_backend_paths = (HOST,)


class HeldIdentityTest(SimpleTestCase):
    def test_configured_backend_returns_identical_held_object(self):
        config = _bind(_IsolatedConfig)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            first = config.configured_backend(HOST)
            second = config.configured_backend(HOST)
            self.assertIs(first, second)
            self.assertIsInstance(first, HeldBackend)
            self.assertIs(config._lowered_by_path[HOST], first)
            # Registration store and lowered held are distinct, linked:
            self.assertIs(first.registry, config.registries[HOST])
            self.assertIs(first.registry, config._ensure(HOST))

    def test_module_level_configured_backend_delegates_to_same_held(self):
        config = _bind(_IsolatedConfig)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            via_config = config.configured_backend(HOST)
            via_module = module_configured_backend(
                HOST, apps_registry=config.apps,
            )
            self.assertIs(via_module, via_config)

    def test_new_registration_invalidates_and_answers_with_it(self):
        config = _bind(_IsolatedConfig)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            first = config.configured_backend(HOST)
            self.assertEqual(first.records, ())
            # Register through the held object: reaches the same raw store.
            first.register(
                trust=DocumentGrant,
                user='user',
                permission='permission',
                content='document',
            )
            self.assertIs(first.registry, config.registries[HOST])
            second = config.configured_backend(HOST)
            self.assertIsNot(second, first)
            self.assertIs(second.registry, first.registry)
            self.assertEqual(len(second.records), 1)
            self.assertIs(second.records[0].root, DocumentGrant)
            # The stale held object is an unchanged snapshot.
            self.assertEqual(first.records, ())
            # And the new held object is now the identical one returned.
            self.assertIs(config.configured_backend(HOST), second)

    def test_failed_lowering_caches_nothing(self):
        config = _bind(_IsolatedConfig)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            held = config.configured_backend(HOST)
            from trusts.compile.nodes import Ref

            root = Ref(DocumentGrant)
            held.registry.register(
                content=root.missing, user=root.user,
                permission=root.permission,
            )
            with self.assertRaises(TrustsConfigurationError):
                config.configured_backend(HOST)
            self.assertNotIn(HOST, config._lowered_by_path)
            with self.assertRaises(TrustsConfigurationError):
                config.configured_backend(HOST)


class BackendUsesHeldTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        super().setUp()
        user_model = get_user_model()
        self.alice = user_model.objects.create_user('alice-held', password='x')
        content_type = ContentType.objects.get_for_model(Document)
        self.change, _created = Permission.objects.get_or_create(
            content_type=content_type, codename='change_document',
            defaults={'name': 'Can change document'},
        )
        self.doc = Document.objects.create(title='held-doc')
        DocumentGrant.objects.create(
            document=self.doc, user=self.alice, permission=self.change,
        )
        self.backend = DocumentBackend()

    def test_has_perm_uses_identical_held_across_questions(self):
        owner = implementation_for_path(DOCUMENT_BACKEND)
        held_before = owner.configured_backend(DOCUMENT_BACKEND)
        self.assertTrue(self.backend.has_perm(self.alice, PERM, self.doc))
        held_mid = owner.configured_backend(DOCUMENT_BACKEND)
        self.assertTrue(self.backend.has_perm(self.alice, PERM, self.doc))
        held_after = owner.configured_backend(DOCUMENT_BACKEND)
        self.assertIs(held_before, held_mid)
        self.assertIs(held_mid, held_after)
        self.assertIs(self.backend._obtain_held(), held_before)
        # get_all_permissions goes through the same held object too.
        self.assertIn(PERM, self.backend.get_all_permissions(self.alice, self.doc))
        self.assertIs(owner.configured_backend(DOCUMENT_BACKEND), held_before)


class _LegacyHandleConfig(TrustsImplementationConfig):
    name = 'tests'
    label = 'trusts_impl_held_legacy'
    trusts_backend_paths = (HOST,)

    def _create_handle(self, path, registry, compiler):
        from trusts.plan.handles import BackendHandle

        return BackendHandle(path=path, registry=registry, compiler=compiler)


class _RegistryFactoryConfig(TrustsImplementationConfig):
    name = 'tests'
    label = 'trusts_impl_held_regfactory'
    trusts_backend_paths = (HOST,)

    def _create_handle(self, path, registry, compiler):
        return registry.build_registry()


class HeldCompatTest(SimpleTestCase):
    def test_legacy_handle_factory_is_promoted_to_held(self):
        config = _bind(_LegacyHandleConfig)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            held = config.configured_backend(HOST)
            self.assertIsInstance(held, HeldBackend)
            self.assertIs(held.registry, config.registries[HOST])
            self.assertIs(config.configured_backend(HOST), held)

    def test_registry_factory_candidate_is_held_as_is(self):
        config = _bind(_RegistryFactoryConfig)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            held = config.configured_backend(HOST)
            self.assertIs(config.configured_backend(HOST), held)
            self.assertEqual(held.records, ())

    def test_lazy_lowered_store_recreated(self):
        config = _bind(_IsolatedConfig)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            first = config.configured_backend(HOST)
            del config._lowered_by_path
            second = config.configured_backend(HOST)
            self.assertIsNot(second, first)
            self.assertIs(config.configured_backend(HOST), second)

    def test_module_level_no_path_and_ambiguous(self):
        config = _bind(_IsolatedConfig)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST,)):
            self.assertIs(
                module_configured_backend(apps_registry=config.apps),
                config.configured_backend(HOST),
            )
        with override_settings(AUTHENTICATION_BACKENDS=()):
            with self.assertRaises(TrustsConfigurationError):
                module_configured_backend(apps_registry=config.apps)

    def test_as_held_normalization(self):
        from trusts.backends import _as_held
        from trusts.compile.factory import TrustsRegistry
        from trusts.plan.handles import BackendHandle
        from trusts.plan.relations import PlanQueryCompiler

        self.assertIsNone(_as_held(None))
        self.assertIsNone(_as_held(BackendHandle(
            path='x', registry=None, compiler=PlanQueryCompiler(),
        )))
        raw = TrustsRegistry()
        handle = BackendHandle(
            path='x', registry=raw, compiler=PlanQueryCompiler(),
        )
        held = _as_held(handle)
        self.assertIsInstance(held, HeldBackend)
        self.assertIs(held.registry, raw)
        self.assertFalse(held.historical_fallback)
        built = raw.build_registry()
        wrapped = _as_held(built)
        self.assertIsInstance(wrapped, HeldBackend)
        self.assertEqual(wrapped.records, ())
        self.assertIs(_as_held(held), held)


class HeldDirectQuestionsTest(KernelHostRequiredMixin, TestCase):
    def setUp(self):
        super().setUp()
        user_model = get_user_model()
        self.alice = user_model.objects.create_user('alice-heldq', password='x')
        content_type = ContentType.objects.get_for_model(Document)
        self.change, _created = Permission.objects.get_or_create(
            content_type=content_type, codename='change_document',
            defaults={'name': 'Can change document'},
        )
        self.doc = Document.objects.create(title='heldq-doc')
        DocumentGrant.objects.create(
            document=self.doc, user=self.alice, permission=self.change,
        )

    def test_held_answers_questions_directly(self):
        owner = implementation_for_path(DOCUMENT_BACKEND)
        held = owner.configured_backend(DOCUMENT_BACKEND)
        self.assertTrue(held.has_permission(self.alice, self.doc, self.change))
        self.assertFalse(held.historical_fallback)
        authorized = held.filter_authorized(
            Document.objects.all(), self.alice, self.change,
        )
        self.assertEqual(list(authorized), [self.doc])
        permissions = held.permissions_for(self.alice, self.doc)
        self.assertIn(
            self.change.pk, list(permissions.values_list('pk', flat=True)),
        )
        users = held.permitted_users(self.doc, self.change)
        self.assertIn(self.alice.pk, list(users.values_list('pk', flat=True)))
