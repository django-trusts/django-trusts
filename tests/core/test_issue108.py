"""#108 / #111: catalogs come from AUTHENTICATION_BACKENDS.

The sweep config receives ``ready()`` and does not own paths.
Core ships no ``kernel_config()``. Mixin identity stays.
Historical core backend is gone.
"""

from django.apps import AppConfig as DjangoAppConfig
from django.test import SimpleTestCase, override_settings
from django.test.utils import isolate_apps

import tests as tests_module
from tests.apps import (
    TestsConfig,
    configured_catalog,
    empty_catalogs,
    live_config,
    sweep_listed_backends,
)
from tests.backends import HostTrustModelBackend, MixinOnlyBackend
from tests.kernel_host.apps import HOST_BACKEND
from trusts.apps import TrustsImplementationConfig
from trusts.backends import catalogs
from trusts.backends import TrustModelBackendMixin, configured_catalogs
from trusts.compile.factory import RegistryFactory
from trusts.compile.nodes import Ref
from trusts.errors import TrustsConfigurationError
from trusts.decorators import filter_by_permitted_content
from trusts.query import AuthorizedManager, AuthorizedQuerySet


HOST = 'tests.backends.HostTrustModelBackend'
MIXIN = 'tests.backends.MixinOnlyBackend'
ALIASED = 'tests.backends.AliasedTrustModelBackend'


class ImplementationHelperSurfaceTest(SimpleTestCase):
    def test_core_is_not_an_implementation_appconfig(self):
        import trusts.apps as apps_mod

        self.assertFalse(hasattr(apps_mod, 'AppConfig'))
        self.assertFalse(hasattr(apps_mod, 'kernel_config'))
        self.assertFalse(TrustsImplementationConfig.default)
        self.assertIsInstance(live_config(), TrustsImplementationConfig)
        self.assertIs(type(live_config()), TrustsImplementationConfig)

    def test_helper_and_resolvers_import(self):
        import trusts.apps as apps_mod

        self.assertTrue(issubclass(TrustsImplementationConfig, DjangoAppConfig))
        self.assertFalse(hasattr(apps_mod, 'implementation_for_path'))
        self.assertFalse(hasattr(apps_mod, 'implementation_for_class'))
        self.assertFalse(hasattr(apps_mod, 'implementation_configs'))
        self.assertFalse(hasattr(apps_mod, 'relationship_registries'))
        self.assertFalse(hasattr(TrustsImplementationConfig, 'trusts_backend_paths'))
        self.assertFalse(hasattr(TrustsImplementationConfig, '_authorization_family'))

    def test_mixin_lives_only_on_trusts_backends(self):
        self.assertEqual(
            TrustModelBackendMixin.__module__, 'trusts.backends',
        )

    def test_historical_backend_no_longer_imports(self):
        import trusts.backends as backends_mod

        self.assertFalse(hasattr(backends_mod, 'TrustModelBackend'))
        self.assertFalse(hasattr(backends_mod, 'HistoricalGroupQueryCompiler'))

    def test_generic_declarations_import_without_kernel_config(self):
        import trusts.apps as apps_mod

        self.assertFalse(hasattr(apps_mod, 'kernel_config'))
        self.assertTrue(callable(filter_by_permitted_content))
        self.assertTrue(issubclass(AuthorizedQuerySet, object))
        self.assertTrue(issubclass(AuthorizedManager, object))
        registry = RegistryFactory()
        self.assertEqual(registry.records, ())
        self.assertIsNotNone(Ref)


class ImplementationRoutingTest(SimpleTestCase):
    def test_exact_path_routing_is_independent_of_app_order(self):
        host = configured_catalog(HOST)
        self.assertEqual(host.path, HOST)
        self.assertIs(host, catalogs[HostTrustModelBackend])
        self.assertEqual(host.family, HostTrustModelBackend.family)

    def test_missing_owner_fails_loud_before_sql(self):
        backend = MixinOnlyBackend()
        self.assertIsNone(backend.get_catalog())
        self.assertFalse(backend.has_perm(object(), 'myapp.change_document', object()))

    def test_duplicate_owner_fails_loud(self):
        with empty_catalogs():
            with override_settings(AUTHENTICATION_BACKENDS=(HOST, ALIASED)):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    sweep_listed_backends()
        self.assertIn('multiple paths', str(ctx.exception))
        self.assertIn(HostTrustModelBackend, catalogs)

    def test_class_path_identity_mismatch_fails_loud(self):
        with empty_catalogs():
            with override_settings(AUTHENTICATION_BACKENDS=(HOST, ALIASED)):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    sweep_listed_backends()
        self.assertIn('multiple paths', str(ctx.exception))


class ImplementationReadyTest(SimpleTestCase):
    def test_empty_authentication_backends_build_nothing(self):
        with empty_catalogs():
            with override_settings(AUTHENTICATION_BACKENDS=()):
                sweep_listed_backends()
                self.assertEqual(catalogs, {})

    def test_repeated_owned_path_fails_at_startup(self):
        with empty_catalogs():
            with override_settings(AUTHENTICATION_BACKENDS=(HOST, HOST)):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    sweep_listed_backends()
        self.assertIn('multiple paths', str(ctx.exception))

    def test_unlisted_class_is_not_built(self):
        self.assertIsNone(MixinOnlyBackend().get_catalog())
        self.assertNotIn(MixinOnlyBackend, catalogs)

    def test_second_ready_does_not_replace_catalogs(self):
        config = live_config()
        before = catalogs[HostTrustModelBackend]
        config.ready()
        config.ready()
        self.assertIs(catalogs[HostTrustModelBackend], before)
        self.assertFalse(hasattr(config, 'registries'))
        self.assertFalse(hasattr(config, 'trusts_backend_paths'))

    def test_listed_path_is_the_catalog_label(self):
        catalog = configured_catalog(HOST)
        self.assertIs(catalog, catalogs[HostTrustModelBackend])
        self.assertEqual(catalog.path, HOST)
        self.assertEqual(catalog.records, catalogs[HostTrustModelBackend].records)


class MixinCatalogResolveTest(SimpleTestCase):
    def test_unlisted_mixin_has_no_catalog(self):
        self.assertIsNone(MixinOnlyBackend().get_catalog())

    def test_unlisted_mixin_denies_and_duplicate_listing_is_one_catalog(self):
        from django.contrib.auth import get_user_model
        from django.db.models.query import QuerySet

        backend = MixinOnlyBackend()
        users = backend.get_permitted_users(object(), 'myapp.change_document')
        self.assertIsInstance(users, QuerySet)
        self.assertIs(users.model, get_user_model())
        held = backend.with_perm('myapp.change_document')
        self.assertIsInstance(held, QuerySet)
        self.assertIs(held.model, get_user_model())
        self.assertIsNone(
            backend.permitted_users_predicate(object(), 'myapp.change_document'),
        )
        self.assertEqual(backend.get_all_permissions(object(), None), set())
        self.assertEqual(backend.get_group_permissions(object(), None), set())
        host = configured_catalog(HOST)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, HOST, MIXIN)):
            found = configured_catalogs()
        self.assertEqual(found, (host,))

    def test_listed_host_catalog_path_is_the_settings_string(self):
        catalog = configured_catalog(HOST)
        self.assertEqual(catalog.path, HOST)
        self.assertIs(catalog, catalogs[HostTrustModelBackend])

    def test_same_class_under_two_paths_raises(self):
        with empty_catalogs():
            with override_settings(AUTHENTICATION_BACKENDS=(HOST, ALIASED)):
                with self.assertRaises(TrustsConfigurationError):
                    sweep_listed_backends()

    def test_live_host_is_the_kernel_suite_catalog(self):
        from django.conf import settings

        if HOST_BACKEND not in settings.AUTHENTICATION_BACKENDS:
            self.skipTest('kernel-only host path is not listed on the pair')
        catalog = configured_catalog(HOST_BACKEND)
        self.assertIs(catalog.cls, HostTrustModelBackend)
        self.assertIn(catalog, configured_catalogs())


@isolate_apps(
    'tests',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    attr_name='isolated_apps',
)
class IsolatedImplementationStoreTest(SimpleTestCase):
    def test_implementation_registry_does_not_touch_live_owner(self):
        before = catalogs[HostTrustModelBackend]
        before_records = before.records
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        config = live_config()
        config.ready()
        self.assertIs(catalogs[HostTrustModelBackend], before)
        self.assertEqual(before.records, before_records)
        self.assertFalse(hasattr(config, 'registries'))

    def test_isolate_apps_without_implementation_does_not_donate(self):
        live = catalogs[HostTrustModelBackend]
        before = live.records
        self.assertFalse(self.isolated_apps.is_installed('trusts'))
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertEqual(live.records, before)
