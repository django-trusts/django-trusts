"""#108 / #111: each app config owns its catalog.

Core ships no ``kernel_config()``. Mixin identity stays.
Historical core backend is gone. A backend outside a
``TrustsConfigMixin`` app fails at construction.
"""

from django.apps import AppConfig as DjangoAppConfig
from django.apps import apps
from django.test import SimpleTestCase, override_settings
from django.test.utils import isolate_apps

import tests as tests_module
from tests.apps import TestsConfig
from tests.gh_permissions.backends import OutsideBackend
from tests.kernel_host.apps import HOST_BACKEND
from tests.kernel_host.backends import HostTrustModelBackend
from tests.support import configured_catalog, sweep_listed_backends, compiler
from trusts.apps import TrustsConfigMixin, installed_catalogs
from trusts.backends import TrustModelBackendMixin
from trusts.compile.factory import Compiler
from trusts.compile.nodes import Ref
from trusts.decorators import filter_by_permitted_content
from trusts.errors import TrustsConfigurationError
from trusts.models import AuthorizedManager, AuthorizedQuerySet


HOST = 'tests.kernel_host.backends.HostTrustModelBackend'
OUTSIDE = 'tests.gh_permissions.backends.OutsideBackend'


class ImplementationHelperSurfaceTest(SimpleTestCase):
    def test_core_is_not_an_implementation_appconfig(self):
        import trusts.apps as apps_mod

        host = apps.get_app_config('trusts_kernel_host')
        self.assertFalse(hasattr(apps_mod, 'AppConfig'))
        self.assertFalse(hasattr(apps_mod, 'kernel_config'))
        self.assertFalse(hasattr(apps_mod, 'TrustsImplementationConfig'))
        self.assertIsInstance(host, TrustsConfigMixin)
        self.assertIsNot(type(host), TrustsConfigMixin)

    def test_helper_and_resolvers_import(self):
        import trusts.apps as apps_mod

        self.assertTrue(issubclass(TrustsConfigMixin, DjangoAppConfig))
        self.assertFalse(hasattr(apps_mod, 'implementation_for_path'))
        self.assertFalse(hasattr(apps_mod, 'implementation_for_class'))
        self.assertFalse(hasattr(apps_mod, 'implementation_configs'))
        self.assertFalse(hasattr(apps_mod, 'relationship_registries'))
        self.assertFalse(hasattr(TrustsConfigMixin, 'trusts_backend_paths'))
        self.assertFalse(hasattr(TrustsConfigMixin, '_authorization_family'))

    def test_mixin_lives_only_on_trusts_backends(self):
        self.assertEqual(
            TrustModelBackendMixin.__module__, 'trusts.backends',
        )

    def test_historical_backend_no_longer_imports(self):
        import trusts.backends as backends_mod

        self.assertFalse(hasattr(backends_mod, 'TrustModelBackend'))
        self.assertFalse(hasattr(backends_mod, 'HistoricalGroupQueryCompiler'))
        self.assertFalse(hasattr(backends_mod, 'catalogs'))
        self.assertFalse(hasattr(backends_mod, 'configured_catalogs'))

    def test_generic_declarations_import_without_kernel_config(self):
        import trusts.apps as apps_mod

        self.assertFalse(hasattr(apps_mod, 'kernel_config'))
        self.assertTrue(callable(filter_by_permitted_content))
        self.assertTrue(issubclass(AuthorizedQuerySet, object))
        self.assertTrue(issubclass(AuthorizedManager, object))
        registry = compiler()
        self.assertEqual(registry.records, ())
        self.assertIsNotNone(Ref)


class ImplementationRoutingTest(SimpleTestCase):
    def test_exact_path_routing_is_the_owning_config(self):
        host = configured_catalog(HOST)
        owner = apps.get_app_config('trusts_kernel_host')
        self.assertEqual(host.path, owner.catalog_path())
        self.assertIs(host, HostTrustModelBackend().catalog)
        self.assertEqual(host.family, 'relationship')

    def test_backend_outside_a_mixin_app_fails_loud(self):
        with self.assertRaises(TrustsConfigurationError) as ctx:
            OutsideBackend()
        self.assertIn(OUTSIDE, str(ctx.exception))
        self.assertIn('TrustsConfigMixin', str(ctx.exception))


class ImplementationReadyTest(SimpleTestCase):
    def test_empty_authentication_backends_still_build_installed_configs(self):
        before = [catalog.path for catalog in installed_catalogs()]
        with override_settings(AUTHENTICATION_BACKENDS=()):
            sweep_listed_backends()
        self.assertEqual(
            [catalog.path for catalog in installed_catalogs()],
            before,
        )
        self.assertIn(
            apps.get_app_config('trusts_kernel_host').catalog_path(),
            before,
        )

    def test_duplicate_backend_listing_does_not_add_a_catalog(self):
        before = installed_catalogs()
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, HOST)):
            sweep_listed_backends()
        after = installed_catalogs()
        self.assertEqual(
            [catalog.path for catalog in after],
            [catalog.path for catalog in before],
        )

    def test_second_ready_does_not_replace_catalogs(self):
        config = apps.get_app_config('trusts_kernel_host')
        before = HostTrustModelBackend().catalog
        config.ready()
        config.ready()
        rebuilt = HostTrustModelBackend().catalog
        self.assertEqual(rebuilt.records, before.records)
        self.assertEqual(rebuilt.path, before.path)
        self.assertFalse(hasattr(config, 'registries'))
        self.assertFalse(hasattr(config, 'trusts_backend_paths'))

    def test_listed_path_is_the_config_label(self):
        catalog = configured_catalog(HOST)
        owner = apps.get_app_config('trusts_kernel_host')
        self.assertIs(catalog, HostTrustModelBackend().catalog)
        self.assertEqual(catalog.path, owner.catalog_path())
        self.assertEqual(catalog.records, HostTrustModelBackend().catalog.records)


class MixinCatalogResolveTest(SimpleTestCase):
    def test_outside_backend_is_not_constructed(self):
        with self.assertRaises(TrustsConfigurationError) as ctx:
            OutsideBackend()
        self.assertIn('TrustsConfigMixin', str(ctx.exception))

    def test_installed_catalogs_follow_apps_not_backend_duplicates(self):
        from django.contrib.auth import get_user_model
        from django.db.models.query import QuerySet

        from tests.backends import MixinOnlyBackend

        backend = MixinOnlyBackend()
        self.assertIs(
            backend.get_catalog(),
            apps.get_app_config('trusts_tests').get_catalog(),
        )
        held = backend.with_perm('myapp.change_document')
        self.assertIsInstance(held, QuerySet)
        self.assertIs(held.model, get_user_model())
        self.assertEqual(backend.get_all_permissions(object(), None), set())
        self.assertEqual(backend.get_group_permissions(object(), None), set())
        host = configured_catalog(HOST)
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, HOST)):
            found = installed_catalogs()
        self.assertIn(host, found)
        self.assertEqual(
            len(found),
            len([
                config for config in apps.get_app_configs()
                if isinstance(config, TrustsConfigMixin)
            ]),
        )

    def test_listed_host_catalog_path_is_the_config_class(self):
        catalog = configured_catalog(HOST)
        self.assertEqual(
            catalog.path,
            apps.get_app_config('trusts_kernel_host').catalog_path(),
        )
        self.assertIs(catalog, HostTrustModelBackend().catalog)

    def test_live_host_is_the_kernel_suite_catalog(self):
        from django.conf import settings

        if HOST_BACKEND not in settings.AUTHENTICATION_BACKENDS:
            self.skipTest('kernel-only host path is not listed on the pair')
        catalog = configured_catalog(HOST_BACKEND)
        self.assertIs(catalog, HostTrustModelBackend().catalog)
        self.assertIn(catalog, installed_catalogs())


@isolate_apps(
    'tests',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    attr_name='isolated_apps',
)
class IsolatedImplementationStoreTest(SimpleTestCase):
    def test_implementation_registry_does_not_touch_live_owner(self):
        before = HostTrustModelBackend().catalog
        before_records = before.records
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        config = apps.get_app_config('trusts_kernel_host')
        config.ready()
        self.assertIs(HostTrustModelBackend().catalog, before)
        self.assertEqual(before.records, before_records)
        self.assertFalse(hasattr(config, 'registries'))

    def test_isolate_apps_without_implementation_does_not_donate(self):
        live = HostTrustModelBackend().catalog
        before = live.records
        self.assertFalse(self.isolated_apps.is_installed('trusts'))
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertEqual(live.records, before)
