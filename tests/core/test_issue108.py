"""#108 / #111: each app config owns its catalog.

Core ships no ``kernel_config()``. Mixin identity stays.
Historical core backend is gone. A backend outside a
``TrustsConfigMixin`` app is ``trusts.E012``.
"""

from django.apps import apps
from django.core.checks import run_checks
from django.test import SimpleTestCase, override_settings
from django.test.utils import isolate_apps

import tests as tests_module
from tests.apps import TestsConfig
from tests.core import KernelHostRequiredMixin, kernel_host_listed
from tests.kernel_host.apps import HOST_BACKEND
from tests.kernel_host.backends import HostTrustModelBackend
from tests.support import configured_catalog, sweep_listed_backends
from trusts.apps import TrustsConfigMixin, installed_catalogs
from trusts.models import PermittedUsersManagerMixin


HOST = 'tests.kernel_host.backends.HostTrustModelBackend'
OUTSIDE = 'tests.gh_permissions.backends.OutsideBackend'


class ImplementationRoutingTest(KernelHostRequiredMixin, SimpleTestCase):
    def test_exact_path_routing_is_the_owning_config(self):
        host = configured_catalog(HOST)
        owner = apps.get_app_config('trusts_kernel_host')
        self.assertEqual(host.path, owner.catalog_path())
        self.assertIs(host, HostTrustModelBackend().catalog)
        self.assertEqual(host.family, 'relationship')

    def test_backend_outside_a_mixin_app_fails_loud(self):
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, OUTSIDE)):
            messages = [
                message for message in run_checks()
                if getattr(message, 'id', None) == 'trusts.E012'
            ]
        self.assertEqual(
            [message.obj.label for message in messages],
            ['gh_permissions'],
        )


class ImplementationReadyTest(KernelHostRequiredMixin, SimpleTestCase):
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
        if not kernel_host_listed():
            self.skipTest('kernel-only host path is not listed on the pair')
        with override_settings(AUTHENTICATION_BACKENDS=(HOST, OUTSIDE, OUTSIDE)):
            messages = [
                message for message in run_checks()
                if getattr(message, 'id', None) == 'trusts.E012'
            ]
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].obj.label, 'gh_permissions')

    def test_installed_catalogs_follow_apps_not_backend_duplicates(self):
        from django.contrib.auth import get_user_model
        from django.db.models.query import QuerySet

        from tests.backends import MixinOnlyBackend

        backend = MixinOnlyBackend()
        self.assertIs(
            backend.get_catalog(),
            apps.get_app_config('trusts_tests').get_catalog(),
        )
        User = get_user_model()

        class GrantUsers(PermittedUsersManagerMixin, User._default_manager.__class__):
            pass

        manager = GrantUsers()
        manager.model = User
        held = manager.with_perm('myapp.change_document')
        self.assertIsInstance(held, QuerySet)
        self.assertIs(held.model, User)
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
        if not kernel_host_listed():
            self.skipTest('kernel-only host path is not listed on the pair')
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
        if not kernel_host_listed():
            self.skipTest('kernel-only host path is not listed on the pair')
        before = HostTrustModelBackend().catalog
        before_records = before.records
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        config = apps.get_app_config('trusts_kernel_host')
        config.ready()
        rebuilt = HostTrustModelBackend().catalog
        self.assertEqual(rebuilt.records, before_records)
        self.assertEqual(rebuilt.path, before.path)
        self.assertIsNot(rebuilt, before)
        self.assertFalse(hasattr(config, 'registries'))

    def test_isolate_apps_without_implementation_does_not_donate(self):
        live = HostTrustModelBackend().catalog
        before = live.records
        self.assertFalse(self.isolated_apps.is_installed('trusts'))
        contributor = TestsConfig('tests', tests_module)
        contributor.apps = self.isolated_apps
        contributor.ready()
        self.assertEqual(live.records, before)
