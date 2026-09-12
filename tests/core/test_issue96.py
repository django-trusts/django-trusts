"""#96 / #111: library identity after the library cutover.

Kernel-only proofs: core is absent from INSTALLED_APPS, no concrete
models or migrations, inert ``trusts.models`` does not import Zero,
historical model imports fail, GH stub populates without Zero.
``kernel_config()`` and a core AppConfig are gone.
"""

import sys
from importlib import import_module

from django.apps import apps
from django.db import connection
from django.db.migrations.loader import MigrationLoader
from django.test import SimpleTestCase, TestCase

from tests.gh_permissions.models import Repository


class KernelIdentityTest(SimpleTestCase):
    def test_core_is_not_an_installed_app(self):
        import trusts.apps as apps_mod

        self.assertFalse(hasattr(apps_mod, 'AppConfig'))
        self.assertFalse(hasattr(apps_mod, 'kernel_config'))
        labels = {config.label for config in apps.get_app_configs()}
        names = {config.name for config in apps.get_app_configs()}
        self.assertNotIn('trusts', labels)
        self.assertNotIn('trusts_core', labels)
        self.assertNotIn('trusts', names)
        with self.assertRaises(LookupError):
            apps.get_app_config('trusts')
        with self.assertRaises(LookupError):
            apps.get_app_config('trusts_core')

    def test_kernel_exposes_no_concrete_models(self):
        trusts = [m for m in apps.get_models() if m.__name__ == 'Trust']
        self.assertEqual(trusts, [])


class KernelMigrationLoaderTest(TestCase):
    def test_kernel_has_no_trusts_migration_keys(self):
        loader = MigrationLoader(connection)
        keys = {key for key in loader.disk_migrations if key[0] == 'trusts'}
        self.assertEqual(keys, set())
        core_keys = {
            key for key in loader.disk_migrations if key[0] == 'trusts_core'
        }
        self.assertEqual(core_keys, set())


class ModelsShimTest(SimpleTestCase):
    def test_import_models_does_not_import_zero(self):
        self.assertNotIn('trusts.zero', sys.modules)
        module = import_module('trusts.models')
        self.assertIs(sys.modules['trusts.models'], module)
        self.assertNotIn('trusts.zero', sys.modules)
        self.assertNotIn('Trust', module.__dict__)

    def test_legacy_trust_import_fails_without_forwarding(self):
        self.assertNotIn('trusts.zero', sys.modules)
        with self.assertRaises((ImportError, AttributeError)):
            from trusts.models import Trust  # noqa: F401
        self.assertNotIn('trusts.zero', sys.modules)

    def test_dir_hasattr_and_unknown_name_do_not_import_zero(self):
        self.assertNotIn('trusts.zero', sys.modules)
        module = import_module('trusts.models')
        names = dir(module)
        self.assertNotIn('Trust', names)
        self.assertNotIn('Content', names)
        self.assertNotIn('trusts.zero', sys.modules)
        self.assertFalse(hasattr(module, 'anything'))
        self.assertFalse(hasattr(module, 'NotALegacyModel'))
        self.assertNotIn('trusts.zero', sys.modules)
        with self.assertRaises(AttributeError) as ctx:
            getattr(module, 'NotALegacyModel')
        self.assertIn('NotALegacyModel', str(ctx.exception))
        self.assertNotIn('ImportError', type(ctx.exception).__name__)
        self.assertNotIn('trusts.zero', sys.modules)


class GhStubWithoutZeroTest(SimpleTestCase):
    def test_gh_repository_loads_and_zero_stays_unimported(self):
        self.assertNotIn('trusts.zero', sys.modules)
        self.assertEqual(Repository._meta.app_label, 'gh_permissions')
        self.assertIs(
            apps.get_model('gh_permissions', 'Repository'),
            Repository,
        )
        self.assertTrue(apps.is_installed('tests.gh_permissions'))
        self.assertNotIn('trusts.zero', sys.modules)
        self.assertFalse(apps.is_installed('trusts'))
