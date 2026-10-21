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
