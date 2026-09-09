"""Kernel / Zero package split (#43 Step 3).

Kernel owns ``trusts/__init__.py`` and a distinct AppConfig label.
Historical migrations stay ``('trusts', '0001_initial')`` /
``('trusts', '0002_trustgroup')`` on Zero. Does not close #43.
"""

import inspect
from pathlib import Path

from django.apps import apps
from django.db import connection
from django.db.migrations.loader import MigrationLoader
from django.test import SimpleTestCase, TestCase

import trusts
from trusts.apps import KernelConfig
from trusts.zero.apps import ZeroConfig
from trusts.zero.models import Trust


class KernelZeroSplitTest(TestCase):
    def test_explicit_appconfigs(self):
        kernel = apps.get_app_config('trusts_kernel')
        zero = apps.get_app_config('trusts')
        self.assertEqual(kernel.name, 'trusts')
        self.assertEqual(kernel.label, 'trusts_kernel')
        self.assertIs(kernel.__class__, KernelConfig)
        self.assertFalse(KernelConfig.default)
        self.assertEqual(zero.name, 'trusts.zero')
        self.assertEqual(zero.label, 'trusts')
        self.assertIs(zero.__class__, ZeroConfig)
        self.assertEqual(zero.default_auto_field, 'django.db.models.AutoField')
        self.assertIsNone(kernel.models_module)

    def test_kernel_init_has_no_zero_constants(self):
        self.assertFalse(hasattr(trusts, 'ENTITY_MODEL_NAME'))
        self.assertFalse(hasattr(trusts, 'GROUP_MODEL_NAME'))
        self.assertFalse(hasattr(trusts, 'PERMISSION_MODEL_NAME'))
        self.assertFalse(hasattr(trusts, 'ROOT_PK'))
        self.assertFalse(hasattr(trusts, 'DEFAULT_SETTLOR'))
        self.assertFalse(hasattr(trusts, 'get_entity_model'))
        source = Path(inspect.getfile(trusts)).read_text()
        self.assertIn('extend_path', source)
        self.assertNotIn('ENTITY_MODEL_NAME', source)

    def test_kernel_checkout_has_no_zero_tree(self):
        kernel_dir = Path(inspect.getfile(trusts)).resolve().parent
        self.assertFalse((kernel_dir / 'zero').exists())
        self.assertFalse((kernel_dir / 'migrations').exists())
        repo_root = Path(__file__).resolve().parents[2]
        self.assertFalse((repo_root / 'trusts' / 'zero').exists())
        self.assertFalse((repo_root / 'packaging' / 'django-trusts-zero').exists())
        zero_migrations = Path(inspect.getfile(Trust)).resolve().parent / 'migrations'
        names = sorted(
            path.name for path in zero_migrations.glob('*.py')
            if path.name != '__init__.py'
        )
        self.assertEqual(names, ['0001_initial.py', '0002_trustgroup.py'])

    def test_historical_migration_identity(self):
        loader = MigrationLoader(connection)
        self.assertIn(('trusts', '0001_initial'), loader.disk_migrations)
        self.assertIn(('trusts', '0002_trustgroup'), loader.disk_migrations)
        self.assertEqual(
            loader.disk_migrations[('trusts', '0001_initial')].__module__,
            'trusts.zero.migrations.0001_initial',
        )
        self.assertEqual(
            loader.disk_migrations[('trusts', '0002_trustgroup')].__module__,
            'trusts.zero.migrations.0002_trustgroup',
        )
        self.assertEqual(
            {name for app, name in loader.applied_migrations if app == 'trusts'},
            {'0001_initial', '0002_trustgroup'},
        )
        self.assertNotIn(('trusts_kernel', '0001_initial'), loader.disk_migrations)


class KernelWheelAbsenceCheckTest(SimpleTestCase):
    def test_kernel_wheel_verifier_lists_zero_as_absent(self):
        from tests.core.test_wheel_install import _load_verifier

        verifier = _load_verifier()
        self.assertIn('trusts.zero', verifier.ABSENT_ZERO_MODULES)
