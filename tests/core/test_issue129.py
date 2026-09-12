"""#129: Core no longer ships unreachable Zero management commands."""

import importlib
import importlib.util
import sys
from pathlib import Path

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parents[2]
_SCRIPTS = ROOT / 'scripts'
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))
from management_archive import ships_trusts_management

REMOVED_MODULES = (
    'trusts.management',
    'trusts.management.commands',
    'trusts.management.commands.create_trust_root',
    'trusts.management.commands.grandfather_trust_group_permissions',
    'trusts.management.commands.update_roles_permissions',
)


class UnreachableManagementCommandsRemovedTest(SimpleTestCase):
    def test_source_tree_has_no_management_package(self):
        self.assertFalse((ROOT / 'trusts' / 'management').exists())

    def test_removed_modules_are_not_importable(self):
        for name in REMOVED_MODULES:
            try:
                spec = importlib.util.find_spec(name)
            except ModuleNotFoundError:
                spec = None
            self.assertIsNone(spec, name)
            with self.assertRaises(ModuleNotFoundError):
                importlib.import_module(name)


class ManagementArchiveMatcherTest(SimpleTestCase):
    def test_root_wheel_member_is_rejected(self):
        self.assertEqual(
            ships_trusts_management(['trusts/management/__init__.py']),
            ['trusts/management/__init__.py'],
        )
        self.assertEqual(
            ships_trusts_management(['trusts/management']),
            ['trusts/management'],
        )
        self.assertEqual(
            ships_trusts_management([
                'trusts/apps.py',
                './trusts/management/commands/create_trust_root.py',
            ]),
            ['./trusts/management/commands/create_trust_root.py'],
        )

    def test_prefixed_sdist_member_is_rejected(self):
        self.assertEqual(
            ships_trusts_management([
                'django_trusts-1.0.0.dev3/trusts/management/__init__.py',
            ]),
            ['django_trusts-1.0.0.dev3/trusts/management/__init__.py'],
        )
        self.assertEqual(
            ships_trusts_management([
                'django_trusts-1.0.0.dev3/trusts/management',
            ]),
            ['django_trusts-1.0.0.dev3/trusts/management'],
        )

    def test_unrelated_paths_are_kept(self):
        self.assertEqual(
            ships_trusts_management([
                'trusts/models.py',
                'trusts/management_notes.py',
                'django_trusts-1.0.0.dev3/trusts/apps.py',
                'scripts/verify-legacy-upgrade.py',
            ]),
            [],
        )

