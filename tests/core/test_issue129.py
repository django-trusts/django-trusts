"""#129: Core no longer ships unreachable Zero management commands."""

import importlib
import importlib.util
from pathlib import Path

from django.test import SimpleTestCase

ROOT = Path(__file__).resolve().parents[2]

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
        self.assertFalse((ROOT / 'scripts' / 'verify-legacy-upgrade.py').exists())
        self.assertFalse((ROOT / 'scripts' / 'legacy' / 'trusts_0001_sqlite.sql').exists())

    def test_removed_modules_are_not_importable(self):
        for name in REMOVED_MODULES:
            self.assertIsNone(importlib.util.find_spec(name), name)
            with self.assertRaises(ModuleNotFoundError):
                importlib.import_module(name)
