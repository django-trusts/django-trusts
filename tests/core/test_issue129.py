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

    def test_removed_modules_are_not_importable(self):
        for name in REMOVED_MODULES:
            try:
                spec = importlib.util.find_spec(name)
            except ModuleNotFoundError:
                spec = None
            self.assertIsNone(spec, name)
            with self.assertRaises(ModuleNotFoundError):
                importlib.import_module(name)
