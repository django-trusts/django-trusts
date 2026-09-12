"""Issue #129: Core no longer ships unreachable management commands."""

import importlib.util
from pathlib import Path

from django.test import SimpleTestCase


ROOT = Path(__file__).resolve().parents[2]

COMMAND_MODULES = (
    'trusts.management',
    'trusts.management.commands',
    'trusts.management.commands.create_trust_root',
    'trusts.management.commands.grandfather_trust_group_permissions',
    'trusts.management.commands.update_roles_permissions',
)


def _find_spec(name):
    try:
        return importlib.util.find_spec(name)
    except ModuleNotFoundError:
        return None


class ManagementCommandRemovalTest(SimpleTestCase):
    def test_checkout_has_no_management_package(self):
        self.assertFalse((ROOT / 'trusts' / 'management').exists())

    def test_importable_specs_are_absent(self):
        for name in COMMAND_MODULES:
            with self.subTest(name=name):
                self.assertIsNone(_find_spec(name))
