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

COMMAND_PATHS = (
    ROOT / 'trusts' / 'management',
    ROOT / 'trusts' / 'management' / 'commands',
    ROOT / 'trusts' / 'management' / 'commands' / 'create_trust_root.py',
    ROOT / 'trusts' / 'management' / 'commands' / 'grandfather_trust_group_permissions.py',
    ROOT / 'trusts' / 'management' / 'commands' / 'update_roles_permissions.py',
)


def _find_spec(name):
    try:
        return importlib.util.find_spec(name)
    except ModuleNotFoundError:
        return None


class ManagementCommandRemovalTest(SimpleTestCase):
    def test_checkout_has_no_management_package(self):
        for path in COMMAND_PATHS:
            self.assertFalse(path.exists(), path)

    def test_this_checkout_does_not_provide_command_modules(self):
        # ``trusts`` is a namespace package. Other checkouts on sys.path
        # may still expose historical command modules; only this tree is
        # under test. Wheel isolation is ``scripts/verify-wheel-install.py``.
        for name in COMMAND_MODULES:
            with self.subTest(name=name):
                spec = _find_spec(name)
                if spec is None or not spec.origin:
                    continue
                origin = Path(spec.origin).resolve()
                self.assertFalse(
                    ROOT == origin or ROOT in origin.parents,
                    '%s still ships from this checkout: %s' % (name, origin),
                )
