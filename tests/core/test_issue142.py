"""#142 Stage B: the public condition error and code helpers."""

from django.test import SimpleTestCase

from trusts.conditions import (
    PermissionConditionError,
    permission_condition_code,
    permission_has_condition,
)
from trusts.errors import TrustsConfigurationError


class StageBPublicSurfaceTest(SimpleTestCase):
    def test_public_conditions_module_keeps_exceptions_and_helpers(self):
        self.assertTrue(
            issubclass(PermissionConditionError, TrustsConfigurationError),
        )
        self.assertTrue(permission_has_condition('change_note:own'))
        self.assertEqual(permission_condition_code('change_note:own'), 'own')
