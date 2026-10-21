"""#142 Stage B: the public condition error and permission-code parse."""

from django.test import SimpleTestCase

from trusts.errors import PermissionConditionError, TrustsConfigurationError
from trusts.utils import parse_perm_code


class StageBPublicSurfaceTest(SimpleTestCase):
    def test_parse_perm_code_splits_the_condition_suffix(self):
        self.assertTrue(
            issubclass(PermissionConditionError, TrustsConfigurationError),
        )
        self.assertEqual(
            parse_perm_code('myapp.change_note:own'),
            ('myapp', 'note', 'change', 'own'),
        )
        self.assertEqual(parse_perm_code('myapp.change_note')[3], '')
