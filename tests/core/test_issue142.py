"""#142 Stage B: public construction imports fail; builders remain."""

from django.contrib.auth import get_user_model
from django.db import models
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from trusts.conditions import (
    PermissionConditionError,
    permission_condition_code,
    permission_has_condition,
)
from trusts.errors import TrustsConfigurationError
from tests.support import compiler


PUBLIC_SURFACE_NAMES = (
    'PermissionConditionError',
    'permission_condition_code',
    'permission_has_condition',
)

HIDDEN_PUBLIC_NAMES = (
    'Expr',
    'Const',
    'Eq',
    'Ne',
    'And',
    'Or',
    'Ref',
    'Query',
    'TQ',
    'condition_refs',
    'principal_ref',
    'permission_ref',
    'object_ref',
    'ConditionLookup',
    'ConditionRecord',
    'ConditionRegistry',
    'ModelIdentity',
    'RegistryConditionLookup',
    'compile_expression_q',
    'evaluate_registered_expression',
    'obsolete_legacy_callback_setting_enabled',
    'validate_expression',
)


class StageBPublicSurfaceTest(SimpleTestCase):
    def test_public_conditions_module_keeps_exceptions_and_helpers(self):
        import trusts.conditions as conditions_mod

        self.assertEqual(tuple(conditions_mod.__all__), PUBLIC_SURFACE_NAMES)
        self.assertTrue(
            issubclass(PermissionConditionError, TrustsConfigurationError),
        )
        for name in HIDDEN_PUBLIC_NAMES:
            self.assertNotIn(name, conditions_mod.__all__)
            self.assertFalse(hasattr(conditions_mod, name), name)
        self.assertTrue(permission_has_condition('change_note:own'))
        self.assertEqual(permission_condition_code('change_note:own'), 'own')


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class StageBRegisterCallableOnlyTest(SimpleTestCase):
    def test_registering_prebuilt_expr_raises_before_mutation(self):
        from trusts.plan.conditions import Eq, Ref

        User = get_user_model()

        class Note(models.Model):
            owner = models.ForeignKey(User, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        owned = Eq(Ref('principal', ()), Ref('object', ('owner',)))
        registry = compiler()
        with self.assertRaises(TypeError):
            registry.add_named_filter(Note, 'own', owned)
        self.assertIsNone(registry.conditions.get_permission_condition_record(Note, 'own'))
        record = registry.add_named_filter(
            Note, 'own', lambda u, p, o: u == o.owner,
        )
        self.assertIsNotNone(record)
        self.assertFalse(hasattr(record, 'func'))
