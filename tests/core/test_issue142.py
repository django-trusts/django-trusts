"""#142 Stage B: public construction imports fail; builders remain."""

from django.contrib.auth import get_user_model
from django.db import models
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from trusts.conditions import (
    PermissionConditionBooleanError,
    PermissionConditionError,
    PermissionConditionNotQueryable,
    PermissionConditionUnsupported,
    permission_condition_code,
    permission_has_condition,
)
from trusts.core import TrustsRegistry


PUBLIC_SURFACE_NAMES = (
    'PermissionConditionBooleanError',
    'PermissionConditionError',
    'PermissionConditionNotQueryable',
    'PermissionConditionUnsupported',
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
        self.assertTrue(issubclass(PermissionConditionBooleanError, PermissionConditionError))
        self.assertTrue(issubclass(PermissionConditionUnsupported, PermissionConditionError))
        self.assertTrue(issubclass(PermissionConditionNotQueryable, ValueError))
        self.assertTrue(permission_has_condition('change_note:own'))
        self.assertEqual(permission_condition_code('change_note:own'), 'own')

    def test_former_public_construction_imports_fail(self):
        import django_trusts
        import trusts.conditions as conditions_mod

        for name in HIDDEN_PUBLIC_NAMES:
            self.assertFalse(hasattr(conditions_mod, name), name)
            self.assertNotIn(name, conditions_mod.__all__)
            self.assertFalse(hasattr(django_trusts, name), name)

        with self.assertRaises(ImportError):
            from trusts.conditions import Expr  # noqa: F401
        with self.assertRaises(ImportError):
            from trusts.conditions import condition_refs  # noqa: F401
        with self.assertRaises(ImportError):
            from trusts.conditions import ConditionRegistry  # noqa: F401
        with self.assertRaises(ImportError):
            from trusts.conditions import validate_expression  # noqa: F401
        with self.assertRaises(ImportError):
            from django_trusts import TQ  # noqa: F401
        with self.assertRaises(ImportError):
            from django_trusts import condition_refs  # noqa: F401

    def test_private_ir_remains_importable_for_compiler_tests(self):
        from trusts.conditions._ir import Expr, TQ, condition_refs

        u, _p, o = condition_refs()
        self.assertIsInstance(u == o.owner, Expr)
        with self.assertRaises(PermissionConditionUnsupported):
            TQ.contains


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class StageBRegisterCallableOnlyTest(SimpleTestCase):
    def test_registering_prebuilt_expr_raises_before_mutation(self):
        from trusts.conditions._ir import condition_refs

        User = get_user_model()

        class Note(models.Model):
            owner = models.ForeignKey(User, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        with self.assertRaises(TypeError):
            registry.register_permission_condition(Note, 'own', u == o.owner)
        self.assertIsNone(registry.get_permission_condition_record(Note, 'own'))
        record = registry.register_permission_condition(
            Note, 'own', lambda u, p, o: u == o.owner,
        )
        self.assertIsNotNone(record)
        self.assertFalse(hasattr(record, 'func'))
