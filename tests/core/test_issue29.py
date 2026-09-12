"""#29: generic registration / check-ID / validation lifecycle.

Live Trust/Content runtime stay on Zero ``tests/legacy/test_issue29.py``.
Stage A raises invalid builders at registration; ``trusts.E001`` remains
a defense-in-depth scan of stored IR.
"""

from io import StringIO
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.checks import Error
from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.db import models
from django.test import SimpleTestCase
from django.test.utils import isolate_apps

from trusts.checks import (
    CHECK_ID_INVALID_EXPR,
    CHECK_ID_REMOVED_LEGACY_CALLBACK_SETTING,
    check_permission_conditions,
    permission_condition_check_messages,
)
from trusts.conditions import (
    ConditionRecord,
    PermissionConditionError,
    condition_refs,
)
from trusts.core import TrustsRegistry


def _note_model():
    User = get_user_model()

    class Note(models.Model):
        owner = models.ForeignKey(User, on_delete=models.CASCADE)
        status = models.CharField(max_length=20, default='open')
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    return Note


def _messages_with_id(messages, check_id):
    return [m for m in messages if m.id == check_id]


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class PermissionConditionCheckLifecycleTest(SimpleTestCase):
    def test_semantic_invalid_expr_raises_at_registration(self):
        Note = _note_model()
        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        with self.assertRaises(PermissionConditionError) as ctx:
            registry.register_permission_condition(
                Note, 'missing', u == o.not_a_field,
            )
        self.assertIn('not_a_field', str(ctx.exception))

    def test_injected_invalid_ir_is_still_e001(self):
        Note = _note_model()
        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        registry.conditions._records[(Note._meta.label, 'missing')] = (
            ConditionRecord(expr=u == o.not_a_field, model=Note)
        )
        errors = _messages_with_id(
            permission_condition_check_messages(
                registry.iter_permission_conditions(),
            ),
            CHECK_ID_INVALID_EXPR,
        )
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], Error)
        self.assertIn('not_a_field', errors[0].msg)

    def test_valid_registration_before_models_ready(self):
        from django.apps import apps

        Note = _note_model()
        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        expr = u == o.owner
        with patch.object(apps, 'models_ready', False):
            record = registry.register_permission_condition(
                Note, 'deferred_own', expr,
            )
        self.assertEqual(record.expr.to_tuple(), expr.to_tuple())
        self.assertEqual(
            _messages_with_id(
                permission_condition_check_messages(
                    registry.iter_permission_conditions(),
                ),
                CHECK_ID_INVALID_EXPR,
            ),
            [],
        )

    def test_multiple_dynamic_errors_are_aggregated(self):
        Note = _note_model()
        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        registry.conditions._records[(Note._meta.label, 'typo')] = (
            ConditionRecord(expr=u == o.nope, model=Note)
        )
        registry.conditions._records[(Note._meta.label, 'types')] = (
            ConditionRecord(expr=o.status == 1, model=Note)
        )
        errors = _messages_with_id(
            permission_condition_check_messages(
                registry.iter_permission_conditions(),
            ),
            CHECK_ID_INVALID_EXPR,
        )
        self.assertEqual(len(errors), 2)
        msgs = ' '.join(m.msg for m in errors)
        self.assertIn('typo', msgs)
        self.assertIn('types', msgs)

    def test_handle_check_and_ready_do_not_raise_on_injected_invalid_ir(self):
        Note = _note_model()
        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        registry.conditions._records[(Note._meta.label, 'typo')] = (
            ConditionRecord(expr=u == o.nope, model=Note)
        )

        class _Handle(object):
            def __init__(self, store):
                self.registry = store

        class _Config(object):
            def _configured_trusts_paths(self):
                return ('tests.backends.HostTrustModelBackend',)

            def configured_backend(self, path=None):
                return _Handle(registry)

            def ready(self):
                return None

        with patch(
            'trusts.apps.implementation_configs', return_value=(_Config(),),
        ):
            _Config().ready()
            errors = _messages_with_id(
                check_permission_conditions(None), CHECK_ID_INVALID_EXPR,
            )
        self.assertTrue(any("'typo'" in m.msg for m in errors))


class ManagePyCheckLifecycleTest(SimpleTestCase):
    def _output(self):
        out = StringIO()
        err = StringIO()
        call_command('check', stdout=out, stderr=err)
        return out.getvalue() + err.getvalue()

    def test_manage_py_check_passes_for_valid_library_suite(self):
        output = self._output()
        self.assertNotIn(CHECK_ID_INVALID_EXPR, output)
        self.assertNotIn(CHECK_ID_REMOVED_LEGACY_CALLBACK_SETTING, output)

    def test_manage_py_check_reports_invalid_registration_via_handle(self):
        from tests.myapp.models import Document

        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        registry.conditions._records[(Document._meta.label, 'typo-29')] = (
            ConditionRecord(expr=u == o.nope, model=Document)
        )

        class _Handle(object):
            def __init__(self, store):
                self.registry = store

        class _Config(object):
            def _configured_trusts_paths(self):
                return ('tests.backends.HostTrustModelBackend',)

            def configured_backend(self, path=None):
                return _Handle(registry)

        with patch(
            'trusts.apps.implementation_configs', return_value=(_Config(),),
        ):
            with self.assertRaises(SystemCheckError) as ctx:
                call_command('check')
        self.assertIn(CHECK_ID_INVALID_EXPR, str(ctx.exception))
        self.assertIn('typo-29', str(ctx.exception))
