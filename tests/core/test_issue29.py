"""#29 / #142 Stage B: registration / check-ID / builder lifecycle.

Live Trust/Content runtime stay on Zero ``tests/legacy/test_issue29.py``.
This module proves library check IDs, builder-once registration, and
the obsolete-setting fail-loud check.
"""

from io import StringIO

from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.db import models
from django.test import SimpleTestCase, override_settings
from django.test.utils import isolate_apps

from trusts.inspect.checks import (
    CHECK_ID_OBSOLETE_CALLBACK_SETTING,
    check_obsolete_legacy_callback_setting,
)
from trusts.errors import PermissionConditionError
from trusts.plan.conditions import obsolete_legacy_callback_setting_enabled
from trusts.plan.grammar import Tree

from tests.support import compiler


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


class _BuilderLog(object):
    def __init__(self, impl=None):
        self.impl = impl or (lambda u, p, o: u == o.owner)
        self.calls = []

    def __call__(self, u, p, o):
        self.calls.append((u, p, o))
        return self.impl(u, p, o)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class PermissionConditionCheckLifecycleTest(SimpleTestCase):
    def test_prebuilt_expr_is_type_error_before_mutation(self):
        Note = _note_model()
        registry = compiler()
        expr = Tree(
            'eq',
            left=Tree('field', root='user', path=()),
            right=Tree('field', root='object', path=('not_a_field',)),
        )
        with self.assertRaises(TypeError):
            registry.add_named_filter(Note, 'missing', expr)
        registry.add_named_filter(Note, 'missing', lambda u, p, o: u == o.owner)

    def test_builder_validates_at_register_when_models_are_ready(self):
        Note = _note_model()
        registry = compiler()
        registry.add_named_filter(
            Note, 'deferred_own', lambda u, p, o: u == o.owner,
        )
        fresh = compiler()
        with self.assertRaises(PermissionConditionError) as ctx:
            fresh.add_named_filter(
                Note, 'deferred_bad', lambda u, p, o: u == o.deferred_missing,
            )
        self.assertIn('deferred_missing', str(ctx.exception))
        fresh.add_named_filter(
            Note, 'deferred_bad', lambda u, p, o: u == o.owner,
        )

    def test_builder_is_invoked_once_with_symbolic_refs(self):
        Note = _note_model()
        log = _BuilderLog()
        registry = compiler()
        registry.add_named_filter(Note, 'spy', log)
        self.assertEqual(len(log.calls), 1)
        self.assertEqual(check_obsolete_legacy_callback_setting(None), [])
        self.assertEqual(len(log.calls), 1)

    def test_builder_exception_and_non_predicate_fail_at_register(self):
        Note = _note_model()
        registry = compiler()

        def exploding(u, p, o):
            raise RuntimeError('builder boom')

        with self.assertRaises(PermissionConditionError) as boom:
            registry.add_named_filter(Note, 'boom', exploding)
        self.assertIn('builder boom', str(boom.exception))
        registry.add_named_filter(Note, 'boom', lambda u, p, o: u == o.owner)

        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(
                Note, 'truth', lambda u, p, o: True,
            )
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(
                Note, 'bare', lambda u, p, o: o.owner,
            )

    def test_obsolete_setting_is_check_error_not_callback_opt_in(self):
        self.assertFalse(obsolete_legacy_callback_setting_enabled())
        self.assertEqual(check_obsolete_legacy_callback_setting(None), [])
        with override_settings(TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS=True):
            errors = _messages_with_id(
                check_obsolete_legacy_callback_setting(None),
                CHECK_ID_OBSOLETE_CALLBACK_SETTING,
            )
        self.assertEqual(len(errors), 1)
        self.assertIn('does not enable', errors[0].msg)

class ManagePyCheckLifecycleTest(SimpleTestCase):
    def _output(self):
        out = StringIO()
        err = StringIO()
        call_command('check', stdout=out, stderr=err)
        return out.getvalue() + err.getvalue()

    def test_manage_py_check_passes_for_valid_library_suite(self):
        output = self._output()
        self.assertNotIn(CHECK_ID_OBSOLETE_CALLBACK_SETTING, output)

    @override_settings(TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS=True)
    def test_manage_py_check_reports_obsolete_callback_setting(self):
        with self.assertRaises(SystemCheckError) as ctx:
            call_command('check')
        self.assertIn(CHECK_ID_OBSOLETE_CALLBACK_SETTING, str(ctx.exception))
        self.assertIn('does not enable', str(ctx.exception))
