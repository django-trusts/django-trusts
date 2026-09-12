"""#29 / #142 Stage A: registration / check-ID / builder lifecycle.

Live Trust/Content runtime stay on Zero ``tests/legacy/test_issue29.py``.
This module proves library check IDs, builder-once registration, and
the obsolete-setting fail-loud check.
"""

from io import StringIO
from unittest.mock import patch

from django.apps import apps
from django.contrib.auth import get_user_model
from django.core.checks import Error
from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.db import models
from django.test import SimpleTestCase, override_settings
from django.test.utils import isolate_apps

from trusts.checks import (
    CHECK_ID_INVALID_EXPR,
    CHECK_ID_LEGACY_CALLBACK,
    check_obsolete_legacy_callback_setting,
    check_permission_conditions,
    permission_condition_check_messages,
)
from trusts.conditions import (
    PermissionConditionError,
    Ref,
    condition_refs,
    obsolete_legacy_callback_setting_enabled,
)
from trusts.core import TrustsConfigurationError, TrustsRegistry


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
    def test_semantic_invalid_expr_does_not_raise_at_registration(self):
        Note = _note_model()
        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        expr = u == o.not_a_field
        record = registry.register_permission_condition(Note, 'missing', expr)
        self.assertIs(record.expr, expr)
        self.assertIs(record.model, Note)
        errors = _messages_with_id(
            permission_condition_check_messages(
                registry.iter_permission_conditions(),
            ),
            CHECK_ID_INVALID_EXPR,
        )
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], Error)
        self.assertIn('not_a_field', errors[0].msg)

    def test_registration_before_models_ready_retains_expr_identity(self):
        Note = _note_model()
        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        expr = u == o.owner
        with patch.object(apps, 'models_ready', False):
            record = registry.register_permission_condition(
                Note, 'deferred_own', expr,
            )
        self.assertIs(record.expr, expr)
        self.assertIs(record.model, Note)
        self.assertEqual(
            _messages_with_id(
                permission_condition_check_messages(
                    registry.iter_permission_conditions(),
                ),
                CHECK_ID_INVALID_EXPR,
            ),
            [],
        )
        bad = u == o.deferred_missing
        with patch.object(apps, 'models_ready', False):
            registry.register_permission_condition(Note, 'deferred_bad', bad)
        errors = _messages_with_id(
            permission_condition_check_messages(
                registry.iter_permission_conditions(),
            ),
            CHECK_ID_INVALID_EXPR,
        )
        self.assertTrue(any('deferred_missing' in m.msg for m in errors))
        self.assertTrue(any("'deferred_bad'" in m.msg for m in errors))

    def test_multiple_dynamic_errors_are_aggregated(self):
        Note = _note_model()
        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        registry.register_permission_condition(Note, 'typo', u == o.nope)
        registry.register_permission_condition(Note, 'types', o.status == 1)
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

    def test_builder_is_invoked_once_with_symbolic_refs(self):
        Note = _note_model()
        log = _BuilderLog()
        registry = TrustsRegistry()
        record = registry.register_permission_condition(Note, 'spy', log)
        self.assertEqual(len(log.calls), 1)
        u, p, o = log.calls[0]
        self.assertIsInstance(u, Ref)
        self.assertIsInstance(p, Ref)
        self.assertIsInstance(o, Ref)
        self.assertEqual(u.source, 'principal')
        self.assertEqual(o.source, 'object')
        self.assertFalse(hasattr(record, 'func'))
        messages = permission_condition_check_messages(
            registry.iter_permission_conditions(),
        )
        self.assertEqual(len(log.calls), 1)
        self.assertEqual(_messages_with_id(messages, CHECK_ID_LEGACY_CALLBACK), [])

    def test_builder_exception_and_non_predicate_fail_at_register(self):
        Note = _note_model()
        registry = TrustsRegistry()

        def exploding(u, p, o):
            raise RuntimeError('builder boom')

        with self.assertRaises(PermissionConditionError) as boom:
            registry.register_permission_condition(Note, 'boom', exploding)
        self.assertIn('builder boom', str(boom.exception))
        self.assertIsNone(registry.get_permission_condition_record(Note, 'boom'))

        with self.assertRaises(PermissionConditionError):
            registry.register_permission_condition(
                Note, 'truth', lambda u, p, o: True,
            )
        with self.assertRaises(PermissionConditionError):
            registry.register_permission_condition(
                Note, 'bare', lambda u, p, o: o.owner,
            )

    def test_obsolete_setting_is_check_error_not_callback_opt_in(self):
        self.assertFalse(obsolete_legacy_callback_setting_enabled())
        self.assertEqual(check_obsolete_legacy_callback_setting(None), [])
        with override_settings(TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS=True):
            errors = _messages_with_id(
                check_obsolete_legacy_callback_setting(None),
                CHECK_ID_LEGACY_CALLBACK,
            )
        self.assertEqual(len(errors), 1)
        self.assertIn('does not enable', errors[0].msg)

    def test_handle_check_and_ready_do_not_raise_on_invalid_expr(self):
        Note = _note_model()
        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        registry.register_permission_condition(Note, 'typo', u == o.nope)

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

    def test_frozen_handle_does_not_invoke_builder(self):
        Note = _note_model()
        registry = TrustsRegistry()
        registry.freeze()
        log = _BuilderLog()
        with self.assertRaises(TrustsConfigurationError):
            registry.register_permission_condition(Note, 'own', log)
        self.assertEqual(log.calls, [])


class ManagePyCheckLifecycleTest(SimpleTestCase):
    def _output(self):
        out = StringIO()
        err = StringIO()
        call_command('check', stdout=out, stderr=err)
        return out.getvalue() + err.getvalue()

    def test_manage_py_check_passes_for_valid_library_suite(self):
        output = self._output()
        self.assertNotIn(CHECK_ID_INVALID_EXPR, output)
        self.assertNotIn(CHECK_ID_LEGACY_CALLBACK, output)

    def test_manage_py_check_reports_invalid_registration_via_handle(self):
        from tests.myapp.models import Document

        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        registry.register_permission_condition(Document, 'typo-29', u == o.nope)

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

    @override_settings(TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS=True)
    def test_manage_py_check_reports_obsolete_callback_setting(self):
        with self.assertRaises(SystemCheckError) as ctx:
            call_command('check')
        self.assertIn(CHECK_ID_LEGACY_CALLBACK, str(ctx.exception))
        self.assertIn('does not enable', str(ctx.exception))
