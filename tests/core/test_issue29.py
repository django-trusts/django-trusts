"""#29: generic registration / check-ID / validation lifecycle.

Live Trust/Content runtime stay on Zero ``tests/legacy/test_issue29.py``.
This module proves the library check IDs and register-then-check
lifecycle on an isolated ``ConditionRegistry`` / handle registry.
"""

from io import StringIO
from unittest.mock import patch

from django.apps import apps
from django.contrib.auth import get_user_model
from django.core.checks import Error, Warning as CheckWarning
from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.db import models
from django.test import SimpleTestCase, override_settings
from django.test.utils import isolate_apps

from trusts.checks import (
    CHECK_ID_INVALID_EXPR,
    CHECK_ID_LEGACY_CALLBACK,
    CHECK_ID_LEGACY_CALLBACK_WARNING,
    check_permission_conditions,
    permission_condition_check_messages,
)
from trusts.conditions import (
    PermissionConditionError,
    condition_refs,
    legacy_permission_callbacks_allowed,
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


class _CallLog(object):
    def __init__(self, impl=None):
        self.impl = impl or (lambda user, perm, obj: True)
        self.calls = []

    def __call__(self, user, perm, obj):
        self.calls.append((user, perm, obj))
        return self.impl(user, perm, obj)


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

    def test_registration_before_models_ready_retains_identity(self):
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

    def test_default_legacy_callback_is_check_error(self):
        self.assertFalse(legacy_permission_callbacks_allowed())
        Note = _note_model()
        log = _CallLog()
        registry = TrustsRegistry()
        registry.register_permission_condition(Note, 'spy', log)
        errors = _messages_with_id(
            permission_condition_check_messages(
                registry.iter_permission_conditions(),
            ),
            CHECK_ID_LEGACY_CALLBACK,
        )
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], Error)
        self.assertIn('spy', errors[0].msg)
        self.assertEqual(log.calls, [])

    @override_settings(TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS=True)
    def test_legacy_opt_in_emits_warning_without_invoking(self):
        self.assertTrue(legacy_permission_callbacks_allowed())
        Note = _note_model()
        log = _CallLog()
        registry = TrustsRegistry()
        registry.register_permission_condition(Note, 'spy', log)
        messages = permission_condition_check_messages(
            registry.iter_permission_conditions(),
        )
        warnings = _messages_with_id(messages, CHECK_ID_LEGACY_CALLBACK_WARNING)
        self.assertEqual(len(warnings), 1)
        self.assertIsInstance(warnings[0], CheckWarning)
        self.assertEqual(_messages_with_id(messages, CHECK_ID_LEGACY_CALLBACK), [])
        self.assertEqual(log.calls, [])

    def test_checks_never_invoke_callables(self):
        Note = _note_model()
        exploding = _CallLog(lambda user, perm, obj: (_ for _ in ()).throw(
            AssertionError('callable must not run during checks')
        ))
        registry = TrustsRegistry()
        registry.register_permission_condition(Note, 'boom', exploding)
        messages = permission_condition_check_messages(
            registry.iter_permission_conditions(),
        )
        self.assertEqual(exploding.calls, [])
        self.assertEqual(len(_messages_with_id(messages, CHECK_ID_LEGACY_CALLBACK)), 1)

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
