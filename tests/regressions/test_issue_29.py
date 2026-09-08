"""Early validation of permission conditions via Django system checks (#29).

Follow-up to #28. Does not close #4. Construction-time operator errors stay
exceptions; model-aware semantic failures and the legacy-callback policy
are ``CheckMessage``s with stable IDs.
"""

from io import StringIO
from unittest.mock import patch

from django.apps import apps
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.checks import Error, Warning as CheckWarning, run_checks
from django.core.management import call_command
from django.core.management.base import SystemCheckError
from django.test import TestCase, override_settings

from trusts.checks import (
    CHECK_ID_INVALID_EXPR,
    CHECK_ID_LEGACY_CALLBACK,
    CHECK_ID_LEGACY_CALLBACK_WARNING,
    check_permission_conditions,
)
from trusts.conditions import (
    PermissionConditionError,
    condition_refs,
    validate_expression,
)
from trusts.models import (
    Content,
    PermissionConditionNotQueryable,
    Trust,
    TrustUserPermission,
    legacy_permission_callbacks_allowed,
)
from tests.regressions.test_issue_4 import _CallLog
from tests.support import (
    create_test_users,
    get_or_create_root_user,
    reload_test_users,
)
from tests.models import AutoAdminCategory, Ticket


# Snapshot taken at import, after app loading / class_prepared, before tests
# mutate the registry. Used so check tests do not depend on test order.
_IMPORT_CONDITIONS = {
    name: dict(codes) for name, codes in Content._conditions.items()
}


def _restore_conditions(snapshot):
    Content._conditions.clear()
    for name, codes in snapshot.items():
        Content._conditions[name] = dict(codes)


def _messages_with_id(messages, check_id):
    return [m for m in messages if m.id == check_id]


def _run_manage_py_check():
    out = StringIO()
    err = StringIO()
    call_command('check', stdout=out, stderr=err)
    return out.getvalue() + err.getvalue()


class ConditionRegistryIsolationMixin(object):
    def setUp(self):
        super(ConditionRegistryIsolationMixin, self).setUp()
        _restore_conditions(_IMPORT_CONDITIONS)

    def tearDown(self):
        _restore_conditions(_IMPORT_CONDITIONS)
        super(ConditionRegistryIsolationMixin, self).tearDown()


class PermissionConditionCheckTest(ConditionRegistryIsolationMixin, TestCase):
    """System-check diagnostics. Runtime fail-closed is covered with a grant."""

    def setUp(self):
        super(PermissionConditionCheckTest, self).setUp()
        call_command('create_trust_root')
        get_or_create_root_user(self)
        create_test_users(self)
        self.org_trust = Trust(
            settlor=self.user, trust=Trust.objects.get_root(), title='Check Org'
        )
        self.org_trust.save()
        self.ticket = Ticket.objects.create(
            trust=self.org_trust, title='owned', owner=self.user,
            organization=self._organization(), status='open',
        )
        self.perm_change = Permission.objects.get(
            content_type=ContentType.objects.get_for_model(Ticket),
            codename='change_ticket',
        )
        TrustUserPermission(
            trust=self.org_trust, entity=self.user, permission=self.perm_change
        ).save()
        reload_test_users(self)
        self.change = 'trusts_tests.change_ticket'

    def _organization(self):
        from tests.models import Organization
        return Organization.objects.create(name='CheckCo', manager=self.user)

    def test_import_time_meta_and_builtin_own_are_valid(self):
        own = Content.get_permission_condition_record(Trust, 'own')
        self.assertIsNotNone(own)
        self.assertIs(own.model, Trust)
        validate_expression(own.expr, Trust)

        meta_own = Content.get_permission_condition_record(Ticket, 'meta_own')
        self.assertIsNotNone(meta_own)
        self.assertIs(meta_own.model, Ticket)
        validate_expression(meta_own.expr, Ticket)

        messages = check_permission_conditions(None)
        self.assertEqual(_messages_with_id(messages, CHECK_ID_INVALID_EXPR), [])
        self.assertEqual(_messages_with_id(messages, CHECK_ID_LEGACY_CALLBACK), [])
        self.assertTrue(self.user.has_perm('%s:meta_own' % self.change, self.ticket))
        self.assertIn(
            self.ticket.pk,
            Ticket.objects.permitted('%s:meta_own' % self.change, self.user).values_list(
                'pk', flat=True
            ),
        )

    def test_valid_custom_expr_proxy_and_cross_app_fk_pass_check(self):
        u, p, o = condition_refs()
        Content.register_permission_condition(Ticket, 'owned', u == o.owner)
        Content.register_permission_condition(
            AutoAdminCategory, 'named', o.name == 'ok'
        )
        with self.assertNumQueries(0):
            messages = check_permission_conditions(None)
        self.assertEqual(_messages_with_id(messages, CHECK_ID_INVALID_EXPR), [])
        owned = Content.get_permission_condition_record(Ticket, 'owned')
        self.assertIs(owned.model, Ticket)
        named = Content.get_permission_condition_record(AutoAdminCategory, 'named')
        self.assertIs(named.model, AutoAdminCategory)

    def test_semantic_invalid_expr_does_not_raise_at_registration(self):
        u, p, o = condition_refs()
        expr = u == o.not_a_field
        Content.register_permission_condition(Ticket, 'missing', expr)
        record = Content.get_permission_condition_record(Ticket, 'missing')
        self.assertIs(record.expr, expr)
        self.assertIs(record.model, Ticket)

    def test_registration_before_models_ready_retains_identity(self):
        u, p, o = condition_refs()
        expr = u == o.owner
        with patch.object(apps, 'models_ready', False):
            Content.register_permission_condition(Ticket, 'deferred_own', expr)
        record = Content.get_permission_condition_record(Ticket, 'deferred_own')
        self.assertIs(record.expr, expr)
        self.assertIs(record.model, Ticket)
        messages = check_permission_conditions(None)
        self.assertEqual(_messages_with_id(messages, CHECK_ID_INVALID_EXPR), [])

        bad = u == o.deferred_missing
        with patch.object(apps, 'models_ready', False):
            Content.register_permission_condition(Ticket, 'deferred_bad', bad)
        errors = _messages_with_id(
            check_permission_conditions(None), CHECK_ID_INVALID_EXPR
        )
        self.assertTrue(any('deferred_missing' in m.msg for m in errors))
        self.assertTrue(any("'deferred_bad'" in m.msg for m in errors))

    def test_meta_permission_conditions_aggregated_as_check_errors(self):
        u, p, o = condition_refs()

        class ImportTimeBadTicket(Content):
            class Meta:
                app_label = 'trusts_tests'
                managed = False
                permission_conditions = (
                    ('bad_a', u == o.missing_a),
                    ('bad_b', o.trust == 1),
                )

        self.assertIsNotNone(
            Content.get_permission_condition_record(ImportTimeBadTicket, 'bad_a')
        )
        errors = _messages_with_id(
            check_permission_conditions(None), CHECK_ID_INVALID_EXPR
        )
        needles = ' '.join(m.msg for m in errors)
        self.assertIn('bad_a', needles)
        self.assertIn('missing_a', needles)
        self.assertIn('bad_b', needles)
        self.assertIn('incompatible', needles)
        self.assertGreaterEqual(len(errors), 2)
        for message in errors:
            self.assertIsInstance(message, Error)
            self.assertIn('fail closed', message.hint)

    def test_multiple_dynamic_errors_are_aggregated(self):
        u, p, o = condition_refs()
        Content.register_permission_condition(Ticket, 'typo', u == o.nope)
        Content.register_permission_condition(Ticket, 'types', o.status == 1)
        errors = _messages_with_id(
            check_permission_conditions(None), CHECK_ID_INVALID_EXPR
        )
        self.assertEqual(len(errors), 2)
        msgs = ' '.join(m.msg for m in errors)
        self.assertIn('typo', msgs)
        self.assertIn('types', msgs)

    def test_app_configs_subset_still_reports_other_apps(self):
        u, p, o = condition_refs()
        Content.register_permission_condition(Ticket, 'typo', u == o.nope)
        trusts_only = [apps.get_app_config('trusts')]
        errors = _messages_with_id(
            check_permission_conditions(app_configs=trusts_only),
            CHECK_ID_INVALID_EXPR,
        )
        self.assertTrue(any("'typo'" in m.msg for m in errors))

    def test_manage_py_check_reports_invalid_meta_condition(self):
        u, p, o = condition_refs()
        Content.register_permission_condition(Ticket, 'typo', u == o.nope)
        with self.assertRaises(SystemCheckError) as ctx:
            _run_manage_py_check()
        self.assertIn(CHECK_ID_INVALID_EXPR, str(ctx.exception))
        self.assertIn('typo', str(ctx.exception))

    def test_manage_py_check_passes_for_valid_registrations(self):
        output = _run_manage_py_check()
        self.assertNotIn(CHECK_ID_INVALID_EXPR, output)
        self.assertNotIn(CHECK_ID_LEGACY_CALLBACK, output)

    @override_settings(SILENCED_SYSTEM_CHECKS=['trusts.E001', 'fields.W342'])
    def test_silenced_expr_check_still_fails_closed_at_runtime(self):
        u, p, o = condition_refs()
        Content.register_permission_condition(Ticket, 'missing', u == o.not_a_field)
        _run_manage_py_check()
        missing = '%s:missing' % self.change
        with self.assertRaises(PermissionConditionError) as direct:
            self.user.has_perm(missing, self.ticket)
        self.assertIn('not_a_field', str(direct.exception))
        with self.assertRaises(PermissionConditionError):
            Ticket.objects.permitted(missing, self.user)
        self.assertTrue(self.user.has_perm(self.change, self.ticket))

    def test_default_legacy_callback_is_check_error_and_runtime_fail_closed(self):
        self.assertFalse(legacy_permission_callbacks_allowed())
        log = _CallLog(lambda user, perm, obj: True)
        Content.register_permission_condition(Ticket, 'spy', log)
        errors = _messages_with_id(
            check_permission_conditions(None), CHECK_ID_LEGACY_CALLBACK
        )
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], Error)
        self.assertIn('spy', errors[0].msg)
        self.assertEqual(log.calls, [])

        spy = '%s:spy' % self.change
        with self.assertRaises(PermissionConditionError) as ctx:
            self.user.has_perm(spy, self.ticket)
        self.assertIn('TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS', str(ctx.exception))
        self.assertEqual(log.calls, [])
        with self.assertRaises(PermissionConditionNotQueryable):
            Ticket.objects.permitted(spy, self.user)
        self.assertEqual(log.calls, [])
        self.assertTrue(self.user.has_perm(self.change, self.ticket))

    @override_settings(SILENCED_SYSTEM_CHECKS=['trusts.E002', 'fields.W342'])
    def test_silenced_legacy_check_still_does_not_invoke_callback(self):
        log = _CallLog(lambda user, perm, obj: True)
        Content.register_permission_condition(Ticket, 'spy', log)
        _run_manage_py_check()
        self.assertEqual(log.calls, [])
        with self.assertRaises(PermissionConditionError):
            self.user.has_perm('%s:spy' % self.change, self.ticket)
        self.assertEqual(log.calls, [])

    @override_settings(TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS=True)
    def test_legacy_opt_in_emits_warning_and_keeps_object_only_behavior(self):
        self.assertTrue(legacy_permission_callbacks_allowed())
        log = _CallLog(lambda user, perm, obj: user == obj.owner)
        Content.register_permission_condition(Ticket, 'spy', log)
        warnings = _messages_with_id(
            check_permission_conditions(None), CHECK_ID_LEGACY_CALLBACK_WARNING
        )
        self.assertEqual(len(warnings), 1)
        self.assertIsInstance(warnings[0], CheckWarning)
        self.assertEqual(
            _messages_with_id(check_permission_conditions(None), CHECK_ID_LEGACY_CALLBACK),
            [],
        )
        self.assertEqual(log.calls, [])

        spy = '%s:spy' % self.change
        with self.assertRaises(PermissionConditionNotQueryable):
            Ticket.objects.permitted(spy, self.user)
        self.assertEqual(log.calls, [])
        self.assertTrue(self.user.has_perm(spy, self.ticket))
        self.assertEqual(len(log.calls), 1)
        self.assertFalse(log.saw_ref())

        output = _run_manage_py_check()
        self.assertIn(CHECK_ID_LEGACY_CALLBACK_WARNING, output)
        self.assertEqual(log.calls, [log.calls[0]])

    def test_checks_never_invoke_callables(self):
        exploding = _CallLog(lambda user, perm, obj: (_ for _ in ()).throw(
            AssertionError('callable must not run during checks')
        ))
        Content.register_permission_condition(Ticket, 'boom', exploding)
        with self.assertNumQueries(0):
            messages = check_permission_conditions(None)
        self.assertEqual(exploding.calls, [])
        self.assertEqual(len(_messages_with_id(messages, CHECK_ID_LEGACY_CALLBACK)), 1)
        run_checks()
        self.assertEqual(exploding.calls, [])

    def test_ready_does_not_raise_when_invalid_conditions_are_registered(self):
        u, p, o = condition_refs()
        Content.register_permission_condition(Ticket, 'typo', u == o.nope)
        apps.get_app_config('trusts').ready()
        errors = _messages_with_id(
            check_permission_conditions(None), CHECK_ID_INVALID_EXPR
        )
        self.assertTrue(any("'typo'" in m.msg for m in errors))
