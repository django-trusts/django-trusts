"""#142 Stage A: registration-time condition builders."""

from django.contrib.auth import get_user_model
from django.core.checks import Error
from django.db import connection, models
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.test.utils import isolate_apps

from trusts.checks import (
    CHECK_ID_REMOVED_LEGACY_CALLBACK_SETTING,
    leftover_legacy_callback_setting_messages,
    permission_condition_check_messages,
)
from trusts.conditions import (
    ModelIdentity,
    PermissionConditionError,
    condition_refs,
)
from trusts.core import BackendHandle, TrustsConfigurationError, TrustsRegistry


def _note_model():
    User = get_user_model()

    class Note(models.Model):
        title = models.CharField(max_length=40)
        owner = models.ForeignKey(User, on_delete=models.CASCADE)
        confidential = models.BooleanField(null=True)

        class Meta:
            app_label = 'trusts_tests'

    return Note


class _CallLog(object):
    def __init__(self, impl):
        self.impl = impl
        self.calls = []

    def __call__(self, user, perm, obj):
        self.calls.append((user, perm, obj))
        return self.impl(user, perm, obj)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class StageABuilderRegistrationTest(SimpleTestCase):
    def test_lambda_and_named_builder_are_identical(self):
        Note = _note_model()
        registry = TrustsRegistry()

        def owned(u, p, o):
            return u == o.owner

        named = registry.register_permission_condition(Note, 'own', owned)
        lam = TrustsRegistry().register_permission_condition(
            Note, 'own', lambda u, p, o: u == o.owner,
        )
        self.assertEqual(named.expr.to_tuple(), lam.expr.to_tuple())
        self.assertFalse(hasattr(named, 'func'))

    def test_builder_invoked_once_and_not_during_evaluate_or_compile(self):
        Note = _note_model()
        registry = TrustsRegistry()
        log = _CallLog(lambda u, p, o: u == o.owner)
        registry.register_permission_condition(Note, 'own', log)
        self.assertEqual(len(log.calls), 1)
        u, p, o = log.calls[0]
        self.assertEqual(u.to_tuple(), ('ref', 'principal', ()))
        self.assertEqual(p.to_tuple(), ('ref', 'permission', ()))
        self.assertEqual(o.to_tuple(), ('ref', 'object', ()))
        with self.assertRaises(AttributeError):
            registry.evaluate_permission_condition(
                Note, 'own', object(), 'change', object(),
            )
        self.assertEqual(len(log.calls), 1)

    def test_real_bool_and_bare_ref_fail_at_register(self):
        Note = _note_model()
        registry = TrustsRegistry()
        with self.assertRaises(PermissionConditionError):
            registry.register_permission_condition(
                Note, 'yes', lambda u, p, o: True,
            )
        with self.assertRaises(PermissionConditionError):
            registry.register_permission_condition(
                Note, 'bare', lambda u, p, o: o.owner,
            )

    def test_unresolved_field_fails_at_register(self):
        Note = _note_model()
        registry = TrustsRegistry()
        with self.assertRaises(PermissionConditionError) as ctx:
            registry.register_permission_condition(
                Note, 'typo', lambda u, p, o: u == o.nope,
            )
        self.assertIn('nope', str(ctx.exception))

    def test_frozen_registry_rejects_before_builder(self):
        Note = _note_model()
        registry = TrustsRegistry()
        registry.freeze()
        log = _CallLog(lambda u, p, o: u == o.owner)
        with self.assertRaises(TrustsConfigurationError):
            registry.register_permission_condition(Note, 'own', log)
        self.assertEqual(log.calls, [])

    def test_handle_method_delegates(self):
        Note = _note_model()
        registry = TrustsRegistry()
        handle = BackendHandle(
            path='tests.backends.HostTrustModelBackend',
            registry=registry,
            compiler=object(),
        )
        record = handle.register_permission_condition(
            Note, 'own', lambda u, p, o: u == o.owner,
        )
        self.assertIs(
            registry.get_permission_condition_record(Note, 'own'), record,
        )

    def test_transitional_expr_still_accepted(self):
        Note = _note_model()
        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        expr = u == o.owner
        record = registry.register_permission_condition(Note, 'own', expr)
        self.assertEqual(record.expr.to_tuple(), expr.to_tuple())

    def test_mutable_and_unsaved_constants_rejected(self):
        Note = _note_model()
        registry = TrustsRegistry()
        with self.assertRaises(PermissionConditionError):
            registry.register_permission_condition(
                Note, 'flags', lambda u, p, o: o.title == ['x'],
            )
        User = get_user_model()
        unsaved = User(username='unsaved-142')
        with self.assertRaises(PermissionConditionError):
            registry.register_permission_condition(
                Note, 'unsaved', lambda u, p, o: o.owner == unsaved,
            )

    @override_settings(TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS=True)
    def test_leftover_setting_is_check_error(self):
        messages = leftover_legacy_callback_setting_messages()
        self.assertEqual(len(messages), 1)
        self.assertIsInstance(messages[0], Error)
        self.assertEqual(messages[0].id, CHECK_ID_REMOVED_LEGACY_CALLBACK_SETTING)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class StageANormalizationRuntimeTest(TransactionTestCase):
    def test_saved_model_constant_is_identity_and_zero_sql_register(self):
        Note = _note_model()
        User = get_user_model()
        with connection.schema_editor() as editor:
            editor.create_model(Note)
        try:
            alice = User.objects.create_user(
                'alice-142', 'alice-142@example.com', 'x',
            )
            keep = Note.objects.create(title='keep', owner=alice)
            registry = TrustsRegistry()
            with self.assertNumQueries(0):
                record = registry.register_permission_condition(
                    Note, 'alice', lambda u, p, o: o.owner == alice,
                )
            const = record.expr.right
            self.assertIsInstance(const.value, ModelIdentity)
            self.assertEqual(const.value.pk, alice.pk)
            alice.username = 'mutated'
            self.assertTrue(
                registry.evaluate_permission_condition(
                    Note, 'alice', alice, 'change', keep,
                )
            )
            q = registry.compile_registered_condition_q(
                Note, 'trusts_tests.change_note:alice', alice,
            )
            self.assertEqual(
                list(Note.objects.filter(q).values_list('pk', flat=True)),
                [keep.pk],
            )
        finally:
            with connection.schema_editor() as editor:
                editor.delete_model(Note)

    def test_nullable_boolean_builder_and_checks_do_not_reinvoke(self):
        Note = _note_model()
        User = get_user_model()
        with connection.schema_editor() as editor:
            editor.create_model(Note)
        try:
            alice = User.objects.create_user(
                'alice-142b', 'alice-142b@example.com', 'x',
            )
            open_note = Note.objects.create(
                title='open', owner=alice, confidential=False,
            )
            secret = Note.objects.create(
                title='secret', owner=alice, confidential=True,
            )
            unset = Note.objects.create(
                title='unset', owner=alice, confidential=None,
            )
            log = _CallLog(lambda u, p, o: o.confidential != True)
            registry = TrustsRegistry()
            registry.register_permission_condition(Note, 'public', log)
            self.assertEqual(len(log.calls), 1)
            permission_condition_check_messages(registry.iter_permission_conditions())
            self.assertEqual(len(log.calls), 1)
            self.assertTrue(
                registry.evaluate_permission_condition(
                    Note, 'public', alice, 'change', open_note,
                )
            )
            self.assertTrue(
                registry.evaluate_permission_condition(
                    Note, 'public', alice, 'change', unset,
                )
            )
            self.assertFalse(
                registry.evaluate_permission_condition(
                    Note, 'public', alice, 'change', secret,
                )
            )
            self.assertEqual(len(log.calls), 1)
        finally:
            with connection.schema_editor() as editor:
                editor.delete_model(Note)
