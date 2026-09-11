"""Zero #16 core half: per-handle permission-condition registry.

Library-only proofs. Does not import Zero nouns. Sibling Zero PR must
keep has_perm / .permitted() / Meta donation / ContentConditionLookup
removal proofs green against this core API.
"""

from contextlib import contextmanager
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.checks import Error, Warning as CheckWarning
from django.db import connection, models
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.test.utils import isolate_apps

from trusts.checks import (
    CHECK_ID_INVALID_EXPR,
    CHECK_ID_LEGACY_CALLBACK,
    CHECK_ID_LEGACY_CALLBACK_WARNING,
    check_permission_conditions,
    iter_live_permission_conditions,
    permission_condition_check_messages,
)
from trusts.conditions import (
    ConditionLookup,
    ConditionRecord,
    ConditionRegistry,
    PermissionConditionError,
    PermissionConditionNotQueryable,
    RegistryConditionLookup,
    condition_refs,
    legacy_permission_callbacks_allowed,
)
from trusts.core import TrustsRegistry


def _note_models():
    User = get_user_model()

    class Note(models.Model):
        title = models.CharField(max_length=40)
        owner = models.ForeignKey(User, on_delete=models.CASCADE)
        status = models.CharField(max_length=20, default='open')

        class Meta:
            app_label = 'trusts_tests'

    class Memo(models.Model):
        title = models.CharField(max_length=40)

        class Meta:
            app_label = 'trusts_tests'

    return Note, Memo


@contextmanager
def _tables(*model_classes):
    with connection.schema_editor() as editor:
        for model in model_classes:
            editor.create_model(model)
    try:
        yield
    finally:
        with connection.schema_editor() as editor:
            for model in reversed(model_classes):
                editor.delete_model(model)


class _CallLog(object):
    def __init__(self, impl=None):
        self.impl = impl or (lambda user, perm, obj: True)
        self.calls = []

    def __call__(self, user, perm, obj):
        self.calls.append((user, perm, obj))
        return self.impl(user, perm, obj)


class ConditionRegistryIsolationTest(SimpleTestCase):
    def test_no_process_global_condition_store(self):
        import trusts.conditions as conditions_mod

        self.assertFalse(hasattr(conditions_mod, '_conditions'))
        self.assertIsInstance(ConditionRegistry(), ConditionRegistry)
        first = ConditionRegistry()
        second = ConditionRegistry()
        self.assertIsNot(first._records, second._records)
        self.assertEqual(list(first.iter_permission_conditions()), [])
        self.assertEqual(list(second.iter_permission_conditions()), [])

    def test_trusts_registry_owns_a_private_condition_store(self):
        left = TrustsRegistry()
        right = TrustsRegistry()
        self.assertIsInstance(left.conditions, ConditionRegistry)
        self.assertIsNot(left.conditions, right.conditions)
        self.assertEqual(list(left.iter_permission_conditions()), [])
        self.assertEqual(list(right.iter_permission_conditions()), [])


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ConditionRegistryShapeTest(SimpleTestCase):
    def test_expr_and_callable_records_and_shape_errors(self):
        Note, Memo = _note_models()
        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        expr = u == o.owner
        record = registry.register_permission_condition(Note, 'owned', expr)
        self.assertIsInstance(record, ConditionRecord)
        self.assertIs(record.expr, expr)
        self.assertIsNone(record.func)
        self.assertIs(record.model, Note)
        self.assertIs(
            registry.get_permission_condition_record(Note, 'owned'), record,
        )
        self.assertIsNone(registry.get_permission_condition_record(Note, 'missing'))
        self.assertIsNone(registry.get_permission_condition_record(Memo, 'owned'))

        log = _CallLog()
        callable_record = registry.register_permission_condition(Note, 'spy', log)
        self.assertIsNone(callable_record.expr)
        self.assertIs(callable_record.func, log)
        self.assertEqual(log.calls, [])

        with self.assertRaises(PermissionConditionError):
            registry.register_permission_condition(Note, 'bare', o.owner)
        with self.assertRaises(TypeError):
            registry.register_permission_condition(Note, 'bad', 'not-a-condition')
        self.assertEqual(log.calls, [])

    def test_duplicate_condition_overwrites_same_identity(self):
        Note, _Memo = _note_models()
        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        first = u == o.owner
        second = o.title == 'keep'
        registry.register_permission_condition(Note, 'named', first)
        registry.register_permission_condition(Note, 'named', second)
        record = registry.get_permission_condition_record(Note, 'named')
        self.assertIs(record.expr, second)
        rows = list(registry.iter_permission_conditions())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], 'named')

    def test_owners_do_not_share_or_overwrite_records(self):
        Note, _Memo = _note_models()
        u, _p, o = condition_refs()
        owner_a = TrustsRegistry()
        owner_b = TrustsRegistry()
        expr_a = u == o.owner
        expr_b = o.title == 'keep'
        owner_a.register_permission_condition(Note, 'own', expr_a)
        owner_b.register_permission_condition(Note, 'own', expr_b)
        self.assertIs(
            owner_a.get_permission_condition_record(Note, 'own').expr, expr_a,
        )
        self.assertIs(
            owner_b.get_permission_condition_record(Note, 'own').expr, expr_b,
        )
        self.assertIsNot(
            owner_a.get_permission_condition_record(Note, 'own'),
            owner_b.get_permission_condition_record(Note, 'own'),
        )

    def test_repeated_registry_construction_does_not_leak(self):
        Note, _Memo = _note_models()
        u, _p, o = condition_refs()
        first = TrustsRegistry()
        first.register_permission_condition(Note, 'own', u == o.owner)
        self.assertIsNotNone(first.get_permission_condition_record(Note, 'own'))
        second = TrustsRegistry()
        self.assertIsNone(second.get_permission_condition_record(Note, 'own'))
        self.assertEqual(list(second.iter_permission_conditions()), [])
        third = ConditionRegistry()
        self.assertIsNone(third.get_permission_condition_record(Note, 'own'))

    def test_freeze_does_not_seal_condition_registration(self):
        Note, _Memo = _note_models()
        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        registry.freeze()
        record = registry.register_permission_condition(Note, 'own', u == o.owner)
        self.assertIs(record.model, Note)

    def test_generic_lookup_binds_without_invoking(self):
        Note, _Memo = _note_models()
        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        log = _CallLog()
        registry.register_permission_condition(Note, 'spy', log)
        lookup = RegistryConditionLookup(registry)
        self.assertIsInstance(lookup, ConditionLookup)
        registry.set_condition_lookup(lookup)
        self.assertIs(registry.condition_lookup, lookup)
        self.assertIs(lookup.record_for(Note, 'spy').func, log)
        self.assertEqual(log.calls, [])
        with self.assertRaises(PermissionConditionNotQueryable):
            lookup.compile_q(Note, 'trusts_tests.change_note:spy', None)
        self.assertEqual(log.calls, [])


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ConditionRegistryRuntimeTest(TransactionTestCase):
    def test_expr_object_list_parity_and_fixed_query(self):
        Note, _Memo = _note_models()
        User = get_user_model()
        with _tables(Note):
            alice = User.objects.create_user(
                'alice-16', 'alice-16@example.com', 'x',
            )
            bob = User.objects.create_user(
                'bob-16', 'bob-16@example.com', 'x',
            )
            keep = Note.objects.create(title='keep', owner=alice, status='open')
            drop = Note.objects.create(title='drop', owner=bob, status='open')
            locked = Note.objects.create(
                title='keep', owner=alice, status='locked',
            )
            u, _p, o = condition_refs()
            registry = TrustsRegistry()
            expr = (u == o.owner) & (o.status != 'locked')
            registry.register_permission_condition(Note, 'editable', expr)
            perm = 'trusts_tests.change_note:editable'
            grant = 'trusts_tests.change_note'
            q = registry.compile_registered_condition_q(Note, perm, alice)
            listed = set(Note.objects.filter(q).values_list('pk', flat=True))
            evaluated = set()
            for row in Note.objects.all():
                if registry.evaluate_permission_condition(
                    Note, 'editable', alice, grant, row,
                ):
                    evaluated.add(row.pk)
            self.assertEqual(listed, {keep.pk})
            self.assertEqual(evaluated, listed)
            self.assertNotIn(drop.pk, listed)
            self.assertNotIn(locked.pk, listed)
            sql = str(Note.objects.filter(q).query)
            self.assertIn('owner', sql.lower())
            self.assertIn('status', sql.lower())

    def test_default_rejects_callable_without_invoking(self):
        self.assertFalse(legacy_permission_callbacks_allowed())
        Note, _Memo = _note_models()
        User = get_user_model()
        with _tables(Note):
            alice = User.objects.create_user(
                'alice-16c', 'alice-16c@example.com', 'x',
            )
            note = Note.objects.create(title='n', owner=alice)
            log = _CallLog(lambda user, perm, obj: True)
            registry = TrustsRegistry()
            registry.register_permission_condition(Note, 'spy', log)
            with self.assertRaises(PermissionConditionNotQueryable):
                registry.compile_registered_condition_q(
                    Note, 'trusts_tests.change_note:spy', alice,
                )
            with self.assertRaises(PermissionConditionError) as ctx:
                registry.evaluate_permission_condition(
                    Note, 'spy', alice, 'trusts_tests.change_note', note,
                )
            self.assertIn('TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS', str(ctx.exception))
            self.assertEqual(log.calls, [])

    @override_settings(TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS=True)
    def test_opt_in_callback_is_object_only(self):
        self.assertTrue(legacy_permission_callbacks_allowed())
        Note, _Memo = _note_models()
        User = get_user_model()
        with _tables(Note):
            alice = User.objects.create_user(
                'alice-16o', 'alice-16o@example.com', 'x',
            )
            note = Note.objects.create(title='n', owner=alice)
            log = _CallLog(lambda user, perm, obj: user == obj.owner)
            registry = TrustsRegistry()
            registry.register_permission_condition(Note, 'spy', log)
            with self.assertRaises(PermissionConditionNotQueryable):
                registry.compile_registered_condition_q(
                    Note, 'trusts_tests.change_note:spy', alice,
                )
            self.assertEqual(log.calls, [])
            self.assertTrue(
                registry.evaluate_permission_condition(
                    Note, 'spy', alice, 'trusts_tests.change_note', note,
                )
            )
            self.assertEqual(len(log.calls), 1)
            self.assertEqual(log.calls[0][0], alice)
            self.assertEqual(log.calls[0][2], note)

    def test_unknown_malformed_and_unbound_fail_closed(self):
        Note, _Memo = _note_models()
        User = get_user_model()
        with _tables(Note):
            alice = User.objects.create_user(
                'alice-16u', 'alice-16u@example.com', 'x',
            )
            note = Note.objects.create(title='n', owner=alice)
            u, _p, o = condition_refs()
            registry = TrustsRegistry()
            with self.assertRaises(AttributeError) as missing:
                registry.compile_registered_condition_q(
                    Note, 'trusts_tests.change_note:missing', alice,
                )
            self.assertIn('missing', str(missing.exception))
            with self.assertRaises(AttributeError):
                registry.evaluate_permission_condition(
                    Note, 'missing', alice, 'trusts_tests.change_note', note,
                )
            registry.register_permission_condition(Note, 'typo', u == o.nope)
            with self.assertRaises(PermissionConditionError) as typo:
                registry.compile_registered_condition_q(
                    Note, 'trusts_tests.change_note:typo', alice,
                )
            self.assertIn('nope', str(typo.exception))
            with self.assertRaises(PermissionConditionError):
                registry.evaluate_permission_condition(
                    Note, 'typo', alice, 'trusts_tests.change_note', note,
                )
            empty = ConditionRecord(model=Note)
            registry.conditions._records[
                (Note._meta.label, 'empty')
            ] = empty
            with self.assertRaises(PermissionConditionError) as unbound:
                registry.evaluate_permission_condition(
                    Note, 'empty', alice, 'trusts_tests.change_note', note,
                )
            self.assertIn('unbound', str(unbound.exception))


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ConditionRegistryCheckTest(SimpleTestCase):
    def test_checks_never_invoke_callables(self):
        Note, _Memo = _note_models()
        exploding = _CallLog(lambda user, perm, obj: (_ for _ in ()).throw(
            AssertionError('callable must not run during checks')
        ))
        registry = ConditionRegistry()
        registry.register_permission_condition(Note, 'boom', exploding)
        messages = permission_condition_check_messages(
            registry.iter_permission_conditions()
        )
        self.assertEqual(exploding.calls, [])
        self.assertEqual(len([m for m in messages if m.id == CHECK_ID_LEGACY_CALLBACK]), 1)

    def test_invalid_expr_is_check_error_not_registration_error(self):
        Note, _Memo = _note_models()
        u, _p, o = condition_refs()
        registry = ConditionRegistry()
        expr = u == o.not_a_field
        record = registry.register_permission_condition(Note, 'missing', expr)
        self.assertIs(record.expr, expr)
        errors = [
            m for m in permission_condition_check_messages(
                registry.iter_permission_conditions()
            )
            if m.id == CHECK_ID_INVALID_EXPR
        ]
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], Error)
        self.assertIn('not_a_field', errors[0].msg)

    @override_settings(TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS=True)
    def test_opt_in_emits_warning_without_invoking(self):
        Note, _Memo = _note_models()
        log = _CallLog()
        registry = ConditionRegistry()
        registry.register_permission_condition(Note, 'spy', log)
        messages = permission_condition_check_messages(
            registry.iter_permission_conditions()
        )
        warnings = [m for m in messages if m.id == CHECK_ID_LEGACY_CALLBACK_WARNING]
        self.assertEqual(len(warnings), 1)
        self.assertIsInstance(warnings[0], CheckWarning)
        self.assertEqual(
            [m for m in messages if m.id == CHECK_ID_LEGACY_CALLBACK], [],
        )
        self.assertEqual(log.calls, [])

    def test_check_permission_conditions_reads_handle_registry(self):
        Note, _Memo = _note_models()
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

        with patch(
            'trusts.apps.implementation_configs', return_value=(_Config(),),
        ):
            messages = check_permission_conditions(None)
        errors = [m for m in messages if m.id == CHECK_ID_INVALID_EXPR]
        self.assertTrue(any("'typo'" in m.msg for m in errors))

    def test_two_owners_same_model_code_both_validated(self):
        Note, _Memo = _note_models()
        u, _p, o = condition_refs()
        owner_a = TrustsRegistry()
        owner_b = TrustsRegistry()
        owner_a.register_permission_condition(Note, 'own', u == o.owner)
        owner_b.register_permission_condition(Note, 'own', u == o.nope)

        class _Handle(object):
            def __init__(self, store):
                self.registry = store

        class _Config(object):
            def __init__(self, store, path):
                self._store = store
                self._path = path

            def _configured_trusts_paths(self):
                return (self._path,)

            def configured_backend(self, path=None):
                return _Handle(self._store)

        configs = (
            _Config(owner_a, 'tests.backends.HostTrustModelBackend'),
            _Config(owner_b, 'tests.backends.MixinOnlyBackend'),
        )
        with patch(
            'trusts.apps.implementation_configs', return_value=configs,
        ):
            live = list(iter_live_permission_conditions())
            messages = check_permission_conditions(None)
        own_rows = [
            record for model, code, record in live
            if model is Note and code == 'own'
        ]
        self.assertEqual(len(own_rows), 2)
        self.assertEqual(len({id(record.expr) for record in own_rows}), 2)
        errors = [m for m in messages if m.id == CHECK_ID_INVALID_EXPR]
        self.assertTrue(any("'own'" in m.msg and 'nope' in m.msg for m in errors))
        self.assertTrue(
            any(m.obj is Note for m in errors),
            'invalid owner B record must still be reported',
        )
