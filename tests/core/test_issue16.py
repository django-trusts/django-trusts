"""#16 / #142 Stage A: per-handle condition registry and builders.

Library-only proofs. Does not import Zero nouns. Transitional ``Expr``
acceptance remains so Zero ``Trust:own`` donation keeps loading.
"""

from contextlib import contextmanager
from decimal import Decimal
from io import BytesIO
from unittest.mock import patch
from uuid import uuid4

from django.contrib.auth import get_user_model
from django.core.checks import Error
from django.db import connection, models
from django.http import HttpRequest
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.test.utils import isolate_apps

from tests.models import Ticket, ticket_meta_own
from trusts.checks import (
    CHECK_ID_INVALID_EXPR,
    CHECK_ID_OBSOLETE_CALLBACK_SETTING,
    check_obsolete_legacy_callback_setting,
    check_permission_conditions,
    iter_live_permission_conditions,
    permission_condition_check_messages,
)
from trusts.conditions import (
    ConditionLookup,
    ConditionRecord,
    ConditionRegistry,
    ModelIdentity,
    PermissionConditionError,
    PermissionConditionUnsupported,
    Ref,
    RegistryConditionLookup,
    condition_refs,
    obsolete_legacy_callback_setting_enabled,
)
from trusts.core import BackendHandle, TrustsConfigurationError, TrustsRegistry


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


class _BuilderLog(object):
    def __init__(self, impl=None):
        self.impl = impl or (lambda u, p, o: u == o.owner)
        self.calls = []

    def __call__(self, u, p, o):
        self.calls.append((u, p, o))
        return self.impl(u, p, o)

    def saw_only_refs(self):
        return all(
            isinstance(arg, Ref) for call in self.calls for arg in call
        )


class ConditionRegistryIsolationTest(SimpleTestCase):
    def test_no_process_global_condition_store(self):
        import trusts.conditions as conditions_mod

        self.assertFalse(hasattr(conditions_mod, '_conditions'))
        self.assertFalse(hasattr(conditions_mod, 'legacy_permission_callbacks_allowed'))
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
    def test_expr_and_builder_records_and_shape_errors(self):
        Note, Memo = _note_models()
        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        expr = u == o.owner
        record = registry.register_permission_condition(Note, 'owned', expr)
        self.assertIsInstance(record, ConditionRecord)
        self.assertIs(record.expr, expr)
        self.assertFalse(hasattr(record, 'func'))
        self.assertIs(record.model, Note)
        self.assertIs(
            registry.get_permission_condition_record(Note, 'owned'), record,
        )
        self.assertIsNone(registry.get_permission_condition_record(Note, 'missing'))
        self.assertIsNone(registry.get_permission_condition_record(Memo, 'owned'))

        log = _BuilderLog()
        builder_record = registry.register_permission_condition(Note, 'spy', log)
        self.assertIsNotNone(builder_record.expr)
        self.assertFalse(hasattr(builder_record, 'func'))
        self.assertEqual(len(log.calls), 1)
        self.assertTrue(log.saw_only_refs())
        self.assertEqual(
            builder_record.expr.to_tuple(),
            ('eq', ('ref', 'principal', ()), ('ref', 'object', ('owner',))),
        )

        with self.assertRaises(PermissionConditionError):
            registry.register_permission_condition(Note, 'bare', o.owner)
        with self.assertRaises(TypeError):
            registry.register_permission_condition(Note, 'bad', 'not-a-condition')
        self.assertEqual(len(log.calls), 1)

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

    def test_freeze_seals_condition_registration_before_builder(self):
        Note, _Memo = _note_models()
        log = _BuilderLog()
        registry = TrustsRegistry()
        registry.freeze()
        with self.assertRaises(TrustsConfigurationError) as ctx:
            registry.register_permission_condition(Note, 'own', log)
        self.assertIn('frozen', str(ctx.exception).lower())
        self.assertEqual(log.calls, [])
        self.assertIsNone(registry.get_permission_condition_record(Note, 'own'))

    def test_handle_register_forwards_and_freeze_is_before_builder(self):
        Note, _Memo = _note_models()
        registry = TrustsRegistry()
        handle = BackendHandle(
            path='tests.backends.HostTrustModelBackend',
            registry=registry,
            compiler=object(),
        )
        log = _BuilderLog()
        record = handle.register_permission_condition(Note, 'own', log)
        self.assertIs(
            registry.get_permission_condition_record(Note, 'own'), record,
        )
        self.assertEqual(len(log.calls), 1)
        registry.freeze()
        late = _BuilderLog()
        with self.assertRaises(TrustsConfigurationError):
            handle.register_permission_condition(Note, 'late', late)
        self.assertEqual(late.calls, [])

    def test_generic_lookup_binds_without_reinvoking_builder(self):
        Note, _Memo = _note_models()
        registry = TrustsRegistry()
        log = _BuilderLog()
        registry.register_permission_condition(Note, 'spy', log)
        lookup = RegistryConditionLookup(registry)
        self.assertIsInstance(lookup, ConditionLookup)
        registry.set_condition_lookup(lookup)
        self.assertIs(registry.condition_lookup, lookup)
        self.assertIsNotNone(lookup.record_for(Note, 'spy').expr)
        self.assertEqual(len(log.calls), 1)
        q = lookup.compile_q(Note, 'trusts_tests.change_note:spy', None)
        self.assertIsNotNone(q)
        self.assertEqual(len(log.calls), 1)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ConditionRegistryRuntimeTest(TransactionTestCase):
    def test_builder_object_list_parity_and_fixed_query(self):
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
            log = _BuilderLog(
                lambda u, p, o: (u == o.owner) & (o.status != 'locked'),
            )
            registry = TrustsRegistry()
            with self.assertNumQueries(0):
                registry.register_permission_condition(Note, 'editable', log)
            self.assertEqual(len(log.calls), 1)
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
            self.assertEqual(len(log.calls), 1)

    def _donate_meta_permission_conditions(self, registry, model):
        """Walk ``Meta.permission_conditions`` the way Zero donates them.

        Idempotent per registry instance so repeated ready() does not
        invoke builders again.
        """
        donated = getattr(registry, '_core_ticket_meta_donation_id', None)
        if donated is registry:
            return False
        for cond_code, condition in (
            getattr(model._meta, 'permission_conditions', ()) or ()
        ):
            registry.register_permission_condition(model, cond_code, condition)
        registry._core_ticket_meta_donation_id = registry
        return True

    def test_ticket_meta_own_donation_is_zero_sql_and_idempotent(self):
        self.assertEqual(
            Ticket._meta.permission_conditions,
            (('meta_own', ticket_meta_own),),
        )
        registry = TrustsRegistry()
        with self.assertNumQueries(0):
            first = self._donate_meta_permission_conditions(registry, Ticket)
        self.assertTrue(first)
        record = registry.get_permission_condition_record(Ticket, 'meta_own')
        self.assertIsNotNone(record)
        self.assertIs(record.model, Ticket)
        self.assertEqual(
            record.expr.to_tuple(),
            ('eq', ('ref', 'principal', ()), ('ref', 'object', ('owner',))),
        )
        with self.assertNumQueries(0):
            second = self._donate_meta_permission_conditions(registry, Ticket)
        self.assertFalse(second)
        self.assertIs(
            registry.get_permission_condition_record(Ticket, 'meta_own'),
            record,
        )

    def test_core_registration_path_is_zero_sql_for_expr_and_builder(self):
        Note, _Memo = _note_models()
        u, _p, o = condition_refs()
        registry = TrustsRegistry()
        with self.assertNumQueries(0):
            registry.register_permission_condition(Note, 'expr', u == o.owner)
        with self.assertNumQueries(0):
            registry.register_permission_condition(
                Note, 'builder', lambda u, p, o: o.status != 'locked',
            )

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

    def test_constant_normalization_is_durable(self):
        Note, _Memo = _note_models()
        User = get_user_model()
        with _tables(Note):
            alice = User.objects.create_user(
                'alice-16n', 'alice-16n@example.com', 'x',
            )
            bob = User.objects.create_user(
                'bob-16n', 'bob-16n@example.com', 'x',
            )
            note = Note.objects.create(title='n', owner=alice, status='open')
            captured = alice
            registry = TrustsRegistry()
            with self.assertNumQueries(0):
                record = registry.register_permission_condition(
                    Note, 'owner_is', lambda u, p, o: o.owner == captured,
                )
            const = record.expr.right
            self.assertIsInstance(const.value, ModelIdentity)
            self.assertEqual(
                const.value.as_tuple(),
                (alice._meta.app_label, alice._meta.model_name, alice.pk),
            )
            alice.username = 'mutated'
            alice.save(update_fields=['username'])
            self.assertTrue(
                registry.evaluate_permission_condition(
                    Note, 'owner_is', bob, 'trusts_tests.change_note', note,
                )
            )
            captured = bob
            self.assertTrue(
                registry.evaluate_permission_condition(
                    Note, 'owner_is', bob, 'trusts_tests.change_note', note,
                )
            )

    def test_forbidden_captures_rejected_at_register(self):
        Note, _Memo = _note_models()
        User = get_user_model()
        unsaved = User(username='ghost-16', email='ghost-16@example.com')
        registry = TrustsRegistry()
        with self.assertRaises(PermissionConditionError):
            registry.register_permission_condition(
                Note, 'unsaved', lambda u, p, o: o.owner == unsaved,
            )
        with self.assertRaises(PermissionConditionUnsupported):
            registry.register_permission_condition(
                Note, 'qs', lambda u, p, o: o.owner == User.objects.all(),
            )
        with self.assertRaises(PermissionConditionUnsupported):
            registry.register_permission_condition(
                Note, 'list', lambda u, p, o: o.status == ['open'],
            )
        with self.assertRaises(PermissionConditionUnsupported):
            registry.register_permission_condition(
                Note, 'req', lambda u, p, o: o.status == HttpRequest(),
            )
        with self.assertRaises(PermissionConditionUnsupported):
            registry.register_permission_condition(
                Note, 'file', lambda u, p, o: o.status == BytesIO(b'x'),
            )
        with self.assertRaises(PermissionConditionUnsupported):
            registry.register_permission_condition(
                Note, 'fn', lambda u, p, o: o.status == str,
            )
        self.assertIsNone(registry.get_permission_condition_record(Note, 'unsaved'))
        self.assertIsNone(registry.get_permission_condition_record(Note, 'qs'))

    def test_immutable_scalars_are_accepted(self):
        Note, _Memo = _note_models()
        registry = TrustsRegistry()
        record = registry.register_permission_condition(
            Note, 'open', lambda u, p, o: o.status == 'open',
        )
        self.assertEqual(record.expr.right.value, 'open')
        uid = uuid4()
        amount = Decimal('1.5')
        # Construction of unused extras proves as_node accepts the types.
        from trusts.conditions import as_node
        self.assertEqual(as_node(amount).value, amount)
        self.assertEqual(as_node(uid).value, uid)
        self.assertEqual(as_node(None).value, None)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ConditionRegistryCheckTest(SimpleTestCase):
    def test_checks_never_reinvoke_builder(self):
        Note, _Memo = _note_models()
        log = _BuilderLog()
        registry = ConditionRegistry()
        registry.register_permission_condition(Note, 'own', log)
        messages = permission_condition_check_messages(
            registry.iter_permission_conditions()
        )
        self.assertEqual(len(log.calls), 1)
        self.assertEqual(
            [m for m in messages if m.id == CHECK_ID_OBSOLETE_CALLBACK_SETTING],
            [],
        )

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

    def test_builder_unresolved_field_fails_at_register(self):
        Note, _Memo = _note_models()
        registry = ConditionRegistry()
        with self.assertRaises(PermissionConditionError) as ctx:
            registry.register_permission_condition(
                Note, 'missing', lambda u, p, o: u == o.not_a_field,
            )
        self.assertIn('not_a_field', str(ctx.exception))
        self.assertIsNone(registry.get_permission_condition_record(Note, 'missing'))

    def test_obsolete_setting_is_check_error_and_does_not_enable_callbacks(self):
        self.assertFalse(obsolete_legacy_callback_setting_enabled())
        self.assertEqual(check_obsolete_legacy_callback_setting(None), [])
        with override_settings(TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS=True):
            self.assertTrue(obsolete_legacy_callback_setting_enabled())
            messages = check_obsolete_legacy_callback_setting(None)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].id, CHECK_ID_OBSOLETE_CALLBACK_SETTING)
        self.assertIn('does not enable', messages[0].msg)

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
