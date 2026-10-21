"""#16 / #142 Stage A: per-handle condition registry and builders.

Library-only proofs. Does not import Zero nouns. A prebuilt tree is
rejected at registration.
"""
from contextlib import contextmanager
from io import BytesIO
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.checks import Error
from django.db import connection, models
from django.http import HttpRequest
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.utils import timezone
from django.test.utils import isolate_apps
from tests.models import Ticket, ticket_meta_own
from trusts.inspect.checks import CHECK_ID_INVALID_EXPR, CHECK_ID_OBSOLETE_CALLBACK_SETTING, check_obsolete_legacy_callback_setting, check_permission_conditions, iter_live_permission_conditions, permission_condition_check_messages
from trusts.conditions import PermissionConditionError
from trusts.plan.conditions import ConditionRecord, ConditionRegistry, FrozenConditionLookup, ModelIdentity, obsolete_legacy_callback_setting_enabled
from trusts.plan.grammar import Tree

from tests.support import built_catalog, override_catalog, compiler

def _store_expr(registry, model, code, expr):
    store = getattr(registry, 'conditions', registry)
    store._records[model._meta.label, code] = ConditionRecord(expr=expr, model=model)

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
    return (Note, Memo)

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

class ConditionRegistryIsolationTest(SimpleTestCase):


    def test_trusts_registry_owns_a_private_condition_store(self):
        left = compiler()
        right = compiler()
        self.assertIsInstance(left.conditions, ConditionRegistry)
        self.assertIsNot(left.conditions, right.conditions)
        self.assertEqual(list(left.conditions.iter_permission_conditions()), [])
        self.assertEqual(list(right.conditions.iter_permission_conditions()), [])

@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ConditionRegistryShapeTest(SimpleTestCase):

    def test_expr_and_builder_records_and_shape_errors(self):
        Note, Memo = _note_models()
        registry = compiler()
        expr = Tree('eq', left=Tree('field', root='user', path=()), right=Tree('field', root='object', path=('owner',)))
        with self.assertRaises(TypeError):
            registry.add_named_filter(Note, 'owned', expr)
        self.assertIsNone(registry.conditions.get_permission_condition_record(Note, 'owned'))
        log = _BuilderLog()
        builder_record = registry.add_named_filter(Note, 'spy', log)
        self.assertIsInstance(builder_record, ConditionRecord)
        self.assertIsNotNone(builder_record.expr)
        self.assertFalse(hasattr(builder_record, 'func'))
        self.assertIs(builder_record.model, Note)
        self.assertEqual(len(log.calls), 1)
        self.assertIsNone(registry.conditions.get_permission_condition_record(Note, 'missing'))
        self.assertIsNone(registry.conditions.get_permission_condition_record(Memo, 'owned'))
        with self.assertRaises(TypeError):
            registry.add_named_filter(Note, 'bare', Tree('field', root='object', path=('owner',)))
        with self.assertRaises(TypeError):
            registry.add_named_filter(Note, 'bad', 'not-a-condition')
        self.assertEqual(len(log.calls), 1)

    def test_duplicate_condition_fails_and_keeps_the_first(self):
        Note, _Memo = _note_models()
        registry = compiler()
        calls = []

        def second(u, p, o):
            calls.append(1)
            return o.title == 'keep'

        registry.add_named_filter(Note, 'named', lambda u, p, o: u == o.owner)
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(Note, 'named', second)
        self.assertEqual(calls, [])
        q = registry.conditions.compile_registered_condition_q(
            Note, 'trusts_tests.change_note:named', get_user_model()(pk=1),
        )
        self.assertIn('owner', str(q))
        self.assertNotIn('keep', str(q))
        rows = list(registry.conditions.iter_permission_conditions())
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], 'named')

    def test_owners_do_not_share_or_overwrite_records(self):
        Note, _Memo = _note_models()
        owner_a = compiler()
        owner_b = compiler()
        owner_a.add_named_filter(Note, 'own', lambda u, p, o: u == o.owner)
        owner_b.add_named_filter(Note, 'own', lambda u, p, o: o.title == 'keep')
        qa = owner_a.conditions.compile_registered_condition_q(
            Note, 'trusts_tests.change_note:own', get_user_model()(pk=1),
        )
        qb = owner_b.conditions.compile_registered_condition_q(
            Note, 'trusts_tests.change_note:own', None,
        )
        self.assertIn('owner', str(qa))
        self.assertIn('keep', str(qb))
        self.assertIsNot(owner_a.conditions.get_permission_condition_record(Note, 'own'), owner_b.conditions.get_permission_condition_record(Note, 'own'))

    def test_repeated_registry_construction_does_not_leak(self):
        Note, _Memo = _note_models()
        first = compiler()
        first.add_named_filter(Note, 'own', lambda u, p, o: u == o.owner)
        self.assertIsNotNone(first.conditions.get_permission_condition_record(Note, 'own'))
        second = compiler()
        self.assertIsNone(second.conditions.get_permission_condition_record(Note, 'own'))
        self.assertEqual(list(second.conditions.iter_permission_conditions()), [])
        third = ConditionRegistry()
        self.assertIsNone(third.get_permission_condition_record(Note, 'own'))

    def test_condition_registration_after_build_invokes_builder(self):
        Note, _Memo = _note_models()
        log = _BuilderLog()
        registry = compiler()
        record = registry.add_named_filter(Note, 'own', log)
        self.assertEqual(len(log.calls), 1)
        self.assertIs(registry.conditions.get_permission_condition_record(Note, 'own'), record)
        catalog = built_catalog(registry)
        self.assertIs(catalog.get_permission_condition_record(Note, 'own'), record)
        self.assertIs(catalog.filter_lookup.record_for(Note, 'own'), record)
        self.assertFalse(hasattr(catalog.filter_lookup, 'conditions'))

    def test_generic_lookup_binds_without_reinvoking_builder(self):
        Note, _Memo = _note_models()
        registry = compiler()
        log = _BuilderLog()
        record = registry.add_named_filter(Note, 'spy', log)
        self.assertEqual(len(log.calls), 1)
        catalog = built_catalog(registry)
        lookup = catalog.filter_lookup
        self.assertIsInstance(lookup, FrozenConditionLookup)
        self.assertIs(lookup.record_for(Note, 'spy'), record)
        self.assertFalse(hasattr(lookup, 'conditions'))
        q = lookup.compile_q(Note, 'trusts_tests.change_note:spy', None, get_user_model())
        self.assertIsNotNone(q)
        self.assertEqual(len(log.calls), 1)

@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ConditionRegistryRuntimeTest(TransactionTestCase):

    def test_builder_object_list_parity_and_fixed_query(self):
        Note, _Memo = _note_models()
        User = get_user_model()
        with _tables(Note):
            alice = User.objects.create_user('alice-16', 'alice-16@example.com', 'x')
            bob = User.objects.create_user('bob-16', 'bob-16@example.com', 'x')
            keep = Note.objects.create(title='keep', owner=alice, status='open')
            drop = Note.objects.create(title='drop', owner=bob, status='open')
            locked = Note.objects.create(title='keep', owner=alice, status='locked')
            log = _BuilderLog(lambda u, p, o: (u == o.owner) & (o.status != 'locked'))
            registry = compiler()
            with self.assertNumQueries(0):
                registry.add_named_filter(Note, 'editable', log)
            self.assertEqual(len(log.calls), 1)
            perm = 'trusts_tests.change_note:editable'
            q = registry.conditions.compile_registered_condition_q(Note, perm, alice)
            listed = set(Note.objects.filter(q).values_list('pk', flat=True))
            self.assertEqual(listed, {keep.pk})
            self.assertNotIn(drop.pk, listed)
            self.assertNotIn(locked.pk, listed)
            sql = str(Note.objects.filter(q).query)
            self.assertIn('owner', sql.lower())
            self.assertIn('status', sql.lower())
            self.assertEqual(len(log.calls), 1)

    def test_ticket_meta_own_registers_through_the_recorder(self):
        registry = compiler()
        with self.assertNumQueries(0):
            record = registry.add_named_filter(
                Ticket, 'meta_own', ticket_meta_own,
            )
        self.assertIs(record.model, Ticket)
        q = registry.conditions.compile_registered_condition_q(
            Ticket, 'tests.change_ticket:meta_own', get_user_model()(pk=1),
        )
        self.assertIn('owner', str(q))

    def test_core_registration_path_is_zero_sql_for_builder(self):
        Note, _Memo = _note_models()
        registry = compiler()
        with self.assertNumQueries(0):
            registry.add_named_filter(Note, 'builder', lambda u, p, o: o.status != 'locked')

    def test_unknown_malformed_and_unbound_fail_closed(self):
        Note, _Memo = _note_models()
        User = get_user_model()
        with _tables(Note):
            alice = User.objects.create_user('alice-16u', 'alice-16u@example.com', 'x')
            typo = Tree('eq', left=Tree('field', root='user', path=()), right=Tree('field', root='object', path=('nope',)))
            registry = compiler()
            with self.assertRaises(AttributeError) as missing:
                registry.conditions.compile_registered_condition_q(Note, 'trusts_tests.change_note:missing', alice)
            self.assertIn('missing', str(missing.exception))
            with self.assertRaises(TypeError):
                registry.add_named_filter(Note, 'typo', typo)
            _store_expr(registry, Note, 'typo', typo)
            with self.assertRaises(PermissionConditionError) as typo:
                registry.conditions.compile_registered_condition_q(Note, 'trusts_tests.change_note:typo', alice)
            self.assertIn('nope', str(typo.exception))
            empty = ConditionRecord(model=Note)
            registry.conditions._records[Note._meta.label, 'empty'] = empty
            with self.assertRaises(PermissionConditionError) as unbound:
                registry.conditions.compile_registered_condition_q(Note, 'trusts_tests.change_note:empty', alice)
            self.assertIn('unbound', str(unbound.exception))

    def test_constant_normalization_is_durable(self):
        Note, _Memo = _note_models()
        User = get_user_model()
        with _tables(Note):
            alice = User.objects.create_user('alice-16n', 'alice-16n@example.com', 'x')
            bob = User.objects.create_user('bob-16n', 'bob-16n@example.com', 'x')
            note = Note.objects.create(title='n', owner=alice, status='open')
            captured = alice
            registry = compiler()
            with self.assertNumQueries(0):
                record = registry.add_named_filter(Note, 'owner_is', lambda u, p, o: o.owner == captured)
            const = record.expr.right
            self.assertIsInstance(const.value, ModelIdentity)
            self.assertEqual(const.value.as_tuple(), (alice._meta.app_label, alice._meta.model_name, alice.pk))
            alice.username = 'mutated'
            alice.save(update_fields=['username'])
            perm = 'trusts_tests.change_note:owner_is'
            listed = set(Note.objects.filter(
                registry.conditions.compile_registered_condition_q(Note, perm, bob),
            ).values_list('pk', flat=True))
            self.assertEqual(listed, {note.pk})
            captured = bob
            listed_again = set(Note.objects.filter(
                registry.conditions.compile_registered_condition_q(Note, perm, bob),
            ).values_list('pk', flat=True))
            self.assertEqual(listed_again, {note.pk})

    def test_saved_user_constant_matches_only_that_principal(self):
        Note, _Memo = _note_models()
        User = get_user_model()

        class NoteGrant(models.Model):
            note = models.ForeignKey(Note, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with _tables(Note, NoteGrant):
            alice = User.objects.create_user(
                'alice-16id', 'alice-16id@example.com', 'x',
            )
            bob = User.objects.create_user(
                'bob-16id', 'bob-16id@example.com', 'x',
            )
            keep = Note.objects.create(title='keep', owner=alice, status='open')
            other = Note.objects.create(title='other', owner=bob, status='open')
            change = Permission.objects.create(
                content_type=ContentType.objects.get_for_model(Note),
                codename='change_note',
                name='Can change note',
            )
            for holder in (alice, bob):
                for row in (keep, other):
                    NoteGrant.objects.create(
                        note=row, user=holder, permission=change,
                    )
            registry = compiler()
            registry.register(
                trust=NoteGrant,
                user='user',
                permission='permission',
                content='note',
            )
            registry.add_named_filter(
                Note, 'is_alice', lambda u, p, o: u == alice,
            )
            code = 'trusts_tests.change_note:is_alice'
            plain = 'trusts_tests.change_note'
            catalog = built_catalog(registry)
            for holder in (alice, bob):
                for row in (keep, other):
                    self.assertTrue(catalog.has_perm(holder, plain, row))
            self.assertTrue(catalog.has_perm(alice, code, keep))
            self.assertTrue(catalog.has_perm(alice, code, other))
            self.assertFalse(catalog.has_perm(bob, code, keep))
            self.assertFalse(catalog.has_perm(bob, code, other))

    def test_forbidden_captures_rejected_at_register(self):
        Note, _Memo = _note_models()
        User = get_user_model()
        unsaved = User(username='ghost-16', email='ghost-16@example.com')
        registry = compiler()
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(Note, 'unsaved', lambda u, p, o: o.owner == unsaved)
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(Note, 'qs', lambda u, p, o: o.owner == User.objects.all())
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(Note, 'list', lambda u, p, o: o.status == ['open'])
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(Note, 'req', lambda u, p, o: o.status == HttpRequest())
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(Note, 'file', lambda u, p, o: o.status == BytesIO(b'x'))
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(Note, 'fn', lambda u, p, o: o.status == str)
        self.assertIsNone(registry.conditions.get_permission_condition_record(Note, 'unsaved'))
        self.assertIsNone(registry.conditions.get_permission_condition_record(Note, 'qs'))

    def test_immutable_scalars_are_accepted(self):
        Note, _Memo = _note_models()
        registry = compiler()
        registry.add_named_filter(Note, 'open', lambda u, p, o: o.status == 'open')
        self.assertIsNotNone(
            registry.conditions.get_permission_condition_record(Note, 'open'),
        )

@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ConditionRegistryCheckTest(SimpleTestCase):

    def test_checks_never_reinvoke_builder(self):
        Note, _Memo = _note_models()
        log = _BuilderLog()
        registry = ConditionRegistry()
        registry.register_permission_condition(Note, 'own', log, get_user_model())
        messages = permission_condition_check_messages(
            registry.iter_permission_conditions(), get_user_model(),
        )
        self.assertEqual(len(log.calls), 1)
        self.assertEqual([m for m in messages if m.id == CHECK_ID_OBSOLETE_CALLBACK_SETTING], [])

    def test_invalid_stored_ir_is_check_error_not_public_register(self):
        Note, _Memo = _note_models()
        registry = ConditionRegistry()
        expr = Tree('eq', left=Tree('field', root='user', path=()), right=Tree('field', root='object', path=('not_a_field',)))
        with self.assertRaises(TypeError):
            registry.register_permission_condition(Note, 'missing', expr)
        self.assertIsNone(registry.get_permission_condition_record(Note, 'missing'))
        _store_expr(registry, Note, 'missing', expr)
        errors = [m for m in permission_condition_check_messages(
            registry.iter_permission_conditions(), get_user_model(),
        ) if m.id == CHECK_ID_INVALID_EXPR]
        self.assertEqual(len(errors), 1)
        self.assertIsInstance(errors[0], Error)
        self.assertIn('not_a_field', errors[0].msg)

    def test_builder_unresolved_field_fails_at_register(self):
        Note, _Memo = _note_models()
        registry = ConditionRegistry()
        with self.assertRaises(PermissionConditionError) as ctx:
            registry.register_permission_condition(Note, 'missing', lambda u, p, o: u == o.not_a_field)
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

    def test_check_permission_conditions_reads_catalog_registry(self):
        from tests.kernel_host.backends import HostTrustModelBackend

        Note, _Memo = _note_models()
        registry = compiler()
        _store_expr(
            registry, Note, 'typo',
            Tree('eq', left=Tree('field', root='user', path=()), right=Tree('field', root='object', path=('nope',))),
        )

        with override_catalog(
            HostTrustModelBackend, registry,
            'tests.kernel_host.backends.HostTrustModelBackend',
        ):
            messages = check_permission_conditions(None)
        errors = [m for m in messages if m.id == CHECK_ID_INVALID_EXPR]
        self.assertTrue(any(("'typo'" in m.msg for m in errors)))

    def test_two_owners_same_model_code_both_validated(self):
        from tests.kernel_host.backends import HostTrustModelBackend
        from tests.backends import MixinOnlyBackend

        Note, _Memo = _note_models()
        owner_a = compiler()
        owner_b = compiler()
        owner_a.add_named_filter(Note, 'own', lambda u, p, o: u == o.owner)
        _store_expr(
            owner_b, Note, 'own',
            Tree('eq', left=Tree('field', root='user', path=()), right=Tree('field', root='object', path=('nope',))),
        )

        with override_settings(AUTHENTICATION_BACKENDS=(
            'tests.kernel_host.backends.HostTrustModelBackend',
            'tests.backends.MixinOnlyBackend',
        )):
            with override_catalog(
                HostTrustModelBackend, owner_a,
                'tests.kernel_host.backends.HostTrustModelBackend',
            ):
                with override_catalog(
                    MixinOnlyBackend, owner_b,
                    'tests.backends.MixinOnlyBackend',
                ):
                    live = list(iter_live_permission_conditions())
                    messages = check_permission_conditions(None)
        own_rows = [record for model, code, record in live if model is Note and code == 'own']
        self.assertEqual(len(own_rows), 2)
        self.assertEqual(len({id(record.expr) for record in own_rows}), 2)
        errors = [m for m in messages if m.id == CHECK_ID_INVALID_EXPR]
        self.assertTrue(any(("'own'" in m.msg and 'nope' in m.msg for m in errors)))
        self.assertTrue(any((m.obj is Note for m in errors)), 'invalid owner B record must still be reported')


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class FieldNullRuleTest(TransactionTestCase):
    """Two fields never match NULL. A field and a constant follow Python."""

    def test_null_matches_only_a_constant(self):
        User = get_user_model()

        class Pair(models.Model):
            left = models.IntegerField(null=True)
            right = models.IntegerField(null=True)
            owner = models.ForeignKey(
                User, null=True, on_delete=models.CASCADE,
            )
            opened = models.DateTimeField(null=True)

            class Meta:
                app_label = 'trusts_tests'

        class PairGrant(models.Model):
            pair = models.ForeignKey(Pair, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with _tables(Pair, PairGrant):
            alice = User.objects.create_user('alice-null', 'alice-null@example.com', 'x')
            bob = User.objects.create_user('bob-null', 'bob-null@example.com', 'x')
            when = timezone.now().replace(microsecond=0)
            bob.last_login = when
            bob.save(update_fields=['last_login'])
            change = Permission.objects.create(
                content_type=ContentType.objects.get_for_model(Pair),
                codename='change_pair',
                name='Can change pair',
            )
            orphan = Pair.objects.create()
            owned = Pair.objects.create(left=1, right=1, owner=alice)
            differ = Pair.objects.create(left=1, right=2, owner=bob)
            five = Pair.objects.create(left=5, right=5)
            timed = Pair.objects.create(opened=when)
            for row in (orphan, owned, differ, five, timed):
                for holder in (alice, bob):
                    PairGrant.objects.create(pair=row, user=holder, permission=change)
            bob.refresh_from_db()
            timed.refresh_from_db()
            registry = compiler()
            registry.register(
                trust=PairGrant, user='user', permission='permission', content='pair',
            )
            registry.add_named_filter(Pair, 'same', lambda u, p, o: o.left == o.right)
            registry.add_named_filter(Pair, 'differ', lambda u, p, o: o.left != o.right)
            registry.add_named_filter(Pair, 'blank', lambda u, p, o: o.left == None)
            registry.add_named_filter(Pair, 'not_five', lambda u, p, o: o.left != 5)
            registry.add_named_filter(Pair, 'not_owner', lambda u, p, o: u != o.owner)
            registry.add_named_filter(
                Pair, 'login', lambda u, p, o: u.last_login == o.opened,
            )
            catalog = built_catalog(registry)
            prefix = 'trusts_tests.change_pair'

            def holds(code, row):
                return {
                    user.pk
                    for user in (alice, bob)
                    if catalog.has_perm(user, '%s:%s' % (prefix, code), row)
                }

            def listed(code, user):
                compiled = registry.conditions.compile_registered_condition_q(
                    Pair, '%s:%s' % (prefix, code), user,
                )
                return set(Pair.objects.filter(compiled).values_list('pk', flat=True))

            def reverse(row, code):
                return set(catalog.permitted_users(
                    row, '%s:%s' % (prefix, code),
                ).values_list('pk', flat=True))

            self.assertEqual(holds('same', orphan), set())
            self.assertEqual(holds('same', owned), {alice.pk, bob.pk})
            self.assertEqual(holds('differ', orphan), set())
            self.assertEqual(holds('differ', differ), {alice.pk, bob.pk})
            self.assertEqual(holds('blank', orphan), {alice.pk, bob.pk})
            self.assertEqual(holds('blank', owned), set())
            self.assertEqual(holds('not_five', orphan), {alice.pk, bob.pk})
            self.assertEqual(holds('not_five', five), set())
            self.assertEqual(holds('not_owner', orphan), set())
            self.assertEqual(holds('not_owner', owned), {bob.pk})
            self.assertEqual(holds('login', timed), {bob.pk})
            self.assertEqual(holds('login', orphan), set())
            self.assertEqual(listed('same', alice), {owned.pk, five.pk})
            self.assertEqual(listed('differ', alice), {differ.pk})
            self.assertEqual(listed('blank', alice), {orphan.pk, timed.pk})
            self.assertEqual(listed('not_five', alice), {
                orphan.pk, owned.pk, differ.pk, timed.pk,
            })
            self.assertEqual(listed('not_owner', alice), {differ.pk})
            self.assertEqual(listed('not_owner', bob), {owned.pk})
            self.assertEqual(listed('login', alice), set())
            self.assertEqual(listed('login', bob), {timed.pk})
            self.assertEqual(reverse(orphan, 'same'), set())
            self.assertEqual(reverse(orphan, 'blank'), {alice.pk, bob.pk})
            self.assertEqual(reverse(timed, 'login'), {bob.pk})
            self.assertEqual(reverse(orphan, 'login'), set())
            self.assertEqual(reverse(five, 'not_five'), set())
            self.assertEqual(reverse(orphan, 'not_five'), {alice.pk, bob.pk})
