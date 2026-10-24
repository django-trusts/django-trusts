"""#16 / #142 Stage A: per-compiler named filters and builders.

Library-only proofs. Does not import Zero nouns. A prebuilt tree is
rejected at registration. Behavior is has_perm, permitted users, and
add_named_filter.
"""
from contextlib import contextmanager
from io import BytesIO

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.http import HttpRequest
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.test.utils import isolate_apps
from tests.core import kernel_host_listed
from tests.models import Organization, Ticket, ticket_meta_own
from tests.support import built_catalog, compiler, override_catalog
from trusts.backends import policy_document
from trusts.errors import PermissionConditionError
from trusts.inspect.checks import (
    CHECK_ID_OBSOLETE_CALLBACK_SETTING,
    check_obsolete_legacy_callback_setting,
)
from trusts.plan.conditions import obsolete_legacy_callback_setting_enabled
from trusts.plan.grammar import Tree


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


def _grant_model(content, name):
    User = get_user_model()
    meta = type('Meta', (), {'app_label': 'trusts_tests'})
    return type(name, (models.Model,), {
        '__module__': 'tests.core.test_issue16',
        'content': models.ForeignKey(content, on_delete=models.CASCADE),
        'user': models.ForeignKey(User, on_delete=models.CASCADE),
        'permission': models.ForeignKey(Permission, on_delete=models.CASCADE),
        'Meta': meta,
    })


def _change_permission(model, codename):
    permission, _created = Permission.objects.get_or_create(
        content_type=ContentType.objects.get_for_model(model),
        codename=codename,
        defaults={'name': codename},
    )
    return permission


def _row_grant(grant_model, content, user, permission):
    return grant_model.objects.create(
        content=content, user=user, permission=permission,
    )


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


def _install(registry, grant_model):
    registry.register(
        trust=grant_model,
        user='user',
        permission='permission',
        content='content',
    )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class NamedFilterIsolationTest(SimpleTestCase):

    def test_compilers_do_not_share_named_filters(self):
        Note, Memo = _note_models()
        left = compiler()
        right = compiler()
        left.add_named_filter(Note, 'own', lambda u, p, o: u == o.owner)
        right.add_named_filter(Note, 'own', lambda u, p, o: o.title == 'keep')
        with self.assertRaises(PermissionConditionError):
            left.add_named_filter(Note, 'own', lambda u, p, o: o.status == 'open')
        right.add_named_filter(Memo, 'own', lambda u, p, o: o.title == 'keep')


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class NamedFilterRegistrationTest(SimpleTestCase):

    def test_builder_runs_once_and_prebuilt_trees_are_rejected(self):
        Note, _Memo = _note_models()
        registry = compiler()
        expr = Tree(
            'eq',
            left=Tree('field', root='user', path=()),
            right=Tree('field', root='object', path=('owner',)),
        )
        with self.assertRaises(TypeError):
            registry.add_named_filter(Note, 'owned', expr)
        registry.add_named_filter(Note, 'owned', lambda u, p, o: u == o.owner)
        log = _BuilderLog()
        tree = registry.add_named_filter(Note, 'spy', log)
        self.assertIsInstance(tree, Tree)
        self.assertEqual(len(log.calls), 1)
        with self.assertRaises(TypeError):
            registry.add_named_filter(Note, 'bare', expr)
        with self.assertRaises(TypeError):
            registry.add_named_filter(Note, 'bad', 'not-a-condition')
        self.assertEqual(len(log.calls), 1)
        built_catalog(registry)
        self.assertEqual(len(log.calls), 1)

    def test_a_new_compiler_does_not_keep_the_previous_filter(self):
        Note, _Memo = _note_models()
        first = compiler()
        first.add_named_filter(Note, 'own', lambda u, p, o: u == o.owner)
        second = compiler()
        second.add_named_filter(Note, 'own', lambda u, p, o: o.title == 'keep')


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class NamedFilterRuntimeTest(TransactionTestCase):

    def test_has_perm_and_permitted_users_agree(self):
        Note, _Memo = _note_models()
        Grant = _grant_model(Note, 'EditableGrant')
        User = get_user_model()
        with _tables(Note, Grant):
            alice = User.objects.create_user(
                'alice-16', 'alice-16@example.com', 'x',
            )
            bob = User.objects.create_user('bob-16', 'bob-16@example.com', 'x')
            keep = Note.objects.create(title='keep', owner=alice, status='open')
            drop = Note.objects.create(title='drop', owner=bob, status='open')
            locked = Note.objects.create(
                title='keep', owner=alice, status='locked',
            )
            change = _change_permission(Note, 'change_note')
            for holder in (alice, bob):
                for row in (keep, drop, locked):
                    _row_grant(Grant, row, holder, change)
            log = _BuilderLog(
                lambda u, p, o: (u == o.owner) & (o.status != 'locked'),
            )
            registry = compiler()
            _install(registry, Grant)
            with self.assertNumQueries(0):
                registry.add_named_filter(Note, 'editable', log)
            self.assertEqual(len(log.calls), 1)
            catalog = built_catalog(registry)
            code = 'trusts_tests.change_note:editable'
            plain = 'trusts_tests.change_note'
            self.assertTrue(catalog.has_perm(alice, plain, locked))
            self.assertTrue(catalog.has_perm(alice, code, keep))
            self.assertFalse(catalog.has_perm(alice, code, drop))
            self.assertFalse(catalog.has_perm(alice, code, locked))
            self.assertFalse(catalog.has_perm(bob, code, keep))
            self.assertTrue(catalog.has_perm(bob, code, drop))
            keep_users = set(catalog.permitted_users(
                keep, code,
            ).values_list('pk', flat=True))
            locked_users = set(catalog.permitted_users(
                locked, code,
            ).values_list('pk', flat=True))
            self.assertEqual(keep_users, {alice.pk})
            self.assertEqual(locked_users, set())
            self.assertEqual(len(log.calls), 1)

    def test_ticket_meta_own_agrees_on_has_perm(self):
        if any(field.name == 'trust' for field in Ticket._meta.concrete_fields):
            self.skipTest(
                'pair Ticket subclasses Content and this fixture is the plain model'
            )
        User = get_user_model()

        class TicketGrant(models.Model):
            ticket = models.ForeignKey(Ticket, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        with _tables(TicketGrant):
            alice = User.objects.create_user(
                'alice-16t', 'alice-16t@example.com', 'x',
            )
            bob = User.objects.create_user(
                'bob-16t', 'bob-16t@example.com', 'x',
            )
            org = Organization.objects.create(name='org', manager=alice)
            keep = Ticket.objects.create(
                title='keep', owner=alice, organization=org,
            )
            other = Ticket.objects.create(
                title='other', owner=bob, organization=org,
            )
            change = _change_permission(Ticket, 'change_ticket')
            for holder in (alice, bob):
                for row in (keep, other):
                    TicketGrant.objects.create(
                        ticket=row, user=holder, permission=change,
                    )
            registry = compiler()
            registry.register(
                trust=TicketGrant,
                user='user',
                permission='permission',
                content='ticket',
            )
            with self.assertNumQueries(0):
                registry.add_named_filter(Ticket, 'meta_own', ticket_meta_own)
            catalog = built_catalog(registry)
            code = 'trusts_tests.change_ticket:meta_own'
            self.assertTrue(catalog.has_perm(alice, code, keep))
            self.assertFalse(catalog.has_perm(bob, code, keep))
            self.assertTrue(catalog.has_perm(bob, code, other))
            self.assertEqual(
                set(catalog.permitted_users(keep, code).values_list(
                    'pk', flat=True,
                )),
                {alice.pk},
            )

    def test_core_registration_path_is_zero_sql_for_builder(self):
        Note, _Memo = _note_models()
        registry = compiler()
        with self.assertNumQueries(0):
            registry.add_named_filter(
                Note, 'builder', lambda u, p, o: o.status != 'locked',
            )

    def test_unknown_code_denies_and_a_prebuilt_tree_is_rejected(self):
        Note, _Memo = _note_models()
        Grant = _grant_model(Note, 'UnknownGrant')
        User = get_user_model()
        with _tables(Note, Grant):
            alice = User.objects.create_user(
                'alice-16u', 'alice-16u@example.com', 'x',
            )
            keep = Note.objects.create(title='keep', owner=alice, status='open')
            change = _change_permission(Note, 'change_note')
            _row_grant(Grant, keep, alice, change)
            registry = compiler()
            _install(registry, Grant)
            typo = Tree(
                'eq',
                left=Tree('field', root='user', path=()),
                right=Tree('field', root='object', path=('nope',)),
            )
            with self.assertRaises(TypeError):
                registry.add_named_filter(Note, 'typo', typo)
            registry.add_named_filter(
                Note, 'typo', lambda u, p, o: o.status == 'open',
            )
            catalog = built_catalog(registry)
            self.assertTrue(catalog.has_perm(
                alice, 'trusts_tests.change_note', keep,
            ))
            self.assertFalse(catalog.has_perm(
                alice, 'trusts_tests.change_note:missing', keep,
            ))
            self.assertTrue(catalog.has_perm(
                alice, 'trusts_tests.change_note:typo', keep,
            ))

    def test_constant_normalization_is_durable(self):
        Note, _Memo = _note_models()
        Grant = _grant_model(Note, 'ConstantGrant')
        User = get_user_model()
        with _tables(Note, Grant):
            alice = User.objects.create_user(
                'alice-16n', 'alice-16n@example.com', 'x',
            )
            bob = User.objects.create_user(
                'bob-16n', 'bob-16n@example.com', 'x',
            )
            note = Note.objects.create(title='n', owner=alice, status='open')
            other = Note.objects.create(title='o', owner=bob, status='open')
            change = _change_permission(Note, 'change_note')
            for holder in (alice, bob):
                for row in (note, other):
                    _row_grant(Grant, row, holder, change)
            captured = alice
            registry = compiler()
            _install(registry, Grant)
            with self.assertNumQueries(0):
                registry.add_named_filter(
                    Note, 'owner_is', lambda u, p, o: o.owner == captured,
                )
            alice.username = 'mutated'
            alice.save(update_fields=['username'])
            captured = bob
            catalog = built_catalog(registry)
            code = 'trusts_tests.change_note:owner_is'
            self.assertTrue(catalog.has_perm(bob, code, note))
            self.assertFalse(catalog.has_perm(bob, code, other))
            self.assertTrue(catalog.has_perm(
                bob, code, Note.objects.filter(pk=note.pk),
            ))
            self.assertFalse(catalog.has_perm(
                bob, code, Note.objects.filter(pk=other.pk),
            ))

    def test_saved_user_constant_matches_only_that_principal(self):
        Note, _Memo = _note_models()
        Grant = _grant_model(Note, 'IdentityGrant')
        User = get_user_model()
        with _tables(Note, Grant):
            alice = User.objects.create_user(
                'alice-16id', 'alice-16id@example.com', 'x',
            )
            bob = User.objects.create_user(
                'bob-16id', 'bob-16id@example.com', 'x',
            )
            keep = Note.objects.create(title='keep', owner=alice, status='open')
            other = Note.objects.create(title='other', owner=bob, status='open')
            change = _change_permission(Note, 'change_note')
            for holder in (alice, bob):
                for row in (keep, other):
                    _row_grant(Grant, row, holder, change)
            registry = compiler()
            _install(registry, Grant)
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
            self.assertEqual(
                set(catalog.permitted_users(keep, code).values_list(
                    'pk', flat=True,
                )),
                {alice.pk},
            )

    def test_forbidden_captures_rejected_at_register(self):
        Note, _Memo = _note_models()
        User = get_user_model()
        unsaved = User(username='ghost-16', email='ghost-16@example.com')
        registry = compiler()
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(
                Note, 'unsaved', lambda u, p, o: o.owner == unsaved,
            )
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(
                Note, 'qs', lambda u, p, o: o.owner == User.objects.all(),
            )
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(
                Note, 'list', lambda u, p, o: o.status == ['open'],
            )
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(
                Note, 'req', lambda u, p, o: o.status == HttpRequest(),
            )
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(
                Note, 'file', lambda u, p, o: o.status == BytesIO(b'x'),
            )
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(
                Note, 'fn', lambda u, p, o: o.status == str,
            )
        registry.add_named_filter(
            Note, 'unsaved', lambda u, p, o: o.status == 'open',
        )
        registry.add_named_filter(
            Note, 'qs', lambda u, p, o: o.status == 'open',
        )

    def test_immutable_scalars_are_accepted(self):
        Note, _Memo = _note_models()
        registry = compiler()
        registry.add_named_filter(
            Note, 'open', lambda u, p, o: o.status == 'open',
        )
        with self.assertRaises(PermissionConditionError):
            registry.add_named_filter(
                Note, 'open', lambda u, p, o: o.status == 'closed',
            )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class NamedFilterCheckTest(SimpleTestCase):

    def test_builder_unresolved_field_fails_at_register(self):
        Note, _Memo = _note_models()
        registry = compiler()
        with self.assertRaises(PermissionConditionError) as ctx:
            registry.add_named_filter(
                Note, 'missing', lambda u, p, o: u == o.not_a_field,
            )
        self.assertIn('not_a_field', str(ctx.exception))
        registry.add_named_filter(Note, 'missing', lambda u, p, o: u == o.owner)

    def test_obsolete_setting_is_check_error_and_does_not_enable_callbacks(self):
        self.assertFalse(obsolete_legacy_callback_setting_enabled())
        self.assertEqual(check_obsolete_legacy_callback_setting(None), [])
        with override_settings(TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS=True):
            self.assertTrue(obsolete_legacy_callback_setting_enabled())
            messages = check_obsolete_legacy_callback_setting(None)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].id, CHECK_ID_OBSOLETE_CALLBACK_SETTING)
        self.assertIn('does not enable', messages[0].msg)

    def test_two_catalogs_keep_distinct_filters_for_one_code(self):
        if not kernel_host_listed():
            self.skipTest('kernel-only host path is not listed on the pair')
        from tests.backends import MixinOnlyBackend
        from tests.kernel_host.backends import HostTrustModelBackend

        Note, _Memo = _note_models()
        owner_a = compiler()
        owner_b = compiler()
        owner_a.add_named_filter(Note, 'own', lambda u, p, o: u == o.owner)
        owner_b.add_named_filter(Note, 'own', lambda u, p, o: o.title == 'keep')
        with override_catalog(
            HostTrustModelBackend, owner_a,
            'tests.kernel_host.backends.HostTrustModelBackend',
        ):
            with override_catalog(
                MixinOnlyBackend, owner_b,
                'tests.backends.MixinOnlyBackend',
            ):
                document = policy_document()
        own_sql = [
            named['sql']
            for row in document['backends']
            for content in row['contents']
            for named in content.get('named_filters', ())
            if named['id'] == 'trusts_tests__Note__own'
        ]
        self.assertEqual(len(own_sql), 2)
        self.assertEqual(len(set(own_sql)), 2)
