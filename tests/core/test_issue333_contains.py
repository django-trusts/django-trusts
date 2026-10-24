"""#333: .contains() membership through the public checks.

A NULL member matches nobody. An object collection admits the user who
is a member and leaves the other granted user out. A user rule whose
member is a field uses that field.
"""
from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import TransactionTestCase, override_settings
from django.test.utils import isolate_apps

from trusts.backends import TrustModelBackendMixin
from trusts.models import PermittedQuerySet, PermittedUsersMixin
from tests.support import compiler, published_class_catalog

PERM = 'trusts_tests.change_containnote'
BACKEND = 'tests.core.test_issue333_contains._ContainBackend'


class _ContainBackend(TrustModelBackendMixin, ModelBackend):
    pass


def _models():
    User = get_user_model()

    class ContainMark(models.Model):

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue333_contain_mark'

    class ContainNote(PermittedUsersMixin, models.Model):
        marks = models.ManyToManyField(ContainMark, related_name='+')
        objects = models.Manager.from_queryset(PermittedQuerySet)()

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue333_contain_note'

    class ContainGrant(models.Model):
        note = models.ForeignKey(ContainNote, on_delete=models.CASCADE)
        user = models.ForeignKey(
            User, on_delete=models.CASCADE, related_name='+',
        )
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue333_contain_grant'

    return ContainMark, ContainNote, ContainGrant


def _pks(queryset):
    return set(queryset.values_list('pk', flat=True))


@contextmanager
def _case(configure):
    """Tables, two granted users, then ``configure(factory, note_model)``."""
    User = get_user_model()
    ContainMark, ContainNote, ContainGrant = _models()
    with connection.schema_editor() as editor:
        for model in (ContainMark, ContainNote, ContainGrant):
            editor.create_model(model)
    try:
        alice = User.objects.create_user('alice-contain', password='x')
        bob = User.objects.create_user('bob-contain', password='x')
        own = Group.objects.create(name='own-contain', pk=alice.pk)
        Group.objects.create(name='bob-pk-contain', pk=bob.pk)
        held = Group.objects.create(name='held-contain')
        other = Group.objects.create(name='other-contain')
        alice.groups.add(held, own)
        bob.groups.add(other)
        mark = ContainMark.objects.create(pk=alice.pk)
        change = Permission.objects.get_or_create(
            content_type=ContentType.objects.get_for_model(ContainNote),
            codename='change_containnote',
            defaults={'name': 'Can change contain note'},
        )[0]
        note = ContainNote.objects.create()
        note.marks.add(mark)
        for holder in (alice, bob):
            ContainGrant.objects.create(
                note=note, user=holder, permission=change,
            )
        factory = compiler(path=BACKEND)
        configure(factory, ContainNote, held)
        factory.register(
            trust=ContainGrant, user='user', permission='permission',
            content='note',
        )
        with published_class_catalog(
            _ContainBackend, factory,
        ), override_settings(AUTHENTICATION_BACKENDS=(BACKEND,)):
            yield alice, bob, ContainNote.objects.get(pk=note.pk)
    finally:
        with connection.schema_editor() as editor:
            for model in (ContainGrant, ContainNote, ContainMark):
                editor.delete_model(model)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ContainsMembershipTest(TransactionTestCase):

    def test_permitted_user_collection_skips_null_and_non_members(self):
        def configure(factory, note_model, held):
            factory.add_named_filter(
                note_model, 'held',
                lambda u, p, o, group=held: u.groups.contains(group),
            )
            factory.add_named_filter(
                note_model, 'blank',
                lambda u, p, o: u.groups.contains(None),
            )

        with _case(configure) as (alice, bob, note):
            held_perm = '%s:held' % PERM
            blank_perm = '%s:blank' % PERM
            self.assertEqual(
                _pks(note.__class__.objects.permitted(
                    PERM, alice, conditions=('held',),
                )),
                {note.pk},
            )
            self.assertEqual(
                _pks(note.__class__.objects.permitted(
                    PERM, bob, conditions=('held',),
                )),
                set(),
            )
            self.assertEqual(
                _pks(note.__class__.objects.permitted(
                    PERM, alice, conditions=('blank',),
                )),
                set(),
            )
            self.assertTrue(alice.has_perm(held_perm, note))
            self.assertFalse(bob.has_perm(held_perm, note))
            self.assertFalse(alice.has_perm(blank_perm, note))
            self.assertFalse(bob.has_perm(blank_perm, note))

    def test_reverse_user_collection_skips_null_and_non_members(self):
        def configure(factory, note_model, held):
            factory.add_named_filter(
                note_model, 'held',
                lambda u, p, o, group=held: u.groups.contains(group),
            )
            factory.add_named_filter(
                note_model, 'blank',
                lambda u, p, o: u.groups.contains(None),
            )

        with _case(configure) as (alice, bob, note):
            self.assertEqual(
                _pks(note.get_permitted_users('%s:held' % PERM)),
                {alice.pk},
            )
            self.assertEqual(
                _pks(note.get_permitted_users('%s:blank' % PERM)),
                set(),
            )
            self.assertNotIn(bob.pk, _pks(
                note.get_permitted_users('%s:held' % PERM),
            ))

    def test_reverse_object_collection_keeps_the_user_member(self):
        def configure(factory, note_model, held):
            factory.add_named_filter(
                note_model, 'marked',
                lambda u, p, o: o.marks.contains(u.id),
            )

        with _case(configure) as (alice, bob, note):
            perm = '%s:marked' % PERM
            self.assertEqual(_pks(note.get_permitted_users(perm)), {alice.pk})
            self.assertTrue(alice.has_perm(perm, note))
            self.assertFalse(bob.has_perm(perm, note))
            self.assertEqual(
                _pks(note.__class__.objects.permitted(
                    PERM, alice, conditions=('marked',),
                )),
                {note.pk},
            )
            self.assertEqual(
                _pks(note.__class__.objects.permitted(
                    PERM, bob, conditions=('marked',),
                )),
                set(),
            )

    def test_user_rule_contains_uses_the_field_member(self):
        def configure(factory, note_model, held):
            factory.set_user_condition(
                'own_group', lambda u: u.groups.contains(u.id),
            )

        with _case(configure) as (alice, bob, note):
            self.assertTrue(alice.has_perm(PERM, note))
            self.assertFalse(bob.has_perm(PERM, note))
            self.assertEqual(
                _pks(note.__class__.objects.permitted(PERM, alice)),
                {note.pk},
            )
            self.assertEqual(
                _pks(note.__class__.objects.permitted(PERM, bob)),
                set(),
            )
            self.assertEqual(_pks(note.get_permitted_users(PERM)), {alice.pk})
