"""Unknown stays unknown until the grant.

``Exists(path)`` is true only when the row that owns the field was
joined, including when that column is NULL, and false for a missing or
dangling foreign key. ``== None`` is true only for a stored NULL on a
reached row. ``!= None`` is that test negated. A NULL operand under an
ordinary comparison does not grant. Collection membership is the join
it already was: one member is enough, and an empty collection is not.
"""
from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import connection, models
from django.http import HttpResponse
from django.test import RequestFactory, TransactionTestCase, override_settings
from django.test.utils import isolate_apps

from tests.support import compiler, published_class_catalog
from trusts.backends import TrustModelBackendMixin
from trusts.decorators import authorization_required
from trusts.errors import PermissionConditionError
from trusts.functions import Exists
from trusts.models import PermittedQuerySet, PermittedUsersMixin
from trusts.plan.grammar import Tree
from trusts.plan.trivalent import (
    Operand,
    _unwrap,
    compare,
    exists_operand,
    field_operand,
    grant_q,
    lower,
    Scope,
)

PERM = 'trusts_tests.change_unkdesk'
BACKEND = 'tests.core.test_unknown._DeskBackend'
DANGLING_ID = 2147483647


class _DeskBackend(TrustModelBackendMixin, ModelBackend):
    pass


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


def _models():
    User = get_user_model()

    class Room(models.Model):
        name = models.CharField(max_length=20, null=True)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'unk_room'

    class Tag(models.Model):
        name = models.CharField(max_length=20, null=True)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'unk_tag'

    class Desk(PermittedUsersMixin, models.Model):
        objects = models.Manager.from_queryset(PermittedQuerySet)()
        label = models.CharField(max_length=20, null=True)
        flag = models.BooleanField(null=True)
        room = models.ForeignKey(
            Room, null=True, db_constraint=False, on_delete=models.DO_NOTHING,
            related_name='desks',
        )
        tags = models.ManyToManyField(Tag, blank=True, related_name='desks')

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'unk_desk'

    class Note(models.Model):
        desk = models.ForeignKey(
            Desk, on_delete=models.CASCADE, related_name='notes',
        )
        body = models.CharField(max_length=20, null=True)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'unk_note'

    class DeskGrant(models.Model):
        desk = models.ForeignKey(Desk, on_delete=models.CASCADE)
        user = models.ForeignKey(
            User, on_delete=models.CASCADE, related_name='+',
        )
        permission = models.ForeignKey(
            Permission, on_delete=models.CASCADE, related_name='+',
        )

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'unk_grant'

    return Room, Tag, Desk, Note, DeskGrant


def _field(path):
    return Tree('field', root='object', path=path)


def _const(value):
    return Tree('const', value=value)


def _cmp(kind, path, value):
    return Tree(kind, left=_field(path), right=_const(value))


def _exists(path):
    return Tree('exists', item=_field(path))


def _bindings(model):
    return {'object': ('alias', model, ())}


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class UnknownLoweringTests(TransactionTestCase):
    """The expression module and the grant boundary agree on one connection."""

    def test_reached_null_missing_and_dangling(self):
        Room, _Tag, Desk, _Note, _Grant = _models()
        with _tables(Room, _Tag, Desk):
            blank = Room.objects.create(name=None)
            kept = Room.objects.create(name='kept')
            other = Room.objects.create(name='other')
            stored = Desk.objects.create(label=None, flag=None, room=blank)
            named = Desk.objects.create(label='yes', flag=False, room=kept)
            differ = Desk.objects.create(label='no', flag=True, room=other)
            missing = Desk.objects.create(label='yes', flag=False, room=None)
            dangling = Desk.objects.create(
                label='yes', flag=None, room_id=DANGLING_ID,
            )
            rows = {
                'stored': stored.pk,
                'named': named.pk,
                'differ': differ.pk,
                'missing': missing.pk,
                'dangling': dangling.pk,
            }

            def expect(node, *names):
                wanted = {rows[name] for name in names}
                quoted = connection.ops.quote_name
                alias = quoted('d')
                scope = Scope(
                    _bindings(Desk), quoted, connection, alias,
                )
                expr = lower(node, scope)
                table = quoted(Desk._meta.db_table)
                sql = 'SELECT %s.%s FROM %s AS %s WHERE %s' % (
                    alias, quoted(Desk._meta.pk.column), table, alias, expr.sql,
                )
                with connection.cursor() as cursor:
                    cursor.execute(sql, tuple(_unwrap(param) for param in expr.params))
                    direct = {row[0] for row in cursor.fetchall()}
                granted = set(Desk.objects.filter(
                    grant_q(node, _bindings(Desk)),
                ).values_list('pk', flat=True))
                self.assertEqual(direct, wanted)
                self.assertEqual(granted, wanted)

            expect(_cmp('eq', ('room', 'name'), None), 'stored')
            expect(_cmp('ne', ('room', 'name'), None), 'named', 'differ')
            expect(_cmp('eq', ('room', 'name'), 'kept'), 'named')
            expect(_cmp('ne', ('room', 'name'), 'kept'), 'differ')
            expect(_exists(('room',)), 'stored', 'named', 'differ')
            expect(_exists(('room', 'name')), 'stored', 'named', 'differ')
            expect(Tree('not', item=_exists(('room',))), 'missing', 'dangling')
            expect(_cmp('eq', ('room',), None), 'missing')
            expect(_cmp('eq', ('label',), None), 'stored')
            expect(_cmp('ne', ('label',), 'yes'), 'differ')
            expect(
                Tree('not', item=Tree('bare', item=_field(('flag',)))),
                'named', 'missing',
            )
            expect(_cmp('ne', ('flag',), True), 'named', 'missing')
            expect(
                Tree(
                    'or',
                    left=_cmp('eq', ('label',), 'yes'),
                    right=_cmp('eq', ('room', 'name'), 'missing'),
                ),
                'named', 'missing', 'dangling',
            )
            expect(
                Tree(
                    'and',
                    left=_cmp('eq', ('label',), 'yes'),
                    right=_cmp('eq', ('room', 'name'), 'kept'),
                ),
                'named',
            )
            coalesce = Tree(
                'eq',
                left=Tree(
                    'call', value='coalesce',
                    item=(_field(('room', 'name')), _const('fallback')),
                ),
                right=_const('fallback'),
            )
            expect(coalesce, 'stored', 'missing', 'dangling')

            quoted = connection.ops.quote_name
            reached = field_operand(
                Desk, ('room', 'name'), ('alias', quoted('d')), quoted,
            )
            none = Operand('(1=0)', (), '(1=1)', (), True)
            derived = compare('ne', reached, none)
            self.assertIn('IS NULL', derived.sql)
            self.assertIn('NOT', derived.sql)
            self.assertNotIn('IS NOT NULL', derived.sql)
            present = exists_operand(
                Desk, ('room',), ('alias', quoted('d')), quoted,
            )
            self.assertIn('EXISTS', present.reached_sql)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class UnknownEntryTests(TransactionTestCase):
    """has_perm, permitted(), get_permitted_users, and the decorator agree."""

    def test_public_checks_and_collection_membership(self):
        User = get_user_model()
        Room, Tag, Desk, Note, DeskGrant = _models()
        filters = {
            'stored_null_name': lambda u, p, o: o.room.name == None,  # noqa: E711
            'ne_none_name': lambda u, p, o: o.room.name != None,  # noqa: E711
            'eq_name': lambda u, p, o: o.room.name == 'kept',
            'ne_name': lambda u, p, o: o.room.name != 'kept',
            'exists_room': lambda u, p, o: Exists(o.room),
            'exists_name': lambda u, p, o: Exists(o.room.name),
            'no_room': lambda u, p, o: ~Exists(o.room),
            'fk_null': lambda u, p, o: o.room == None,  # noqa: E711
            'label_null': lambda u, p, o: o.label == None,  # noqa: E711
            'flag_off': lambda u, p, o: ~o.flag,
            'flag_ne': lambda u, p, o: o.flag != True,  # noqa: E712
            'or_unknown': (
                lambda u, p, o: (o.label == 'yes') | (o.room.name == 'missing')
            ),
            'and_unknown': (
                lambda u, p, o: (o.label == 'yes') & (o.room.name == 'kept')
            ),
        }
        factory = compiler(path=BACKEND)
        for code, builder in filters.items():
            factory.add_named_filter(Desk, code, builder)
        with _tables(Room, Tag, Desk, Note, DeskGrant):
            held = Tag.objects.create(name='held')
            extra = Tag.objects.create(name='extra')
            nameless = Tag.objects.create(name=None)
            held_pk = held.pk
            nameless_pk = nameless.pk
            factory.add_named_filter(
                Desk, 'has_tag',
                lambda u, p, o, tag=held_pk: o.tags.contains(tag),
            )
            factory.add_named_filter(
                Desk, 'or_tag',
                lambda u, p, o, tag=held_pk: (
                    (o.flag != True) | o.tags.contains(tag)  # noqa: E712
                ),
            )
            factory.add_named_filter(
                Desk, 'and_tag',
                lambda u, p, o, tag=held_pk: ~o.flag & o.tags.contains(tag),
            )
            factory.add_named_filter(
                Desk, 'null_tag',
                lambda u, p, o, tag=nameless_pk: o.tags.contains(tag),
            )
            with self.assertRaises(PermissionConditionError) as raised:
                factory.add_named_filter(
                    Desk, 'bad_collection',
                    lambda u, p, o: o.tags.name == 'held',
                )
            self.assertIn('Multi-valued relation', str(raised.exception))
            with self.assertRaises(PermissionConditionError) as raised:
                factory.add_named_filter(
                    Desk, 'bad_reverse',
                    lambda u, p, o: o.notes.body == 'x',
                )
            self.assertIn('Multi-valued relation', str(raised.exception))
            factory.register(
                trust=DeskGrant, user='user', permission='permission',
                content='desk',
            )
            blank = Room.objects.create(name=None)
            kept = Room.objects.create(name='kept')
            other = Room.objects.create(name='other')
            stored = Desk.objects.create(label=None, flag=None, room=blank)
            named = Desk.objects.create(label='yes', flag=False, room=kept)
            differ = Desk.objects.create(label='no', flag=True, room=other)
            missing = Desk.objects.create(label='yes', flag=False, room=None)
            dangling = Desk.objects.create(
                label='yes', flag=None, room_id=DANGLING_ID,
            )
            named.tags.add(held, extra)
            dangling.tags.add(held)
            differ.tags.add(nameless)
            change = Permission.objects.create(
                content_type=ContentType.objects.get_for_model(Desk),
                codename='change_unkdesk',
                name='Can change unk desk',
            )
            alice = User.objects.create_user('alice-unk', password='x')
            bob = User.objects.create_user('bob-unk', password='x')
            desks = (stored, named, differ, missing, dangling)
            for row in desks:
                for holder in (alice, bob):
                    DeskGrant.objects.create(
                        desk=row, user=holder, permission=change,
                    )
            expected = {
                'stored_null_name': {stored.pk},
                'ne_none_name': {named.pk, differ.pk},
                'eq_name': {named.pk},
                'ne_name': {differ.pk},
                'exists_room': {stored.pk, named.pk, differ.pk},
                'exists_name': {stored.pk, named.pk, differ.pk},
                'no_room': {missing.pk, dangling.pk},
                'fk_null': {missing.pk},
                'label_null': {stored.pk},
                'flag_off': {named.pk, missing.pk},
                'flag_ne': {named.pk, missing.pk},
                'or_unknown': {named.pk, missing.pk, dangling.pk},
                'and_unknown': {named.pk},
                'has_tag': {named.pk, dangling.pk},
                'or_tag': {named.pk, missing.pk, dangling.pk},
                'and_tag': {named.pk},
                'null_tag': {differ.pk},
            }
            users = (alice, bob)
            with published_class_catalog(
                _DeskBackend, factory,
            ), override_settings(AUTHENTICATION_BACKENDS=(BACKEND,)):
                for code, wanted in expected.items():
                    filtered = '%s:%s' % (PERM, code)
                    for user in users:
                        with self.subTest(code=code, user=user.username):
                            listed = set(Desk.objects.permitted(
                                PERM, user, conditions=(code,),
                            ).values_list('pk', flat=True))
                            self.assertEqual(listed, wanted)
                            for row in desks:
                                self.assertIs(
                                    user.has_perm(filtered, row),
                                    row.pk in wanted,
                                )
                    for row in desks:
                        with self.subTest(code=code, row=row.pk):
                            found = set(row.get_permitted_users(
                                filtered,
                            ).values_list('pk', flat=True))
                            holders = {user.pk for user in users} if (
                                row.pk in wanted
                            ) else set()
                            self.assertEqual(found, holders)

                @authorization_required(Desk, PERM, conditions=('no_room',))
                def roomless(request, pk):
                    return HttpResponse('ok')

                request = RequestFactory().get('/')
                request.user = alice
                self.assertEqual(
                    roomless(request, pk=dangling.pk).status_code, 200,
                )
                with self.assertRaises(PermissionDenied):
                    roomless(request, pk=stored.pk)
