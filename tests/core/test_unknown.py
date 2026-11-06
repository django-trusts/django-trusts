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
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import connection, models
from django.http import HttpResponse
from django.test import RequestFactory, TransactionTestCase, override_settings
from django.test.utils import isolate_apps

from tests.support import compiler, published_class_catalog
from trusts.backends import TrustModelBackendMixin
from trusts.decorators import authorization_required, filter_by_permitted_content
from trusts.errors import PermissionConditionError, TrustsConfigurationError
from trusts.functions import Exists, Lower
from trusts.models import (
    AuthorizedQuerySet,
    PermittedQuerySet,
    PermittedQuerySetMixin,
    PermittedUsersMixin,
)
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

    def test_reachable_shapes_the_suite_had_not_executed(self):
        """Public shapes that the rest of the suite never built.

        A reverse one-to-one is a hop for ``Exists`` and not a stored
        NULL. A permission codename and app label are the string carried
        into the grant. A function on the left takes the right-hand
        field's export hint. ``Exists`` rejects a non-path. A relation
        condition may be ``Exists(row.field)``.
        """
        User = get_user_model()
        Room, _Tag, Desk, _Note, DeskGrant = _models()

        class Card(models.Model):
            desk = models.OneToOneField(
                Desk, related_name='card', on_delete=models.CASCADE,
            )
            unit = models.CharField(max_length=20, null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'unk_card'

        factory = compiler(path='tests.core.test_unknown.gaps')
        factory.add_named_filter(
            Desk, 'has_card', lambda u, p, o: Exists(o.card),
        )
        factory.add_named_filter(
            Desk, 'has_unit', lambda u, p, o: Exists(o.card.unit),
        )
        factory.add_named_filter(
            Desk, 'app_label',
            lambda u, p, o: p.app_label == 'trusts_tests',
        )
        factory.add_named_filter(
            Desk, 'codename',
            lambda u, p, o: p.codename == 'change_unkdesk',
        )
        factory.add_named_filter(
            Desk, 'other_code',
            lambda u, p, o: p.codename == 'missing',
        )
        factory.add_named_filter(
            Desk, 'lower_room',
            lambda u, p, o: Lower(o.label) == o.room.name,
        )
        factory.add_named_filter(
            Desk, 'card_null', lambda u, p, o: o.card == None,  # noqa: E711
        )
        with self.assertRaises(PermissionConditionError):
            factory.add_named_filter(
                Desk, 'bad_exists', lambda u, p, o: Exists(o),
            )
        relation = compiler(path='tests.core.test_unknown.relation')
        relation.register(
            trust=DeskGrant, user='user', permission='permission',
            content='desk',
            condition=lambda row: Exists(row.desk),
        )
        self.assertEqual(len(relation.records), 1)
        factory.register(
            trust=DeskGrant, user='user', permission='permission',
            content='desk',
        )
        with _tables(Room, _Tag, Desk, Card, DeskGrant):
            kept = Room.objects.create(name='kept')
            other = Room.objects.create(name='other')
            matched = Desk.objects.create(label='Kept', room=kept)
            differ = Desk.objects.create(label='no', room=other)
            blank = Desk.objects.create(label=None, room=kept)
            Card.objects.create(desk=matched, unit=None)
            change = Permission.objects.create(
                content_type=ContentType.objects.get_for_model(Desk),
                codename='change_unkdesk',
                name='Can change unk desk',
            )
            alice = User.objects.create_user('alice-gap', password='x')
            for row in (matched, differ, blank):
                DeskGrant.objects.create(
                    desk=row, user=alice, permission=change,
                )
            expected = {
                'has_card': {matched.pk},
                'has_unit': {matched.pk},
                'app_label': {matched.pk, differ.pk, blank.pk},
                'codename': {matched.pk, differ.pk, blank.pk},
                'other_code': set(),
                'lower_room': {matched.pk},
            }
            with published_class_catalog(
                _DeskBackend, factory,
            ), override_settings(AUTHENTICATION_BACKENDS=(BACKEND,)):
                for code, wanted in expected.items():
                    listed = set(Desk.objects.permitted(
                        PERM, alice, conditions=(code,),
                    ).values_list('pk', flat=True))
                    self.assertEqual(listed, wanted, code)
                with self.assertRaises(PermissionConditionError) as raised:
                    alice.has_perm('%s:card_null' % PERM, matched)
                self.assertIn('Cannot push condition path', str(raised.exception))


class _ParityBackend(TrustModelBackendMixin, ModelBackend):
    pass


def _add_column(test, model, name, field):
    model.add_to_class(name, field)
    stored = model._meta.get_field(name)
    with connection.schema_editor() as editor:
        editor.add_field(model, stored)

    def detach():
        column = stored.column
        with connection.cursor() as cursor:
            present = {
                item.name
                for item in connection.introspection.get_table_description(
                    cursor, model._meta.db_table,
                )
            }
            if column in present:
                cursor.execute(
                    'ALTER TABLE %s DROP COLUMN %s' % (
                        connection.ops.quote_name(model._meta.db_table),
                        connection.ops.quote_name(column),
                    )
                )
        meta = model._meta
        if stored in meta.local_fields:
            meta.local_fields.remove(stored)
        meta._expire_cache()
        if hasattr(model, stored.name):
            delattr(model, stored.name)

    test.addCleanup(detach)
    return stored


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class EntryPointParityTests(TransactionTestCase):
    """Every public check answers one three-valued question.

    The via seed and the next walked user use one hop predicate. A
    named filter that mixes a scalar comparison with ``.contains()``
    uses that same predicate. A delegated inquiry comparison keeps the
    old bind and still agrees at the grant.
    """

    def test_via_seed_child_and_mixed_contains_agree(self):
        User = get_user_model()
        _add_column(
            self, User, 'via_manager',
            models.ForeignKey(
                'self', null=True, related_name='parity_reports',
                on_delete=models.DO_NOTHING, db_constraint=False,
                db_index=False,
            ),
        )
        _add_column(
            self, User, 'parity_nick',
            models.CharField(max_length=20, null=True),
        )
        _add_column(
            self, User, 'parity_flag',
            models.BooleanField(null=True),
        )

        class Room(models.Model):
            name = models.CharField(max_length=20, null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'parity_room'

        _add_column(
            self, User, 'parity_room',
            models.ForeignKey(
                Room, null=True, db_constraint=False,
                on_delete=models.DO_NOTHING, related_name='+',
                db_index=False,
            ),
        )

        class Folder(models.Model):
            name = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'parity_folder'

        class TaskQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Task(PermittedUsersMixin, models.Model):
            name = models.CharField(max_length=20)
            folder = models.ForeignKey(
                Folder, related_name='tasks', on_delete=models.CASCADE,
            )
            label = models.CharField(max_length=20, null=True)
            flag = models.BooleanField(null=True)
            room = models.ForeignKey(
                Room, null=True, db_constraint=False,
                on_delete=models.DO_NOTHING, related_name='tasks',
            )
            objects = models.Manager.from_queryset(TaskQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'parity_task'

        class Seat(models.Model):
            holder = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            auth_group = models.ForeignKey(
                Group, on_delete=models.CASCADE, related_name='+',
            )
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'parity_seat'

        with _tables(Room, Folder, Task, Seat):
            kept = Room.objects.create(name='kept')
            blank = Room.objects.create(name=None)
            ada = User.objects.create_user('parity-ada', password='x')
            ben = User.objects.create_user('parity-ben', password='x')
            ben.via_manager = ada
            ben.save()
            folder = Folder.objects.create(name='folder')
            task = Task.objects.create(name='task', folder=folder, label='yes')
            change = Permission.objects.create(
                content_type=ContentType.objects.get_for_model(Task),
                codename='change_paritytask',
                name='Can change parity task',
            )
            group = Group.objects.create(name='parity')
            group.permissions.add(change)
            Seat.objects.create(holder=ada, auth_group=group, folder=folder)
            code = 'trusts_tests.change_paritytask'
            passing = dict(
                parity_nick='kept', parity_flag=False, parity_room=kept,
            )

            def paint(person, values):
                dangling = 'parity_room_id' in values
                for name, value in values.items():
                    if name == 'parity_room_id':
                        continue
                    setattr(person, name, value)
                if dangling:
                    person.parity_room = None
                person.save()
                if dangling:
                    User.objects.filter(pk=person.pk).update(
                        parity_room_id=values['parity_room_id'],
                    )

            user_cases = (
                ('eq-known', lambda user: user.parity_nick == 'kept',
                 passing, dict(parity_nick='kept'), True, True),
                ('eq-null-child', lambda user: user.parity_nick == 'kept',
                 passing, dict(parity_nick=None), True, False),
                ('ne-null-child', lambda user: user.parity_nick != 'stop',
                 passing, dict(parity_nick=None), True, False),
                ('eq-none-both', lambda user: user.parity_nick == None,  # noqa: E711
                 dict(parity_nick=None), dict(parity_nick=None), True, True),
                ('ne-none-child', lambda user: user.parity_nick != None,  # noqa: E711
                 passing, dict(parity_nick=None), True, False),
                ('not-null-child', lambda user: ~user.parity_flag,
                 passing, dict(parity_flag=None), True, False),
                ('exists-dangling-child', lambda user: Exists(user.parity_room),
                 passing, dict(parity_room_id=DANGLING_ID), True, False),
                ('exists-missing-child', lambda user: Exists(user.parity_room),
                 passing, dict(parity_room=None), True, False),
                ('eq-none-dangling', lambda user: user.parity_room.name == None,  # noqa: E711
                 dict(parity_room=blank), dict(parity_room_id=DANGLING_ID),
                 True, False),
                ('eq-none-missing', lambda user: user.parity_room.name == None,  # noqa: E711
                 dict(parity_room=blank), dict(parity_room=None), True, False),
                ('or-true-branch', lambda user: (
                    (user.parity_nick == 'nope') | (user.parity_flag == False)  # noqa: E712
                 ), passing, dict(parity_nick=None, parity_flag=False),
                 True, True),
                ('or-unknown', lambda user: (
                    (user.parity_nick == 'kept') | (user.parity_flag == True)  # noqa: E712
                 ), passing, dict(parity_nick=None, parity_flag=None),
                 True, False),
                ('and-unknown', lambda user: (
                    (user.parity_nick != None) & (user.parity_flag == False)  # noqa: E711, E712
                 ), passing, dict(parity_nick=None, parity_flag=False),
                 True, False),
                ('or-contains', lambda user: (
                    (user.parity_nick == 'kept') | user.groups.contains(group)
                 ), passing, dict(parity_nick=None), True, True),
                ('and-contains', lambda user: (
                    (user.parity_nick != None) & user.groups.contains(group)  # noqa: E711
                 ), passing, dict(parity_nick=None), True, False),
            )
            ada.groups.add(group)
            ben.groups.add(group)
            for label, predicate, ada_values, ben_values, ada_ok, ben_ok in user_cases:
                paint(ada, passing)
                paint(ben, passing)
                paint(ada, ada_values)
                paint(ben, ben_values)
                handle = compiler(path='tests.core.parity-user-%s' % label)
                handle.set_user_condition('called', predicate)
                handle.register(
                    trust=Seat, user='holder', group='auth_group',
                    content='folder__tasks', via=('holder__via_manager', 8),
                )
                with self.subTest(label=label, who='ada'):
                    self._agree(handle, ada, task, folder, change, code, ada_ok)
                with self.subTest(label=label, who='ben'):
                    self._agree(handle, ben, task, folder, change, code, ben_ok)

            task.room = None
            task.flag = None
            task.label = 'yes'
            task.save()
            object_cases = (
                ('obj-eq-none-missing', lambda u, p, o: o.room.name == None,  # noqa: E711
                 dict(room=None, label='yes', flag=False), False),
                ('obj-eq-none-stored', lambda u, p, o: o.room.name == None,  # noqa: E711
                 dict(room=blank, label='yes', flag=False), True),
                ('obj-eq-none-dangling', lambda u, p, o: o.room.name == None,  # noqa: E711
                 dict(room_id=DANGLING_ID, label='yes', flag=False), False),
                ('obj-exists-dangling', lambda u, p, o: Exists(o.room),
                 dict(room_id=DANGLING_ID, label='yes', flag=False), False),
                ('obj-not-exists-dangling', lambda u, p, o: ~Exists(o.room),
                 dict(room_id=DANGLING_ID, label='yes', flag=False), True),
                ('obj-ne-null', lambda u, p, o: o.label != 'yes',
                 dict(room=kept, label=None, flag=False), False),
                ('obj-or-contains', lambda u, p, o: (
                    (o.flag != True) | u.groups.contains(group)  # noqa: E712
                 ), dict(room=kept, label='yes', flag=None), True),
                ('obj-and-contains', lambda u, p, o: (
                    (o.flag != None) & u.groups.contains(group)  # noqa: E711
                 ), dict(room=kept, label='yes', flag=None), False),
            )
            paint(ada, passing)
            paint(ben, passing)
            for label, predicate, task_values, allowed in object_cases:
                dangling = 'room_id' in task_values
                for name, value in task_values.items():
                    if name == 'room_id':
                        continue
                    setattr(task, name, value)
                if dangling:
                    task.room = None
                task.save()
                if dangling:
                    Task.objects.filter(pk=task.pk).update(
                        room_id=task_values['room_id'],
                    )
                # An OR that mentions the user forces both sides into
                # the hop, and the object comparison cannot be written
                # there. An AND keeps the object side on the content
                # overlay and puts only the user side in the hop.
                rejected = label == 'obj-or-contains'
                handle = compiler(path='tests.core.parity-obj-%s' % label)
                handle.set_user_condition(
                    'open', lambda user: user.username != 'nobody',
                )
                handle.add_named_filter(Task, 'kept', predicate)
                handle.register(
                    trust=Seat, user='holder', group='auth_group',
                    content='folder__tasks',
                    **({} if rejected else {
                        'via': ('holder__via_manager', 8),
                    }),
                )
                people = (ada,) if rejected else (ada, ben)
                for person in people:
                    with self.subTest(label=label, who=person.username):
                        self._agree(
                            handle, person, task, folder, change, code,
                            allowed, conditions=('kept',),
                        )
                if rejected:
                    refused = compiler(
                        path='tests.core.parity-via-%s' % label,
                    )
                    refused.set_user_condition(
                        'open', lambda user: user.username != 'nobody',
                    )
                    refused.add_named_filter(Task, 'kept', predicate)
                    with self.subTest(label=label, who='via-rejected'):
                        with self.assertRaises(TrustsConfigurationError):
                            refused.register(
                                trust=Seat, user='holder',
                                group='auth_group',
                                content='folder__tasks',
                                via=('holder__via_manager', 8),
                            )

    def test_inquiry_null_and_contains_agree(self):
        User = get_user_model()

        class Folder(models.Model):
            name = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'parity_inq_folder'

        class TaskQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Task(PermittedUsersMixin, models.Model):
            name = models.CharField(max_length=20)
            folder = models.ForeignKey(
                Folder, related_name='tasks', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(TaskQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'parity_inq_task'

        class Seat(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'parity_inq_seat'

        class Bridge(models.Model):
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
            delegate = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            sponsor = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            perm = models.ForeignKey(
                Permission, null=True, db_constraint=False,
                on_delete=models.DO_NOTHING, related_name='+',
            )
            caps = models.ManyToManyField(Permission, related_name='+')

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'parity_inq_bridge'

        caps = Bridge._meta.get_field('caps')
        if not hasattr(caps, 'm2m_field_name'):
            caps.contribute_to_related_class(Permission, caps.remote_field)
        with _tables(Folder, Task, Seat, Bridge):
            folder = Folder.objects.create(name='folder')
            task = Task.objects.create(name='task', folder=folder)
            change = Permission.objects.create(
                content_type=ContentType.objects.get_for_model(Task),
                codename='change_parityinq',
                name='Can change parity inquiry',
            )
            other = Permission.objects.create(
                content_type=ContentType.objects.get_for_model(Task),
                codename='view_parityinq',
                name='Can view parity inquiry',
            )
            ada = User.objects.create_user('inq-ada', password='x')
            bob = User.objects.create_user('inq-bob', password='x')
            Seat.objects.create(user=ada, permission=change, folder=folder)
            bridge = Bridge.objects.create(
                folder=folder, delegate=bob, sponsor=ada, perm=None,
            )
            code = 'trusts_tests.change_parityinq'
            cases = (
                ('ne-null', lambda row, permission: row.perm != permission,
                 None, False, False),
                ('ne-same', lambda row, permission: row.perm != permission,
                 change, False, False),
                ('ne-other', lambda row, permission: row.perm != permission,
                 other, False, True),
                ('eq-same', lambda row, permission: row.perm == permission,
                 change, False, True),
                ('eq-other', lambda row, permission: row.perm == permission,
                 other, False, False),
                ('eq-none', lambda row, permission: row.perm == None,  # noqa: E711
                 None, False, True),
                ('eq-none-set', lambda row, permission: row.perm == None,  # noqa: E711
                 change, False, False),
                ('eq-none-dangling', lambda row, permission: row.perm == None,  # noqa: E711
                 DANGLING_ID, True, False),
                ('or-contains-null', lambda row, permission: (
                    (row.perm != permission) | row.caps.contains(permission)
                 ), None, True, True),
                ('or-contains-empty', lambda row, permission: (
                    (row.perm != permission) | row.caps.contains(permission)
                 ), None, False, False),
                ('and-contains-null', lambda row, permission: (
                    (row.perm != None) & row.caps.contains(permission)  # noqa: E711
                 ), None, True, False),
            )
            for label, predicate, perm_value, member, allowed in cases:
                if perm_value == DANGLING_ID:
                    bridge.perm_id = DANGLING_ID
                    bridge.perm = None
                    bridge.save()
                    Bridge.objects.filter(pk=bridge.pk).update(perm_id=DANGLING_ID)
                else:
                    bridge.perm = perm_value
                    bridge.save()
                bridge.caps.clear()
                if member:
                    bridge.caps.add(change)
                handle = compiler(path='tests.core.parity-inq-%s' % label)
                handle.register(
                    trust=Seat, user='user', permission='permission',
                    content='folder__tasks',
                )
                handle.register(
                    trust=Bridge, delegate='delegate', sponsor='sponsor',
                    content='folder__tasks', condition=predicate,
                )
                with self.subTest(label=label):
                    self._agree(
                        handle, bob, task, folder, change, code, allowed,
                    )
                    self._agree(
                        handle, ada, task, folder, change, code, True,
                    )

    def _agree(self, handle, user, task, folder, change, code, allowed,
               conditions=()):
        filtered = '%s:%s' % (code, conditions[0]) if conditions else code
        with published_class_catalog(
            _ParityBackend, handle,
        ), override_settings(
            AUTHENTICATION_BACKENDS=('tests.core.test_unknown._ParityBackend',),
        ):
            has = user.has_perm(filtered, task)
            permitted = task.pk in set(task.__class__.objects.permitted(
                code, user, conditions=conditions,
            ).values_list('pk', flat=True))
            reached = task.get_permitted_users(filtered).filter(
                pk=user.pk,
            ).exists()
            folders = folder.pk in set(filter_by_permitted_content(
                folder.__class__.objects.all(), user, change,
                content=task.__class__, conditions=conditions,
            ).values_list('pk', flat=True))

            @authorization_required(
                task.__class__, code, conditions=conditions,
            )
            def guarded(request, pk):
                return HttpResponse('ok')

            request = RequestFactory().get('/')
            request.user = user
            try:
                guarded(request, pk=task.pk)
                decorated = True
            except PermissionDenied:
                decorated = False
        self.assertEqual(
            (has, permitted, reached, folders, decorated),
            (allowed, allowed, allowed, allowed, allowed),
        )
