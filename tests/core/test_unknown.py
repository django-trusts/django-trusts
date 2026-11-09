"""Unknown stays unknown until the grant.

``Reachable(path)`` is true when the row named by the last relation was
joined. A terminal forward foreign key is followed, so a NULL or dangling
key is false. A path that reaches the evaluator and ends in a column
ignores that column and tests the table that owns it. ``== None`` is true
only for a stored NULL on a reached row. ``!= None`` is that test negated,
and unknown stays unknown under negation. Collection membership is the
join it already was: one member is enough, and an empty collection is
not.
"""
from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.fields import GenericForeignKey
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.db import connection, models
from django.db.models import Value
from django.http import HttpResponse
from django.test import RequestFactory, TransactionTestCase, override_settings
from django.test.utils import CaptureQueriesContext, isolate_apps

from tests.support import compiler, published_class_catalog
from trusts.backends import TrustModelBackendMixin
from trusts.decorators import authorization_required, filter_by_permitted_content
from trusts.errors import PermissionConditionError, TrustsConfigurationError
from trusts.functions import Coalesce, Lower, Reachable
from trusts.plan.grammar import EXISTS_NAME
from trusts.models import (
    AuthorizedQuerySet,
    PermittedQuerySet,
    PermittedQuerySetMixin,
    PermittedUsersMixin,
)
from trusts.plan.grammar import Tree
from trusts.plan.trivalent import (
    GrantPredicate,
    Operand,
    _unwrap,
    compare,
    exists_operand,
    field_operand,
    grant_q,
    lower,
    Scope,
)
from trusts.plan.writers import _filter_bindings, compile_to_q

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

    class Note(PermittedUsersMixin, models.Model):
        objects = models.Manager.from_queryset(PermittedQuerySet)()
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
        self.assertEqual(Reachable.__name__, EXISTS_NAME)
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
            # Reachable(room) follows the key. A NULL or dangling room
            # is false. A column on that path, if one reaches the
            # evaluator, ignores the column and tests the room row.
            # A bare root counts as reached.
            expect(_exists(()), 'stored', 'named', 'differ', 'missing', 'dangling')
            expect(_exists(('room',)), 'stored', 'named', 'differ')
            expect(_exists(('room', 'name')), 'stored', 'named', 'differ')
            expect(
                Tree('not', item=_exists(('room',))),
                'missing', 'dangling',
            )
            expect(
                Tree('not', item=_exists(('room', 'name'))),
                'missing', 'dangling',
            )
            expect(
                Tree('not', item=_cmp('eq', ('room', 'name'), None)),
                'named', 'differ',
            )
            expect(
                Tree('not', item=_cmp('ne', ('room', 'name'), None)),
                'stored',
            )
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
            # The terminal foreign key is followed. NULL and dangling
            # keys produce no room row.
            self.assertIn('EXISTS', present.reached_sql)
            self.assertIn('unk_room', present.reached_sql)
            self.assertNotIn('1=1', present.reached_sql)
            followed = exists_operand(
                Desk, ('room', 'name'), ('alias', quoted('d')), quoted,
            )
            self.assertIn('EXISTS', followed.reached_sql)
            self.assertIn('unk_room', followed.reached_sql)
            root = exists_operand(
                Desk, (), ('alias', quoted('d')), quoted,
            )
            self.assertIn('1=1', root.reached_sql)
            self.assertNotIn('EXISTS', root.reached_sql)


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
            'exists_room': lambda u, p, o: Reachable(o.room),
            'no_room': lambda u, p, o: ~Reachable(o.room),
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

    def test_reachable_follows_a_null_or_dangling_desk(self):
        """Reachable(desk) is the desk row. NULL and dangling keys are false."""
        User = get_user_model()

        class Desk(models.Model):
            label = models.CharField(max_length=20, null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'unk_owned_desk'

        class Room(PermittedUsersMixin, models.Model):
            objects = models.Manager.from_queryset(PermittedQuerySet)()
            desk = models.ForeignKey(
                Desk, null=True, db_constraint=False,
                on_delete=models.DO_NOTHING, related_name='rooms',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'unk_owned_room'

        class RoomGrant(models.Model):
            room = models.ForeignKey(Room, on_delete=models.CASCADE)
            holder = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'unk_owned_grant'

        _add_column(
            self, User, 'via_manager',
            models.ForeignKey(
                'self', null=True, related_name='owned_reports',
                on_delete=models.DO_NOTHING, db_constraint=False,
                db_index=False,
            ),
        )
        factory = compiler(path='tests.core.test_unknown.room-desk')
        factory.add_named_filter(
            Room, 'has_desk', lambda u, p, o: Reachable(o.desk),
        )
        factory.add_named_filter(
            Room, 'no_desk', lambda u, p, o: ~Reachable(o.desk),
        )
        with self.assertRaises(PermissionConditionError) as raised:
            factory.add_named_filter(
                Room, 'desk_label', lambda u, p, o: Reachable(o.desk.label),
            )
        self.assertIn('is a column', str(raised.exception))
        factory.add_named_filter(
            Room, 'label_null', lambda u, p, o: o.desk.label == None,  # noqa: E711
        )
        factory.set_user_condition(
            'open', lambda user: user.username != 'nobody',
        )
        factory.register(
            trust=RoomGrant, user='holder', permission='permission',
            content='room', via=('holder__via_manager', 8),
        )
        code = 'trusts_tests.change_unkownedroom'
        with _tables(Desk, Room, RoomGrant):
            owned = Desk.objects.create(label='kept')
            blank = Desk.objects.create(label=None)
            ada = User.objects.create_user('owned-ada', password='x')
            ben = User.objects.create_user('owned-ben', password='x')
            ben.via_manager = ada
            ben.save()
            null_room = Room.objects.create(desk=None)
            dangling_room = Room.objects.create(desk=None)
            Room.objects.filter(pk=dangling_room.pk).update(
                desk_id=DANGLING_ID,
            )
            linked = Room.objects.create(desk=owned)
            stored_null = Room.objects.create(desk=blank)
            change = Permission.objects.create(
                content_type=ContentType.objects.get_for_model(Room),
                codename='change_unkownedroom',
                name='Can change owned room',
            )
            for room in (null_room, dangling_room, linked, stored_null):
                RoomGrant.objects.create(
                    room=room, holder=ada, permission=change,
                )
            self.assertIsNone(null_room.desk_id)
            questions = (
                ('has_desk', {linked.pk, stored_null.pk}),
                ('no_desk', {null_room.pk, dangling_room.pk}),
                ('label_null', {stored_null.pk}),
            )
            with published_class_catalog(
                _DeskBackend, factory,
            ), override_settings(AUTHENTICATION_BACKENDS=(BACKEND,)):
                for name, wanted in questions:
                    for person in (ada, ben):
                        with self.subTest(name=name, who=person.username):
                            listed = set(Room.objects.permitted(
                                code, person, conditions=(name,),
                            ).values_list('pk', flat=True))
                            self.assertEqual(listed, wanted)
                            for room in (null_room, dangling_room, linked, stored_null):
                                self.assertIs(
                                    person.has_perm('%s:%s' % (code, name), room),
                                    room.pk in wanted,
                                )
                    for room in (null_room, dangling_room, linked, stored_null):
                        with self.subTest(name=name, room=room.pk):
                            found = set(room.get_permitted_users(
                                '%s:%s' % (code, name),
                            ).values_list('pk', flat=True))
                            holders = {ada.pk, ben.pk} if room.pk in wanted else set()
                            self.assertEqual(found, holders)

    def test_reachable_shapes_the_suite_had_not_executed(self):
        """Public shapes that the rest of the suite never built.

        A reverse one-to-one is a hop for ``Reachable`` and not a stored
        NULL. A permission codename and app label are the string carried
        into the grant. A function on the left takes the right-hand
        field's export hint. ``Reachable`` rejects a non-path. A relation
        condition may be ``Reachable(row.desk)``.
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
            Desk, 'has_card', lambda u, p, o: Reachable(o.card),
        )
        with self.assertRaises(PermissionConditionError) as raised:
            factory.add_named_filter(
                Desk, 'has_unit', lambda u, p, o: Reachable(o.card.unit),
            )
        self.assertIn('is a column', str(raised.exception))
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
        with self.assertRaises(PermissionConditionError) as raised:
            factory.add_named_filter(
                Desk, 'card_null', lambda u, p, o: o.card == None,  # noqa: E711
            )
        self.assertIn('Cannot push condition path', str(raised.exception))
        with self.assertRaises(PermissionConditionError) as raised:
            factory.add_named_filter(
                Desk, 'card_ne_none',
                lambda u, p, o: o.card != None,  # noqa: E711
            )
        self.assertIn('Cannot push condition path', str(raised.exception))
        with self.assertRaises(PermissionConditionError) as raised:
            factory.add_named_filter(
                Desk, 'lower_card', lambda u, p, o: Lower(o.card) == 'x',
            )
        self.assertIn('Cannot push condition path', str(raised.exception))
        with self.assertRaises(PermissionConditionError) as raised:
            factory.add_named_filter(
                Desk, 'bad_exists', lambda u, p, o: Reachable(o),
            )
        self.assertIn('root alone', str(raised.exception))

        class Stub(models.Model):
            grant = models.OneToOneField(
                DeskGrant, related_name='stub', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'unk_stub'

        refused = compiler(path='tests.core.test_unknown.relation-reject')
        with self.assertRaises(PermissionConditionError) as raised:
            refused.register(
                trust=DeskGrant, user='user', permission='permission',
                content='desk',
                condition=lambda row: row.stub == None,  # noqa: E711
            )
        self.assertIn('Cannot push condition path', str(raised.exception))
        relation = compiler(path='tests.core.test_unknown.relation')
        relation.register(
            trust=DeskGrant, user='user', permission='permission',
            content='desk',
            condition=lambda row: Reachable(row.desk),
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

    def test_unsaved_user_permission_row_and_identity(self):
        """Shapes the public checkers reach and the suite had not run.

        An unsaved user has no primary key, so the condition is compiled
        without a user binding. An object comparison still runs. A user
        field cannot. ``Reachable`` on a permission attribute is rejected
        at registration. A string permission's ``name`` still fails when
        the inquiry passes a codename. A permission row is the pk for a
        bare ``p``, and a real column for ``p.codename``. Two function
        grants compare and hash by that tree.
        """
        User = get_user_model()
        Room, _Tag, Desk, Note, DeskGrant = _models()
        factory = compiler(path='tests.core.test_unknown.row')
        lowered = factory.add_named_filter(
            Note, 'lower_kept', lambda u, p, o: Lower(o.body) == 'row-kept',
        )
        coalesced = factory.add_named_filter(
            Note, 'coal_kept',
            lambda u, p, o: Coalesce(o.body, Value('fallback')) == 'fallback',
        )
        label_kept = factory.add_named_filter(
            Note, 'label_kept', lambda u, p, o: o.body == 'row-kept',
        )
        user_active = factory.add_named_filter(
            Note, 'user_active', lambda u, p, o: u.is_active,
        )
        with self.assertRaises(PermissionConditionError) as raised:
            factory.add_named_filter(
                Note, 'perm_exists', lambda u, p, o: Reachable(p.codename),
            )
        self.assertIn(
            'does not apply to a permission field', str(raised.exception),
        )
        with self.assertRaises(PermissionConditionError) as raised:
            factory.add_named_filter(
                Note, 'perm_exists_label',
                lambda u, p, o: Reachable(p.app_label),
            )
        self.assertIn(
            'does not apply to a permission field', str(raised.exception),
        )
        factory.add_named_filter(
            Note, 'same_perm', lambda u, p, o: p == p,
        )
        factory.add_named_filter(
            Note, 'by_code', lambda u, p, o: p.codename == 'change_unkdesk',
        )
        factory.add_named_filter(
            Note, 'by_missing', lambda u, p, o: p.codename == 'missing',
        )
        factory.add_named_filter(
            Note, 'by_name',
            lambda u, p, o: p.name == 'Can change unk desk',
        )
        factory.register(
            trust=DeskGrant, user='user', permission='permission',
            content='desk__notes',
        )
        with _tables(Room, _Tag, Desk, Note, DeskGrant):
            upper = Desk.objects.create(label='Kept')
            lower_only = Desk.objects.create(label='kept')
            Desk.objects.create(label='no')
            ungranted = Desk.objects.create(label='Kept')
            upper_note = Note.objects.create(desk=upper, body='row-kept')
            lower_note = Note.objects.create(desk=lower_only, body='row-other')
            blank_note = Note.objects.create(desk=upper, body=None)
            Note.objects.create(desk=ungranted, body='row-kept')
            change = Permission.objects.create(
                content_type=ContentType.objects.get_for_model(Note),
                codename='change_unkdesk',
                name='Can change unk desk',
            )
            alice = User.objects.create_user('alice-row', password='x')
            unsaved = User(username='ghost-row')
            for row in (upper, lower_only):
                DeskGrant.objects.create(
                    desk=row, user=alice, permission=change,
                )
            self.assertIsNone(unsaved.pk)
            skipped = _filter_bindings(Note, unsaved, PERM, User)
            self.assertNotIn('user', skipped)
            row_bindings = _filter_bindings(Note, alice, change, User)
            string_bindings = _filter_bindings(Note, alice, PERM, User)
            same = GrantPredicate(coalesced, row_bindings)
            copy = GrantPredicate(coalesced, row_bindings)
            other = GrantPredicate(lowered, row_bindings)
            self.assertEqual(same, copy)
            self.assertEqual(hash(same), hash(copy))
            self.assertEqual(len({same, copy}), 1)
            self.assertNotEqual(same, other)
            self.assertEqual(len({same, other}), 2)
            self.assertNotEqual(same, GrantPredicate(coalesced, string_bindings))
            self.assertIs(same.__eq__(object()), NotImplemented)
            self.assertIs(same == object(), False)
            with published_class_catalog(
                _DeskBackend, factory,
            ), override_settings(AUTHENTICATION_BACKENDS=(BACKEND,)):
                listed = set(Note.objects.permitted(
                    PERM, alice, conditions=('lower_kept',),
                ).values_list('pk', flat=True))
                coal = set(Note.objects.permitted(
                    PERM, alice, conditions=('coal_kept',),
                ).values_list('pk', flat=True))
                self.assertEqual(listed, {upper_note.pk})
                self.assertNotIn(lower_note.pk, listed)
                self.assertEqual(coal, {blank_note.pk})
                self.assertEqual(
                    set((
                        Note.objects.permitted(
                            PERM, alice, conditions=('lower_kept',),
                        ) | Note.objects.permitted(
                            PERM, alice, conditions=('coal_kept',),
                        )
                    ).values_list('pk', flat=True)),
                    {upper_note.pk, blank_note.pk},
                )
                # The grant lookup rejects an unsaved user before SQL.
                # The condition was already compiled without a user binding.
                with self.assertRaises(ValueError) as raised:
                    unsaved.has_perm('%s:label_kept' % PERM, upper_note)
                self.assertIn('must be saved', str(raised.exception))
                with self.assertRaises(ValueError) as raised:
                    list(Note.objects.permitted(
                        PERM, unsaved, conditions=('label_kept',),
                    ))
                self.assertIn('must be saved', str(raised.exception))
                self.assertEqual(set(Note.objects.filter(compile_to_q(
                    label_kept, Note, unsaved, PERM, User,
                )).values_list('pk', flat=True)), {upper_note.pk, ungranted.notes.get().pk})
                with self.assertRaises(PermissionConditionError) as raised:
                    list(Note.objects.filter(compile_to_q(
                        user_active, Note, unsaved, PERM, User,
                    )))
                self.assertIn(
                    "Cannot lower field rooted at 'user'", str(raised.exception),
                )
                granted_desks = {upper.pk, lower_only.pk}

                def desks(code):
                    return set(filter_by_permitted_content(
                        Desk.objects.all(), alice, change, content=Note,
                        conditions=(code,),
                    ).values_list('pk', flat=True))

                self.assertEqual(desks('same_perm'), granted_desks)
                self.assertEqual(desks('by_code'), granted_desks)
                self.assertEqual(desks('by_name'), granted_desks)
                self.assertEqual(desks('by_missing'), set())
                with self.assertRaises(PermissionConditionError) as raised:
                    alice.has_perm('%s:by_name' % PERM, upper_note)
                self.assertIn(
                    'Permission references cannot traverse attributes in V1',
                    str(raised.exception),
                )
                with self.assertRaises(PermissionConditionError) as raised:
                    list(Note.objects.permitted(
                        PERM, alice, conditions=('by_name',),
                    ))
                self.assertIn(
                    'Permission references cannot traverse attributes in V1',
                    str(raised.exception),
                )

    def test_registration_rejects_root_and_column_paths(self):
        """A Reachable path ends in a forward FK or a reverse one-to-one."""
        _Room, _Tag, Desk, _Note, DeskGrant = _models()

        class Marker(models.Model):
            content_type = models.ForeignKey(
                ContentType, on_delete=models.CASCADE,
            )
            object_id = models.PositiveIntegerField()
            target = GenericForeignKey('content_type', 'object_id')

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'unk_marker'

        factory = compiler(path='tests.core.test_unknown.shapes')
        rejected = (
            ('root', lambda u, p, o: Reachable(o), 'root alone'),
            ('user_root', lambda u, p, o: Reachable(u), 'root alone'),
            ('column', lambda u, p, o: Reachable(o.label), 'is a column'),
            ('through', lambda u, p, o: Reachable(o.room.name), 'is a column'),
            ('attname', lambda u, p, o: Reachable(o.room_id), 'is a column'),
            ('pk', lambda u, p, o: Reachable(o.room.id), 'is a column'),
            ('mid_attname', lambda u, p, o: Reachable(o.room_id.name),
             'Name the relation'),
            ('m2m', lambda u, p, o: Reachable(o.tags), 'Multi-valued'),
            ('reverse', lambda u, p, o: Reachable(o.notes), 'Multi-valued'),
            ('perm', lambda u, p, o: Reachable(p), 'permission field'),
            ('perm_col', lambda u, p, o: Reachable(p.codename),
             'permission field'),
        )
        for code, builder, text in rejected:
            with self.subTest(code=code):
                with self.assertRaises(PermissionConditionError) as raised:
                    factory.add_named_filter(Desk, code, builder)
                self.assertIn(text, str(raised.exception))
        gfk_cases = (
            ('gfk_cont', lambda u, p, o: Reachable(o.target.id)),
            ('gfk_cmp', lambda u, p, o: o.target.id == 1),
        )
        for code, builder in gfk_cases:
            with self.subTest(code=code):
                with self.assertRaises(PermissionConditionError) as raised:
                    factory.add_named_filter(Marker, code, builder)
                self.assertIn('GenericForeignKey', str(raised.exception))
        with self.assertRaises(PermissionConditionError) as raised:
            factory.set_user_condition('root', lambda user: Reachable(user))
        self.assertIn('root alone', str(raised.exception))
        with self.assertRaises(PermissionConditionError) as raised:
            factory.set_user_condition(
                'nick', lambda user: Reachable(user.username),
            )
        self.assertIn('is a column', str(raised.exception))

        refused = compiler(path='tests.core.test_unknown.shapes-row')
        with self.assertRaises(PermissionConditionError) as raised:
            refused.register(
                trust=DeskGrant, user='user', permission='permission',
                content='desk',
                condition=lambda row: Reachable(row),
            )
        self.assertIn('root alone', str(raised.exception))
        with self.assertRaises(PermissionConditionError) as raised:
            refused.register(
                trust=DeskGrant, user='user', permission='permission',
                content='desk',
                condition=lambda row: Reachable(row.desk.label),
            )
        self.assertIn('is a column', str(raised.exception))
        with self.assertRaises(PermissionConditionError) as raised:
            refused.register(
                trust=DeskGrant, user='user', permission='permission',
                content='desk',
                condition=lambda row: Reachable(row.desk_id.room),
            )
        self.assertIn('desk_id', str(raised.exception))
        self.assertIn('Name the relation', str(raised.exception))

        accepted = compiler(path='tests.core.test_unknown.shapes-ok')
        accepted.add_named_filter(
            Desk, 'room', lambda u, p, o: Reachable(o.room),
        )
        accepted.register(
            trust=DeskGrant, user='user', permission='permission',
            content='desk',
            condition=lambda row: Reachable(row.desk),
        )
        self.assertEqual(len(accepted.records), 1)


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

        class Unit(models.Model):
            code = models.CharField(max_length=20, null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'parity_unit'

        class Room(models.Model):
            name = models.CharField(max_length=20, null=True)
            unit = models.ForeignKey(
                Unit, null=True, db_constraint=False,
                on_delete=models.DO_NOTHING, related_name='rooms',
            )

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

        with _tables(Unit, Room, Folder, Task, Seat):
            open_unit = Unit.objects.create(code=None)
            kept = Room.objects.create(name='kept', unit=None)
            blank = Room.objects.create(name=None, unit=open_unit)
            dangling_unit = Room.objects.create(name='kept', unit=None)
            Room.objects.filter(pk=dangling_unit.pk).update(
                unit_id=DANGLING_ID,
            )
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
                # Reachable(parity_room) follows the key. NULL and dangling
                # are false. Reachable(parity_room.unit) follows unit too,
                # including a unit row whose code is NULL.
                ('exists-dangling-child', lambda user: Reachable(user.parity_room),
                 passing, dict(parity_room_id=DANGLING_ID), True, False),
                ('exists-missing-child', lambda user: Reachable(user.parity_room),
                 passing, dict(parity_room=None), True, False),
                # Ada is the walk seed. Her failure would stop the path
                # before Ben, so the missing room is hers.
                ('not-exists-room-child',
                 lambda user: ~Reachable(user.parity_room),
                 dict(parity_room=None), passing, True, False),
                ('exists-unit-null-key',
                 lambda user: Reachable(user.parity_room.unit),
                 passing, dict(parity_room=None), False, False),
                ('exists-unit-dangling-key',
                 lambda user: Reachable(user.parity_room.unit),
                 dict(parity_room=dangling_unit),
                 dict(parity_room_id=DANGLING_ID), False, False),
                ('reachable-unit-null-code',
                 lambda user: Reachable(user.parity_room.unit),
                 dict(parity_room=blank), dict(parity_room=kept), True, False),
                ('eq-none-unit-code',
                 lambda user: user.parity_room.unit.code == None,  # noqa: E711
                 dict(parity_room=blank), dict(parity_room=kept), True, False),
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
                ('obj-exists-null', lambda u, p, o: Reachable(o.room),
                 dict(room=None, label='yes', flag=False), False),
                ('obj-exists-dangling', lambda u, p, o: Reachable(o.room),
                 dict(room_id=DANGLING_ID, label='yes', flag=False), False),
                ('obj-not-exists-dangling', lambda u, p, o: ~Reachable(o.room),
                 dict(room_id=DANGLING_ID, label='yes', flag=False), True),
                ('obj-exists-unit-null-key',
                 lambda u, p, o: Reachable(o.room.unit),
                 dict(room=kept, label='yes', flag=False), False),
                ('obj-exists-unit-missing-room',
                 lambda u, p, o: Reachable(o.room.unit),
                 dict(room=None, label='yes', flag=False), False),
                ('obj-exists-unit-dangling-room',
                 lambda u, p, o: Reachable(o.room.unit),
                 dict(room_id=DANGLING_ID, label='yes', flag=False), False),
                ('obj-exists-unit-dangling-key',
                 lambda u, p, o: Reachable(o.room.unit),
                 dict(room=dangling_unit, label='yes', flag=False), False),
                ('obj-reachable-unit-null-code',
                 lambda u, p, o: Reachable(o.room.unit),
                 dict(room=blank, label='yes', flag=False), True),
                ('obj-eq-none-unit-code',
                 lambda u, p, o: o.room.unit.code == None,  # noqa: E711
                 dict(room=blank, label='yes', flag=False), True),
                ('obj-eq-none-unit-code-missing',
                 lambda u, p, o: o.room.unit.code == None,  # noqa: E711
                 dict(room=kept, label='yes', flag=False), False),
                ('obj-ne-none-unit-code-missing',
                 lambda u, p, o: o.room.unit.code != None,  # noqa: E711
                 dict(room=None, label='yes', flag=False), False),
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


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class SheetAliasTests(TransactionTestCase):
    """Sponsor checks read the ownership row the sheet already joined."""

    def test_inner_join_is_the_only_ownership_read(self):
        self._run(False)

    def test_left_join_is_the_only_ownership_read(self):
        self._run(True)

    def _run(self, null):
        User = get_user_model()

        class Organization(models.Model):
            name = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'shape_org'

        class Ownership(models.Model):
            organization = models.ForeignKey(
                Organization, on_delete=models.CASCADE, related_name='+',
            )
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'shape_ownership'

        class Repository(models.Model):
            organization = models.ForeignKey(
                Organization, on_delete=models.CASCADE, related_name='+',
            )
            name = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'shape_repo'

        class Delegation(models.Model):
            repository = models.ForeignKey(
                Repository, on_delete=models.CASCADE,
            )
            sponsor_ownership = models.ForeignKey(
                Ownership, on_delete=models.CASCADE, related_name='+',
                null=null,
            )
            delegate = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'shape_delegation'

        class Grant(models.Model):
            repository = models.ForeignKey(
                Repository, on_delete=models.CASCADE,
            )
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'shape_grant'

        created = (Organization, Ownership, Repository, Delegation, Grant)
        with connection.schema_editor() as editor:
            for model in created:
                editor.create_model(model)
        try:
            handle = compiler(path='tests.core.shape-alias-%s' % null)
            handle.register(
                trust=Grant, user='user', permission='permission',
                content='repository',
            )
            handle.register(
                trust=Delegation,
                delegate='delegate',
                sponsor='sponsor_ownership__user',
                content='repository',
                condition=lambda row: (
                    row.sponsor_ownership.organization
                    == row.repository.organization
                ),
            )
            org = Organization.objects.create(name='org')
            other = Organization.objects.create(name='other')
            repo = Repository.objects.create(organization=org, name='repo')
            ada = User.objects.create_user('shape-ada', password='x')
            ben = User.objects.create_user('shape-ben', password='x')
            cy = User.objects.create_user('shape-cy', password='x')
            own = Ownership.objects.create(organization=org, user=ada)
            mismatch = Ownership.objects.create(organization=other, user=ada)
            change = Permission.objects.create(
                content_type=ContentType.objects.get_for_model(Repository),
                codename='change_shaperepo',
                name='Can change shape repo',
            )
            Grant.objects.create(repository=repo, user=ada, permission=change)
            Delegation.objects.create(
                repository=repo, sponsor_ownership=own, delegate=ben,
            )
            Delegation.objects.create(
                repository=repo, sponsor_ownership=mismatch, delegate=cy,
            )
            catalog = handle.compile()
            code = 'trusts_tests.change_shaperepo'
            self.assertIs(catalog.has_perm(ben, code, repo), True)
            self.assertIs(catalog.has_perm(cy, code, repo), False)
            if null:
                dee = User.objects.create_user('shape-dee', password='x')
                Delegation.objects.create(
                    repository=repo, sponsor_ownership=None, delegate=dee,
                )
                self.assertIs(catalog.has_perm(dee, code, repo), False)
            ada.is_active = False
            ada.save(update_fields=['is_active'])
            try:
                self.assertIs(catalog.has_perm(ben, code, repo), False)
            finally:
                ada.is_active = True
                ada.save(update_fields=['is_active'])
            self.assertIs(catalog.has_perm(ben, code, repo), True)
            with CaptureQueriesContext(connection) as ctx:
                catalog.has_perm(ben, code, repo)
            matched = [
                item['sql'] for item in ctx.captured_queries
                if 'shape_ownership' in item['sql']
            ]
            self.assertEqual(len(matched), 1)
            sql = matched[0]
            self.assertEqual(sql.count('shape_ownership'), 1)
            self.assertNotIn('FROM "shape_ownership"', sql)
            self.assertNotIn('FROM `shape_ownership`', sql)
        finally:
            with connection.schema_editor() as editor:
                for model in reversed(created):
                    editor.delete_model(model)
