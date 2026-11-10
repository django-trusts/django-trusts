"""A present row's ``== None`` is ``IS NULL``, not ``CASE WHEN (1=1)``.

A missing row stays Unknown. ``!= None`` is that test negated. The same
shape is used by an ``along=`` path condition, a ``via=`` user condition,
and a plain ``condition=``.
"""
from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.test.utils import isolate_apps

from tests.core.test_via_walk import _add_user_column, _attach_manager
from tests.support import (
    compiler,
    published_class_catalog,
    render_configured_policy,
)
from trusts.backends import TrustModelBackendMixin
from trusts.decorators import filter_by_permitted_content
from trusts.models import (
    AuthorizedQuerySet,
    PermittedQuerySetMixin,
    PermittedUsersManagerMixin,
    PermittedUsersMixin,
)
from trusts.plan.trivalent import Operand, compare


class _NullBackend(TrustModelBackendMixin, ModelBackend):
    pass


def _flat(sql):
    return ' '.join(sql.split())


def _q(name):
    return connection.ops.quote_name(name)


@contextmanager
def _listed(handle):
    with published_class_catalog(_NullBackend, handle):
        with override_settings(
            AUTHENTICATION_BACKENDS=(
                'tests.core.test_null_guard._NullBackend',
            ),
        ):
            yield


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


def _permission(model, codename):
    content_type = ContentType.objects.get_for_model(model)
    permission, _created = Permission.objects.get_or_create(
        content_type=content_type,
        codename=codename,
        defaults={'name': codename},
    )
    return permission


def _user_pks(content, perm):
    user_model = get_user_model()
    listing = type(
        'NullGuardUsers',
        (PermittedUsersManagerMixin, type(user_model.objects)),
        {},
    )()
    listing.model = user_model
    listing.name = 'objects'
    return set(listing.permitted(content, perm).values_list('pk', flat=True))


def _none():
    return Operand('(1=0)', (), '(1=1)', (), True)


class PresentNullSqlTests(SimpleTestCase):
    """The constant-true guard is dropped. A real guard stays."""

    def test_present_row_is_plain_null(self):
        column = Operand('"issue"."cut_here"', (), '(1=1)', (), False)
        eq = compare('eq', column, _none())
        ne = compare('ne', column, _none())
        swapped = compare('eq', _none(), column)
        self.assertEqual(eq.sql, '("issue"."cut_here" IS NULL)')
        self.assertEqual(eq.params, ())
        self.assertEqual(swapped.sql, eq.sql)
        self.assertEqual(ne.sql, '(NOT ("issue"."cut_here" IS NULL))')
        self.assertNotIn('CASE', eq.sql)
        self.assertNotIn('IS NOT NULL', ne.sql)

    def test_parenthesized_and_spaced_true_guards_are_the_same_constant(self):
        for guard in ('((1=1))', ' ( 1 = 1 ) ', '1=1', '(((1=1)))'):
            column = Operand('"t"."a"', (), guard, (), False)
            sql = compare('eq', column, _none()).sql
            self.assertEqual(sql, '("t"."a" IS NULL)', guard)
            self.assertNotIn('1=1', sql)

    def test_real_guard_stays_unknown_when_the_row_is_missing(self):
        missing = Operand(
            '(SELECT "h0"."room_label" FROM "nullg_room" AS "h0" '
            'WHERE "h0"."code" = "issue"."room_ref")',
            (),
            'EXISTS (SELECT 1 FROM "nullg_room" AS "h0" '
            'WHERE "h0"."code" = "issue"."room_ref")',
            (),
            False,
        )
        eq = compare('eq', missing, _none())
        ne = compare('ne', _none(), missing)
        self.assertIn('CASE WHEN (EXISTS', eq.sql)
        self.assertIn('"h0"."room_label"', eq.sql)
        self.assertIn(') IS NULL)', eq.sql)
        self.assertNotIn('1=1', eq.sql)
        self.assertEqual(ne.sql, '(NOT (%s))' % eq.sql)
        self.assertNotIn('IS NOT NULL', ne.sql)
        reached = Operand(
            '"desk"."label"', (), '"desk"."id" IS NOT NULL', (), False,
        )
        guarded = compare('eq', reached, _none())
        self.assertIn('CASE WHEN ("desk"."id" IS NOT NULL)', guarded.sql)
        self.assertNotIn('1=1', guarded.sql)
        false_guard = Operand('"t"."a"', (), '(1=0)', (), False)
        kept = compare('eq', false_guard, _none()).sql
        self.assertIn('CASE WHEN ((1=0))', kept)
        compound = Operand('"t"."a"', ('x',), '(1=1) AND (1=1)', (), False)
        mixed = compare('eq', compound, _none())
        self.assertIn('CASE WHEN', mixed.sql)
        self.assertEqual(mixed.params, ('x',))

    def test_present_null_keeps_value_params_only(self):
        column = Operand('%s', ('kept',), '(1=1)', (), False)
        eq = compare('eq', _none(), column)
        self.assertEqual(eq.sql, '(%s IS NULL)')
        self.assertEqual(eq.params, ('kept',))
        guarded = Operand('(%s)', ('v',), 'EXISTS (%s)', ('r',), False)
        eq = compare('ne', guarded, _none())
        self.assertEqual(eq.params, ('r', 'v'))
        self.assertIn('CASE WHEN (EXISTS (%s))', eq.sql)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class AlongNullGuardTests(TransactionTestCase):
    """``along=`` path conditions on a stored NULL and a missing room."""

    def setUp(self):
        super().setUp()
        User = get_user_model()

        class Room(models.Model):
            code = models.CharField(max_length=20, unique=True)
            name = models.CharField(
                max_length=20, null=True, db_column='room_label',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'nullg_room'

        class Issue(models.Model):
            title = models.CharField(max_length=20)
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )
            reset_inheritance = models.BooleanField(
                null=True, db_column='cut_here',
            )
            note = models.CharField(
                max_length=20, null=True, db_column='issue_note',
            )
            room = models.ForeignKey(
                Room, to_field='code', db_column='room_ref', null=True,
                db_constraint=False, on_delete=models.DO_NOTHING,
                related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'nullg_issue'

        class SheetQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Sheet(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=20)
            issue = models.ForeignKey(
                Issue, related_name='sheets', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(SheetQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'nullg_sheet'

        class Grant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )
            issue = models.ForeignKey(Issue, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'nullg_grant'

        self.User, self.Room, self.Issue, self.Sheet, self.Grant = (
            User, Room, Issue, Sheet, Grant,
        )
        cm = _tables(Room, Issue, Sheet, Grant)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        self.change = _permission(Sheet, 'change_nullsheet')
        self.code = '%s.%s' % (
            self.change.content_type.app_label, self.change.codename,
        )
        self.alice = User.objects.create_user('nullg-alice', password='x')
        self.bob = User.objects.create_user('nullg-bob', password='x')
        self.kept = Room.objects.create(code='kept', name='kept')
        self.blank = Room.objects.create(code='blank', name=None)
        self.issues = {}
        self.sheets = {}

    def _issue(self, title, parent=None, reset=None, note=None, room='kept'):
        if room == 'kept':
            related = self.kept
        elif room == 'blank':
            related = self.blank
        else:
            related = None
        issue = self.Issue(
            title=title,
            parent=None if parent is None else self.issues[parent],
            reset_inheritance=reset,
            note=note,
            room=related,
        )
        if room == 'dangling':
            setattr(issue, self.Issue._meta.get_field('room').attname, 'missing')
        issue.save()
        self.issues[title] = issue
        self.sheets[title] = self.Sheet.objects.create(title=title, issue=issue)
        return issue

    def _open(self, name, along):
        handle = compiler(path='tests.core.null-guard.along-%s' % name)
        handle.register(
            trust=self.Grant, user='user', permission='permission',
            content='issue__sheets', along=along,
        )
        return handle

    def _expect(self, handle, user, titles):
        wanted = set(titles)
        with _listed(handle):
            permitted = set(self.Sheet.objects.permitted(
                self.code, user,
            ).values_list('title', flat=True))
            authorized = set(self.Sheet.objects.authorized(
                user, self.change,
            ).values_list('title', flat=True))
            self.assertEqual(permitted, wanted)
            self.assertEqual(authorized, wanted)
            for sheet in self.Sheet.objects.all():
                allowed = sheet.title in wanted
                self.assertIs(
                    user.has_perm(self.code, sheet), allowed, sheet.title,
                )
                holders = set(sheet.get_permitted_users(
                    self.change,
                ).values_list('pk', flat=True))
                self.assertEqual(user.pk in holders, allowed, sheet.title)
                self.assertEqual(
                    user.pk in _user_pks(sheet, self.change), allowed,
                    sheet.title,
                )
                self.assertEqual(
                    self.code in user.get_all_permissions(sheet), allowed,
                    sheet.title,
                )
                self.assertIs(
                    self.bob.has_perm(self.code, sheet), False, sheet.title,
                )
                self.assertNotIn(self.bob.pk, holders)
            issues = set(filter_by_permitted_content(
                self.Issue.objects.all(), user, self.change,
                content=self.Sheet,
            ).values_list('title', flat=True))
            self.assertEqual(issues, wanted)

    def _sql(self, handle):
        with _listed(handle):
            query = str(self.Sheet.objects.permitted(self.code, self.alice).query)
        policy = _flat(render_configured_policy(handle).decode())
        return _flat(query), policy

    def _assert_plain(self, sql, column):
        self.assertIn('%s IS NULL' % _q(column), sql, sql)
        self.assertNotIn('1=1', sql, sql)
        self.assertNotIn('CASE WHEN', sql, sql)

    def test_false_or_null_continues_and_true_stops(self):
        # A(false) → B(null) → C(true) → D(false); A → E(false) → F(null).
        self._issue('A', reset=False, note='a')
        self._issue('B', parent='A', reset=None, note=None, room='blank')
        self._issue('C', parent='B', reset=True, note='c', room=None)
        self._issue('D', parent='C', reset=False, note='d', room='dangling')
        self._issue('E', parent='A', reset=False, note='e')
        self._issue('F', parent='E', reset=None, note=None, room='blank')
        self._issue('G', reset=None, note=None, room=None)
        self.Grant.objects.create(
            user=self.alice, permission=self.change, issue=self.issues['A'],
        )
        handle = self._open('either', (
            lambda t: (
                (t.issue.reset_inheritance == False)  # noqa: E712
                | (t.issue.reset_inheritance == None)  # noqa: E711
            ) & t.issue.parent,
            8,
        ))
        query, policy = self._sql(handle)
        for text in (query, policy):
            self._assert_plain(text, 'cut_here')
            self.assertNotIn(_q('reset_inheritance'), text, text)
        self._expect(handle, self.alice, {'A', 'B', 'E', 'F'})
        self.Grant.objects.create(
            user=self.alice, permission=self.change, issue=self.issues['C'],
        )
        self._expect(handle, self.alice, {'A', 'B', 'C', 'D', 'E', 'F'})
        self._expect(handle, self.bob, set())

    def test_not_none_and_either_side_use_the_stored_column(self):
        self._issue('A', reset=False, note='a')
        self._issue('B', parent='A', reset=None, note=None, room='blank')
        self._issue('E', parent='A', reset=False, note='e')
        self._issue('F', parent='E', reset=None, note=None, room='blank')
        self.Grant.objects.create(
            user=self.alice, permission=self.change, issue=self.issues['A'],
        )
        ne = self._open('ne', (
            lambda t: (t.issue.note != None) & t.issue.parent,  # noqa: E711
            8,
        ))
        query, policy = self._sql(ne)
        for text in (query, policy):
            self.assertIn('NOT', text)
            self._assert_plain(text, 'issue_note')
            self.assertNotIn('%s IS NOT NULL' % _q('issue_note'), text, text)
        self._expect(ne, self.alice, {'A', 'E'})
        left = self._open('left', (
            lambda t: (None == t.issue.note) & t.issue.parent,  # noqa: E711
            8,
        ))
        query, policy = self._sql(left)
        for text in (query, policy):
            self._assert_plain(text, 'issue_note')
        # F's note is null, but E's note is set, so the walk never reaches F.
        self._expect(left, self.alice, {'A', 'B'})

    def test_missing_room_stays_unknown(self):
        self._issue('A', reset=False, note='a', room='kept')
        self._issue('B', parent='A', reset=False, note='b', room='blank')
        self._issue('C', parent='B', reset=False, note='c', room=None)
        self._issue('D', parent='A', reset=False, note='d', room='dangling')
        self._issue('E', parent='A', reset=False, note='e', room='kept')
        self.Grant.objects.create(
            user=self.alice, permission=self.change, issue=self.issues['A'],
        )
        handle = self._open('room', (
            lambda t: (t.issue.room.name == None) & t.issue.parent,  # noqa: E711
            8,
        ))
        query, policy = self._sql(handle)
        for text in (query, policy):
            self.assertIn('CASE WHEN', text, text)
            self.assertIn(_q('room_label'), text, text)
            self.assertIn('IS NULL', text, text)
            self.assertIn(_q('code'), text, text)
            self.assertIn(_q('room_ref'), text, text)
            self.assertNotIn('1=1', text, text)
        # B's room exists and its name is NULL. C has no room. D's code
        # matches no room. Neither missing row is a stored NULL.
        self._expect(handle, self.alice, {'A', 'B'})
        ne = self._open('room-ne', (
            lambda t: (t.issue.room.name != None) & t.issue.parent,  # noqa: E711
            8,
        ))
        query, policy = self._sql(ne)
        for text in (query, policy):
            self.assertIn('CASE WHEN', text, text)
            self.assertIn('NOT', text)
            self.assertIn(_q('room_label'), text, text)
            self.assertIn('IS NULL', text, text)
            self.assertNotIn('1=1', text, text)
            self.assertNotIn('%s IS NOT NULL' % _q('room_label'), text, text)
        self._expect(ne, self.alice, {'A', 'E'})


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ViaNullGuardTests(TransactionTestCase):
    """``via=`` path conditions and user conditions on a walked user."""

    def setUp(self):
        super().setUp()
        User = get_user_model()
        _attach_manager(self, User)
        _add_user_column(
            self, User, 'via_mark',
            models.BooleanField(null=True, db_column='via_mark_col'),
        )
        self.User = User
        self.people = {}
        for name in ('ada', 'ben', 'cy', 'dee', 'eve'):
            self.people[name] = User.objects.create_user(
                'nullv-%s' % name, password='x',
            )
        ada, ben, cy, dee, eve = (
            self.people[name] for name in ('ada', 'ben', 'cy', 'dee', 'eve')
        )
        ben.via_manager = ada
        ben.save()
        cy.via_manager = ben
        cy.save()
        dee.via_manager = ada
        dee.save()
        eve.via_manager = dee
        eve.save()

        class Folder(models.Model):
            name = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'nullv_folder'

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
                db_table = 'nullv_task'

        class Seat(models.Model):
            holder = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'nullv_seat'

        self.Folder, self.Task, self.Seat = Folder, Task, Seat
        cm = _tables(Folder, Task, Seat)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        self.change = _permission(Task, 'change_nulltask')
        self.code = '%s.%s' % (
            self.change.content_type.app_label, self.change.codename,
        )
        self.folder = Folder.objects.create(name='folder')
        self.task = Task.objects.create(name='task', folder=self.folder)
        self.seat = Seat.objects.create(
            holder=ada, permission=self.change, folder=self.folder,
        )

    def _marks(self, **values):
        for name, value in values.items():
            person = self.people[name]
            person.via_mark = value
            person.save(update_fields=['via_mark'])

    def _open(self, name, *, via, condition=None):
        handle = compiler(path='tests.core.null-guard.via-%s' % name)
        if condition is not None:
            handle.set_user_condition('mark', condition)
        handle.register(
            trust=self.Seat, user='holder', permission='permission',
            content='folder__tasks', via=via,
        )
        return handle

    def _expect(self, handle, names):
        wanted = set(names)
        with _listed(handle):
            for name, user in self.people.items():
                allowed = name in wanted
                permitted = self.task.name in set(
                    self.Task.objects.permitted(
                        self.code, user,
                    ).values_list('name', flat=True)
                )
                authorized = self.task.name in set(
                    self.Task.objects.authorized(
                        user, self.change,
                    ).values_list('name', flat=True)
                )
                self.assertEqual(permitted, allowed, name)
                self.assertEqual(authorized, allowed, name)
                self.assertIs(user.has_perm(self.code, self.task), allowed, name)
                holders = set(self.task.get_permitted_users(
                    self.change,
                ).values_list('pk', flat=True))
                self.assertEqual(user.pk in holders, allowed, name)
                self.assertEqual(
                    user.pk in _user_pks(self.task, self.change), allowed, name,
                )
                self.assertEqual(
                    self.code in user.get_all_permissions(self.task), allowed,
                    name,
                )
                folders = set(filter_by_permitted_content(
                    self.Folder.objects.all(), user, self.change,
                    content=self.Task,
                ).values_list('name', flat=True))
                self.assertEqual(
                    folders, {'folder'} if allowed else set(), name,
                )

    def _sql(self, handle):
        with _listed(handle):
            query = str(self.Task.objects.permitted(
                self.code, self.people['ada'],
            ).query)
        policy = _flat(render_configured_policy(handle).decode())
        return _flat(query), policy

    def test_path_condition_uses_the_stored_column(self):
        self._marks(ada=True, ben=None, cy=True, dee=False, eve=True)
        handle = self._open('path', via=(
            lambda t: (
                (t.holder.via_mark == False)  # noqa: E712
                | (t.holder.via_mark == None)  # noqa: E711
            ) & t.holder.via_manager,
            8,
        ))
        query, policy = self._sql(handle)
        for text in (query, policy):
            self.assertIn('%s IS NULL' % _q('via_mark_col'), text, text)
            self.assertNotIn(_q('via_mark'), text, text)
            self.assertNotIn('1=1', text, text)
            self.assertNotIn('CASE WHEN', text, text)
        # The seat's holder is depth 0. True does not remove ada. A step
        # is taken only when that user's mark is false or null.
        self._expect(handle, {'ada', 'ben', 'dee'})
        ne = self._open('path-ne', via=(
            lambda t: (t.holder.via_mark != None) & t.holder.via_manager,  # noqa: E711
            8,
        ))
        query, policy = self._sql(ne)
        for text in (query, policy):
            self.assertIn('NOT', text)
            self.assertIn('%s IS NULL' % _q('via_mark_col'), text, text)
            self.assertNotIn('%s IS NOT NULL' % _q('via_mark_col'), text, text)
            self.assertNotIn('CASE WHEN', text, text)
            self.assertNotIn('1=1', text, text)
        # ben's mark is null, so the step stops. dee and eve are set.
        self._expect(ne, {'ada', 'dee', 'eve'})

    def test_user_condition_and_a_missing_manager_do_not_overgrant(self):
        self._marks(ada=None, ben=False, cy=True, dee=None, eve=True)
        local = self._open(
            'user',
            via=('holder__via_manager', 8),
            condition=lambda user: (
                (user.via_mark == False) | (user.via_mark == None)  # noqa: E712, E711
            ),
        )
        query, policy = self._sql(local)
        for text in (query, policy):
            self.assertIn('%s IS NULL' % _q('via_mark_col'), text, text)
            self.assertNotIn(_q('via_mark'), text, text)
            self.assertNotIn('1=1', text, text)
            self.assertNotIn('CASE WHEN', text, text)
        self._expect(local, {'ada', 'ben', 'dee'})
        ne = self._open(
            'user-ne',
            via=('holder__via_manager', 8),
            condition=lambda user: user.via_mark != None,  # noqa: E711
        )
        self._marks(ada=False, ben=False, cy=True, dee=None, eve=True)
        query, policy = self._sql(ne)
        for text in (query, policy):
            self.assertIn('NOT', text)
            self.assertIn('%s IS NULL' % _q('via_mark_col'), text, text)
            self.assertNotIn('CASE WHEN', text, text)
            self.assertNotIn('1=1', text, text)
        self._expect(ne, {'ada', 'ben', 'cy'})
        missing = self._open(
            'missing',
            via=('holder__via_manager', 8),
            condition=lambda user: user.via_manager.via_mark == None,  # noqa: E711
        )
        query, policy = self._sql(missing)
        for text in (query, policy):
            self.assertIn('CASE WHEN', text, text)
            self.assertIn(_q('via_mark_col'), text, text)
            self.assertIn('IS NULL', text, text)
            self.assertNotIn('1=1', text, text)
        # ada has no manager. That is Unknown, not a stored NULL.
        self._marks(ada=None, ben=False, cy=True, dee=None, eve=True)
        self._expect(missing, set())
        self.seat.holder = self.people['dee']
        self.seat.save(update_fields=['holder'])
        # dee's manager is ada, whose mark is null, so dee matches.
        # eve's manager is dee, whose mark is also null, so eve matches.
        self._expect(missing, {'dee', 'eve'})
        self.people['ada'].via_mark = False
        self.people['ada'].save(update_fields=['via_mark'])
        self._expect(missing, set())


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class ConditionNullGuardTests(TransactionTestCase):
    """A plain ``condition=`` uses the same null test."""

    def setUp(self):
        super().setUp()
        User = get_user_model()

        class Room(models.Model):
            code = models.CharField(max_length=20, unique=True)
            name = models.CharField(
                max_length=20, null=True, db_column='room_label',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'nullc_room'

        class Folder(models.Model):
            name = models.CharField(max_length=20)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'nullc_folder'

        class DocQuerySet(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Doc(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=20)
            folder = models.ForeignKey(
                Folder, related_name='docs', on_delete=models.CASCADE,
            )
            objects = models.Manager.from_queryset(DocQuerySet)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'nullc_doc'

        class Grant(models.Model):
            user = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )
            folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
            reset_inheritance = models.BooleanField(
                null=True, db_column='cut_here',
            )
            note = models.CharField(
                max_length=20, null=True, db_column='grant_note',
            )
            room = models.ForeignKey(
                Room, to_field='code', db_column='room_ref', null=True,
                db_constraint=False, on_delete=models.DO_NOTHING,
                related_name='+',
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'nullc_grant'

        self.User = User
        self.Room, self.Folder, self.Doc, self.Grant = Room, Folder, Doc, Grant
        cm = _tables(Room, Folder, Doc, Grant)
        cm.__enter__()
        self.addCleanup(cm.__exit__, None, None, None)
        self.change = _permission(Doc, 'change_nulldoc')
        self.code = '%s.%s' % (
            self.change.content_type.app_label, self.change.codename,
        )
        self.alice = User.objects.create_user('nullc-alice', password='x')
        self.bob = User.objects.create_user('nullc-bob', password='x')
        self.kept = Room.objects.create(code='kept', name='kept')
        self.blank = Room.objects.create(code='blank', name=None)
        self.docs = {}
        self.folders = {}

    def _doc(self, title, reset, note, room):
        folder = self.Folder.objects.create(name=title)
        doc = self.Doc.objects.create(title=title, folder=folder)
        grant = self.Grant(
            user=self.alice, permission=self.change, folder=folder,
            reset_inheritance=reset, note=note, room=None,
        )
        if room == 'kept':
            grant.room = self.kept
        elif room == 'blank':
            grant.room = self.blank
        elif room == 'dangling':
            setattr(grant, self.Grant._meta.get_field('room').attname, 'missing')
        grant.save()
        self.docs[title] = doc
        self.folders[title] = folder
        return doc

    def _open(self, name, condition):
        handle = compiler(path='tests.core.null-guard.cond-%s' % name)
        handle.register(
            trust=self.Grant, user='user', permission='permission',
            content='folder__docs', condition=condition,
        )
        return handle

    def _expect(self, handle, titles):
        wanted = set(titles)
        with _listed(handle):
            permitted = set(self.Doc.objects.permitted(
                self.code, self.alice,
            ).values_list('title', flat=True))
            authorized = set(self.Doc.objects.authorized(
                self.alice, self.change,
            ).values_list('title', flat=True))
            self.assertEqual(permitted, wanted)
            self.assertEqual(authorized, wanted)
            for doc in self.Doc.objects.all():
                allowed = doc.title in wanted
                self.assertIs(
                    self.alice.has_perm(self.code, doc), allowed, doc.title,
                )
                self.assertIs(
                    self.bob.has_perm(self.code, doc), False, doc.title,
                )
                holders = set(doc.get_permitted_users(
                    self.change,
                ).values_list('pk', flat=True))
                self.assertEqual(self.alice.pk in holders, allowed, doc.title)
                self.assertNotIn(self.bob.pk, holders)
                self.assertEqual(
                    self.alice.pk in _user_pks(doc, self.change), allowed,
                    doc.title,
                )
                self.assertEqual(
                    self.code in self.alice.get_all_permissions(doc), allowed,
                    doc.title,
                )
            folders = set(filter_by_permitted_content(
                self.Folder.objects.all(), self.alice, self.change,
                content=self.Doc,
            ).values_list('name', flat=True))
            self.assertEqual(folders, wanted)

    def _sql(self, handle):
        with _listed(handle):
            query = str(self.Doc.objects.permitted(self.code, self.alice).query)
        policy = _flat(render_configured_policy(handle).decode())
        return _flat(query), policy

    def test_local_null_combination_and_either_side(self):
        self._doc('blank', reset=None, note=None, room=None)
        self._doc('held', reset=False, note='x', room='blank')
        self._doc('full', reset=True, note='y', room='kept')
        self._doc('lost', reset=None, note='z', room='dangling')
        either = self._open('either', lambda t: (
            (t.reset_inheritance == False) | (t.reset_inheritance == None)  # noqa: E712, E711
        ))
        query, policy = self._sql(either)
        for text in (query, policy):
            self.assertIn('%s IS NULL' % _q('cut_here'), text, text)
            self.assertNotIn(_q('reset_inheritance'), text, text)
            self.assertNotIn('1=1', text, text)
            self.assertNotIn('CASE WHEN', text, text)
        self._expect(either, {'blank', 'held', 'lost'})
        ne = self._open('ne', lambda t: t.note != None)  # noqa: E711
        query, policy = self._sql(ne)
        for text in (query, policy):
            self.assertIn('NOT', text)
            self.assertIn('%s IS NULL' % _q('grant_note'), text, text)
            self.assertNotIn('%s IS NOT NULL' % _q('grant_note'), text, text)
            self.assertNotIn('CASE WHEN', text, text)
            self.assertNotIn('1=1', text, text)
        self._expect(ne, {'held', 'full', 'lost'})
        left = self._open('left', lambda t: None == t.reset_inheritance)  # noqa: E711
        query, policy = self._sql(left)
        for text in (query, policy):
            self.assertIn('%s IS NULL' % _q('cut_here'), text, text)
            self.assertNotIn('CASE WHEN', text, text)
        self._expect(left, {'blank', 'lost'})
        both = self._open('both', lambda t: (
            (t.note != None) & (t.reset_inheritance == False)  # noqa: E711, E712
        ))
        self._expect(both, {'held'})

    def test_relation_null_keeps_the_guard_and_the_to_field(self):
        self._doc('blank', reset=None, note=None, room=None)
        self._doc('held', reset=False, note='x', room='blank')
        self._doc('full', reset=True, note='y', room='kept')
        self._doc('lost', reset=None, note='z', room='dangling')
        stored = self._open('stored', lambda t: t.room == None)  # noqa: E711
        query, policy = self._sql(stored)
        for text in (query, policy):
            self.assertIn('%s IS NULL' % _q('room_ref'), text, text)
            self.assertNotIn('CASE WHEN', text, text)
            self.assertNotIn('1=1', text, text)
        # The stored code is null only for blank. A dangling code is a
        # value, so it does not match ``== None``.
        self._expect(stored, {'blank'})
        name = self._open('name', lambda t: t.room.name == None)  # noqa: E711
        query, policy = self._sql(name)
        for text in (query, policy):
            self.assertIn('CASE WHEN', text, text)
            self.assertIn(_q('room_label'), text, text)
            self.assertIn('IS NULL', text, text)
            self.assertIn(_q('code'), text, text)
            self.assertIn(_q('room_ref'), text, text)
            self.assertNotIn('1=1', text, text)
        self._expect(name, {'held'})
        ne = self._open('name-ne', lambda t: t.room.name != None)  # noqa: E711
        query, policy = self._sql(ne)
        for text in (query, policy):
            self.assertIn('CASE WHEN', text, text)
            self.assertIn('NOT', text)
            self.assertIn(_q('room_label'), text, text)
            self.assertIn('IS NULL', text, text)
            self.assertNotIn('1=1', text, text)
        self._expect(ne, {'full'})
