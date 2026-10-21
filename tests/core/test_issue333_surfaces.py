"""#333: relation conditions and user rules use the shared predicate language.

Each newly accepted kind is checked through ``has_perm``, ``.permitted()``,
and ``get_permitted_users`` against a Python oracle. Kinds that stay
rejected are registered and must fail closed.
"""
from contextlib import contextmanager
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Group, Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.test.utils import isolate_apps

from tests.myapp.models import DocumentDelegation, DocumentGrant
from trusts.backends import TrustModelBackendMixin
from trusts.compile.nodes import Ref
from trusts.conditions import PermissionConditionError
from trusts.models import PermittedQuerySet, PermittedUsersMixin
from tests.support import compiler, published_class_catalog

PERM = 'trusts_tests.change_surfacenote'
BACKEND = 'tests.core.test_issue333_surfaces._SurfaceBackend'


class _SurfaceBackend(TrustModelBackendMixin, ModelBackend):
    pass


def _surface_models():
    User = get_user_model()

    class SurfaceMark(models.Model):
        flag = models.BooleanField(null=True)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue333_surface_mark'

    class SurfaceNote(PermittedUsersMixin, models.Model):
        objects = models.Manager.from_queryset(PermittedQuerySet)()

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue333_surface_note'

    class SurfaceGrant(models.Model):
        note = models.ForeignKey(SurfaceNote, on_delete=models.CASCADE)
        user = models.ForeignKey(
            User, on_delete=models.CASCADE, related_name='+',
        )
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
        left = models.IntegerField(null=True)
        right = models.IntegerField(null=True)
        status = models.CharField(max_length=16, null=True)
        flag = models.BooleanField(null=True)
        marker = models.ForeignKey(
            SurfaceMark, null=True, on_delete=models.CASCADE, related_name='+',
        )
        marks = models.ManyToManyField(SurfaceMark, related_name='+')

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue333_surface_grant'

    class SurfaceLink(models.Model):
        note = models.ForeignKey(SurfaceNote, on_delete=models.CASCADE)
        delegate = models.ForeignKey(
            User, on_delete=models.CASCADE, related_name='+',
        )
        sponsor = models.ForeignKey(
            User, on_delete=models.CASCADE, related_name='+',
        )
        token = models.ForeignKey(
            Permission, null=True, on_delete=models.CASCADE, related_name='+',
        )
        left = models.IntegerField(null=True)
        right = models.IntegerField(null=True)
        status = models.CharField(max_length=16, null=True)
        flag = models.BooleanField(null=True)
        marker = models.ForeignKey(
            SurfaceMark, null=True, on_delete=models.CASCADE, related_name='+',
        )
        marks = models.ManyToManyField(SurfaceMark, related_name='+')

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue333_surface_link'

    return SurfaceMark, SurfaceNote, SurfaceGrant, SurfaceLink


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


@contextmanager
def _published(factory):
    factory.path = BACKEND
    with published_class_catalog(
        _SurfaceBackend, factory,
    ), override_settings(AUTHENTICATION_BACKENDS=(BACKEND,)):
        yield


def _agree(test, content, perm, users, rows, allowed):
    for user in users:
        expected = {row.pk for row in rows if allowed(user, row)}
        with test.subTest(user=user.username, check='permitted'):
            listed = content.objects.permitted(perm, user)
            test.assertEqual(set(listed.values_list('pk', flat=True)), expected)
        with test.subTest(user=user.username, check='has_perm'):
            held = {row.pk for row in rows if user.has_perm(perm, row)}
            test.assertEqual(held, expected)
    for row in rows:
        expected = {user.pk for user in users if allowed(user, row)}
        with test.subTest(row=row.pk, check='permitted_users'):
            found = row.get_permitted_users(perm)
            test.assertEqual(set(found.values_list('pk', flat=True)), expected)


def _both_set(row):
    return row.left is not None and row.right is not None


def _saved_user(saved):
    def builder(row):
        return row.user == saved
    return builder


def _contains_member(member_pk):
    """One-argument builder. A default would look like a delegated permission."""
    def builder(row):
        return row.marks.contains(member_pk)
    return builder


def _relation_cases(member_pk):
    """Newly accepted relation kinds and the Python result of one grant."""
    return (
        (
            'ne',
            lambda t: t.left != t.right,
            lambda row: _both_set(row) and row.left != row.right,
        ),
        (
            'eq-const',
            lambda t: t.left == 1,
            lambda row: row.left == 1,
        ),
        (
            'ne-const',
            lambda t: t.status != 'open',
            lambda row: row.status != 'open',
        ),
        (
            'eq-null',
            lambda t: t.status == None,  # noqa: E711
            lambda row: row.status is None,
        ),
        (
            'or',
            lambda t: (t.left == t.right) | (t.status == 'open'),
            lambda row: (
                (_both_set(row) and row.left == row.right)
                or row.status == 'open'
            ),
        ),
        (
            'bare',
            lambda t: t.flag,
            lambda row: row.flag is True,
        ),
        (
            'not',
            lambda t: ~t.flag,
            lambda row: row.flag is not True,
        ),
        (
            'contains',
            _contains_member(member_pk),
            lambda row: row.marked,
        ),
        (
            'contains-null',
            lambda t: t.marks.contains(None),
            lambda row: False,
        ),
        (
            'related',
            lambda t: t.marker.flag,
            lambda row: (
                row.marker_id is not None and row.marker.flag is True
            ),
        ),
        (
            'not-related',
            lambda t: ~t.marker.flag,
            lambda row: not (
                row.marker_id is not None and row.marker.flag is True
            ),
        ),
    )


_SPECS = (
    {'left': None, 'right': None, 'status': None, 'flag': None, 'marked': False, 'marker': None},
    {'left': 1, 'right': None, 'status': 'open', 'flag': True, 'marked': False, 'marker': True},
    {'left': 1, 'right': 1, 'status': 'open', 'flag': False, 'marked': True, 'marker': False},
    {'left': 1, 'right': 2, 'status': 'closed', 'flag': None, 'marked': False, 'marker': None},
    {'left': 5, 'right': 5, 'status': None, 'flag': True, 'marked': True, 'marker': 'null'},
    {'left': None, 'right': 2, 'status': 'open', 'flag': False, 'marked': False, 'marker': True},
)


def _store_row(model, spec, mark, markers, **fields):
    row = model.objects.create(
        left=spec['left'], right=spec['right'], status=spec['status'],
        flag=spec['flag'], marker=markers[spec['marker']], **fields,
    )
    if spec['marked']:
        row.marks.add(mark)
    row.marked = spec['marked']
    return row


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class SurfaceAgreementTest(TransactionTestCase):
    """Relation ``condition=`` and user rules agree with Python."""

    def test_relation_user_and_delegated_kinds_agree(self):
        User = get_user_model()
        Mark, Note, Grant, Link = _surface_models()
        with _tables(Mark, Note, Grant, Link):
            mark = Mark.objects.create(flag=True)
            markers = {
                None: None,
                True: Mark.objects.create(flag=True),
                False: Mark.objects.create(flag=False),
                'null': Mark.objects.create(flag=None),
            }
            change = Permission.objects.get_or_create(
                content_type=ContentType.objects.get_for_model(Note),
                codename='change_surfacenote',
                defaults={'name': 'Can change surface note'},
            )[0]
            other = Permission.objects.create(
                content_type=change.content_type,
                codename='view_surfacenote',
                name='Can view surface note',
            )
            alice = User.objects.create_user('alice-333s', password='x')
            bob = User.objects.create_user('bob-333s', password='x')
            carol = User.objects.create_user('carol-333s', password='x')
            dave = User.objects.create_user('dave-333s', password='x')
            bob.last_login = bob.date_joined + timedelta(days=1)
            bob.save(update_fields=['last_login'])
            alice.is_staff = True
            alice.save(update_fields=['is_staff'])
            alice = User.objects.get(pk=alice.pk)
            bob = User.objects.get(pk=bob.pk)
            group = Group.objects.create(name='surface-333')
            alice.groups.add(group)
            carol.groups.add(group)
            notes = []
            grants = {}
            links = {}
            for spec in _SPECS:
                note = Note.objects.create()
                notes.append(note)
                for holder in (alice, bob):
                    grant = _store_row(
                        Grant, spec, mark, markers, note=note, user=holder,
                        permission=change,
                    )
                    grants[(holder.pk, note.pk)] = grant
                if spec['left'] == 1 and spec['right'] == 2:
                    token = None
                elif spec['marked']:
                    token = other
                else:
                    token = change
                link = _store_row(
                    Link, spec, mark, markers, note=note, delegate=bob,
                    sponsor=alice, token=token,
                )
                links[note.pk] = link
            notes = tuple(notes)
            users = (alice, bob, carol)
            self._relation(Grant, Note, mark, alice, notes, users, grants)
            Grant.objects.filter(user=bob).delete()
            self._delegated(
                Grant, Link, Note, mark, change, notes, alice, bob, carol,
                links,
            )
            for note in notes:
                Grant.objects.create(
                    note=note, user=bob, permission=change,
                )
            self._user_rules(
                Grant, Note, notes, alice, bob, carol, dave, group,
            )

    def _relation(self, Grant, Note, mark, alice, notes, users, grants):
        cases = _relation_cases(mark.pk) + (
            (
                'eq-user',
                _saved_user(alice),
                lambda row: row.user_id == alice.pk,
            ),
        )
        for name, builder, predicate in cases:
            factory = compiler(path=BACKEND)
            factory.register(
                trust=Grant, user='user', permission='permission',
                content='note', condition=builder,
            )
            def allowed(user, note, predicate=predicate):
                grant = grants.get((user.pk, note.pk))
                if grant is None:
                    return False
                return predicate(grant)
            with self.subTest(surface='relation', kind=name):
                with _published(factory):
                    _agree(self, Note, PERM, users, notes, allowed)

    def _delegated(self, Grant, Link, Note, mark, change, notes, alice, bob,
                   carol, links):
        cases = _relation_cases(mark.pk) + (
            (
                'ne-permission',
                lambda row, permission: row.token != permission,
                lambda row: (
                    row.token_id is not None and row.token_id != change.pk
                ),
            ),
        )
        users = (alice, bob, carol)
        for name, builder, predicate in cases:
            factory = compiler(path=BACKEND)
            factory.register(
                trust=Grant, user='user', permission='permission',
                content='note',
            )
            factory.register(
                trust=Link, delegate='delegate', sponsor='sponsor',
                content='note', condition=builder,
            )

            def allowed(user, note, predicate=predicate):
                if user.pk == alice.pk:
                    return True
                if user.pk != bob.pk:
                    return False
                return predicate(links[note.pk])

            with self.subTest(surface='delegated', kind=name):
                with _published(factory):
                    _agree(self, Note, PERM, users, notes, allowed)

    def _user_rules(self, Grant, Note, notes, alice, bob, carol, dave, group):
        granted = {alice.pk, bob.pk}
        cases = (
            (
                'eq_const',
                lambda u: u.username == 'alice-333s',
                lambda user: user.username == 'alice-333s',
            ),
            (
                'ne_const',
                lambda u: u.username != 'alice-333s',
                lambda user: user.username != 'alice-333s',
            ),
            (
                'eq_null',
                lambda u: u.last_login == None,  # noqa: E711
                lambda user: user.last_login is None,
            ),
            (
                'ne_fields',
                lambda u: u.last_login != u.date_joined,
                lambda user: (
                    user.last_login is not None
                    and user.date_joined is not None
                    and user.last_login != user.date_joined
                ),
            ),
            (
                'either',
                lambda u: u.is_staff | u.is_superuser,
                lambda user: user.is_staff is True or user.is_superuser is True,
            ),
            (
                'contains',
                lambda u, member=group: u.groups.contains(member),
                lambda user: user.groups.filter(pk=group.pk).exists(),
            ),
            (
                'eq_self',
                lambda u, saved=alice: u == saved,
                lambda user: user.pk == alice.pk,
            ),
            (
                'off',
                lambda u: ~u.is_staff,
                lambda user: user.is_staff is not True,
            ),
        )
        for name, builder, predicate in cases:
            factory = compiler(path=BACKEND)
            factory.set_user_condition(name, builder)
            factory.register(
                trust=Grant, user='user', permission='permission',
                content='note',
            )

            def allowed(user, note, predicate=predicate):
                return user.pk in granted and predicate(user)

            with self.subTest(surface='user', kind=name):
                with _published(factory):
                    _agree(self, Note, PERM, (alice, bob, carol, dave), notes, allowed)
        factory = compiler(path=BACKEND)
        factory.set_user_override(
            'picked', lambda u, member=group: u.groups.contains(member),
        )
        factory.register(
            trust=Grant, user='user', permission='permission', content='note',
        )

        def override_allowed(user, note):
            if user.pk in granted:
                return True
            return user.groups.filter(pk=group.pk).exists()

        with self.subTest(surface='override', kind='contains'):
            with _published(factory):
                _agree(
                    self, Note, PERM, (alice, bob, carol, dave), notes,
                    override_allowed,
                )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class RemainingLimitsTest(SimpleTestCase):
    """Kinds that cannot mean the same thing on every check stay rejected."""

    def test_field_member_contains_and_permission_hops_stay_rejected(self):
        User = get_user_model()

        class SurfaceCeiling(models.Model):
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, on_delete=models.CASCADE, related_name='+',
            )
            document = models.ForeignKey(
                'myapp.Document', on_delete=models.CASCADE,
            )
            label = models.ForeignKey(
                User, null=True, on_delete=models.CASCADE, related_name='+',
            )
            marks = models.ManyToManyField(User, related_name='+')

            class Meta:
                app_label = 'trusts_tests'

        class SurfaceHop(models.Model):
            document = models.ForeignKey(
                'myapp.Document', on_delete=models.CASCADE,
            )
            delegate = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            sponsor = models.ForeignKey(
                User, on_delete=models.CASCADE, related_name='+',
            )
            allowed = models.ManyToManyField(Permission, related_name='+')

            class Meta:
                app_label = 'trusts_tests'

        handle = compiler()
        with self.assertRaisesRegex(PermissionConditionError, 'permission path'):
            handle.register(
                trust=SurfaceCeiling, user='user', permission='permission',
                content='document',
                condition=lambda t: t.marks.contains(t.label),
            )
        with self.assertRaisesRegex(
            PermissionConditionError, 'row-only delegated',
        ):
            handle.register(
                trust=SurfaceHop, delegate='delegate', sponsor='sponsor',
                content='document',
                condition=lambda row: row.allowed.contains(row.delegate),
            )
        with self.assertRaisesRegex(
            PermissionConditionError, 'field on the requested permission',
        ):
            handle.register(
                trust=SurfaceHop, delegate='delegate', sponsor='sponsor',
                content='document',
                condition=lambda row, permission: (
                    permission.codename == 'change_document'
                ),
            )
        with self.assertRaisesRegex(
            PermissionConditionError, 'requested permission to a constant',
        ):
            handle.register(
                trust=SurfaceHop, delegate='delegate', sponsor='sponsor',
                content='document',
                condition=lambda row, permission: permission == 'change_document',
            )
        self.assertEqual(handle.records, ())
        self.assertEqual(handle.delegations, ())

    def test_bare_field_error_names_the_model_that_holds_the_field(self):
        with self.assertRaisesRegex(
            PermissionConditionError, r'not myapp\.Document\.title\.',
        ):
            compiler().register(
                trust=DocumentGrant, user='user', permission='permission',
                content='document', condition=lambda t: t.document.title,
            )
        with self.assertRaisesRegex(
            PermissionConditionError, r'not myapp\.Document\.title\.',
        ):
            compiler().add_named_filter(
                DocumentGrant, 'titled', lambda u, p, o: o.document.title,
            )

    def test_plain_object_condition_raises_permission_condition_error(self):
        grant = Ref(DocumentGrant)
        delegation = Ref(DocumentDelegation)
        with self.assertRaises(PermissionConditionError):
            compiler().register_relation(
                content=grant.document, user=grant.user,
                permission=grant.permission, condition=object(),
            )
        with self.assertRaises(PermissionConditionError):
            compiler().build_delegation(
                content=delegation.document, delegate=delegation.delegate,
                sponsor=delegation.sponsor, condition=object(),
            )

    def test_role_path_uses_the_shared_builder(self):
        with self.assertRaises(PermissionConditionError):
            compiler().register(
                trust=DocumentGrant, user=lambda t: t.user['pk'],
                permission='permission', content='document',
            )
        with self.assertRaises(PermissionConditionError):
            compiler().register(
                trust=DocumentGrant, user=lambda t: t.user(),
                permission='permission', content='document',
            )
        with self.assertRaises(PermissionConditionError):
            compiler().register(
                trust=DocumentGrant, user=lambda t: t.user == t.document,
                permission='permission', content='document',
            )
        record = compiler().register(
            trust=DocumentGrant, user=lambda t: t.user,
            permission=lambda t: t.permission,
            content=lambda t: t.document,
        )
        self.assertEqual(record.user_path, ('user',))
        self.assertEqual(record.permission_path, ('permission',))
        self.assertEqual(record.content_path, ('document',))
