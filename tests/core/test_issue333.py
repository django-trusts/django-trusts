"""#333: one condition tree, one NULL rule, and one duplicate rule.

A field compared with a constant follows Python. Two fields never match
when either side is NULL. ``has_perm``, ``permitted()``, and
``get_permitted_users`` give the same answer for every named filter.
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
from django.utils import timezone

from trusts.backends import TrustModelBackendMixin
from trusts.errors import PermissionConditionError
from trusts.models import PermittedQuerySet, PermittedUsersMixin
from tests.support import compiler, published_class_catalog

PERM = 'trusts_tests.change_pair'


class _PairBackend(TrustModelBackendMixin, ModelBackend):
    pass


def _both_set(left, right):
    return left is not None and right is not None


def _owner(row):
    return row.owner_id


def _marked(row):
    if row.label_id is None:
        return False
    return row.marks.filter(pk=row.label_id).exists()


def _on_team(user, row):
    if row.team_id is None:
        return False
    return user.groups.filter(pk=row.team_id).exists()


# Python oracle for each named filter: ``(builder, allowed(user, row))``.
FILTERS = {
    'same': (
        lambda u, p, o: o.left == o.right,
        lambda u, r: _both_set(r.left, r.right) and r.left == r.right,
    ),
    'differ': (
        lambda u, p, o: o.left != o.right,
        lambda u, r: _both_set(r.left, r.right) and r.left != r.right,
    ),
    'blank': (
        lambda u, p, o: o.left == None,  # noqa: E711
        lambda u, r: r.left is None,
    ),
    'not_five': (
        lambda u, p, o: o.left != 5,
        lambda u, r: r.left != 5,
    ),
    'not_owner': (
        lambda u, p, o: u != o.owner,
        lambda u, r: _owner(r) is not None and _owner(r) != u.pk,
    ),
    'login': (
        lambda u, p, o: u.last_login == o.opened,
        lambda u, r: (
            _both_set(u.last_login, r.opened) and u.last_login == r.opened
        ),
    ),
    'not_login': (
        lambda u, p, o: u.last_login != o.opened,
        lambda u, r: (
            _both_set(u.last_login, r.opened) and u.last_login != r.opened
        ),
    ),
    'self_login': (
        lambda u, p, o: u.last_login == u.last_login,
        lambda u, r: u.last_login is not None,
    ),
    'never_seen': (
        lambda u, p, o: u.last_login == None,  # noqa: E711
        lambda u, r: u.last_login is None,
    ),
    'either': (
        lambda u, p, o: (o.left == o.right) | (o.left == None),  # noqa: E711
        lambda u, r: (
            (_both_set(r.left, r.right) and r.left == r.right)
            or r.left is None
        ),
    ),
    'login_or_owner': (
        lambda u, p, o: (u.last_login == o.opened) | (u == o.owner),
        lambda u, r: (
            (_both_set(u.last_login, r.opened) and u.last_login == r.opened)
            or _owner(r) == u.pk
        ),
    ),
    'seen_not_owner': (
        lambda u, p, o: (u.last_login == u.last_login) & (u != o.owner),
        lambda u, r: (
            u.last_login is not None
            and _owner(r) is not None and _owner(r) != u.pk
        ),
    ),
    'both': (
        lambda u, p, o: (o.left != 5) & (u != o.owner),
        lambda u, r: (
            r.left != 5 and _owner(r) is not None and _owner(r) != u.pk
        ),
    ),
    'flagged': (
        lambda u, p, o: o.flag,
        lambda u, r: r.flag is True,
    ),
    'not_flagged': (
        lambda u, p, o: ~o.flag,
        lambda u, r: r.flag is not True,
    ),
    'staff': (
        lambda u, p, o: u.is_staff,
        lambda u, r: u.is_staff is True,
    ),
    'not_staff': (
        lambda u, p, o: ~u.is_staff,
        lambda u, r: u.is_staff is not True,
    ),
    'marked': (
        lambda u, p, o: o.marks.contains(o.label),
        lambda u, r: _marked(r),
    ),
    'on_team': (
        lambda u, p, o: u.groups.contains(o.team),
        lambda u, r: _on_team(u, r),
    ),
    'off_and_same': (
        lambda u, p, o: ~o.flag & (o.left == o.right),
        lambda u, r: (
            r.flag is not True
            and _both_set(r.left, r.right)
            and r.left == r.right
        ),
    ),
    'off_or_marked': (
        lambda u, p, o: ~o.flag | o.marks.contains(o.label),
        lambda u, r: r.flag is not True or _marked(r),
    ),
}


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


def _pair_models():
    User = get_user_model()

    class Mark(models.Model):

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue333_mark'

    class Pair(PermittedUsersMixin, models.Model):
        left = models.IntegerField(null=True)
        right = models.IntegerField(null=True)
        owner = models.ForeignKey(
            User, null=True, on_delete=models.CASCADE, related_name='+',
        )
        opened = models.DateTimeField(null=True)
        flag = models.BooleanField(null=True)
        label = models.ForeignKey(
            Mark, null=True, on_delete=models.CASCADE, related_name='+',
        )
        team = models.ForeignKey(
            Group, null=True, on_delete=models.CASCADE, related_name='+',
        )
        marks = models.ManyToManyField(Mark, related_name='+')
        objects = models.Manager.from_queryset(PermittedQuerySet)()

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue333_pair'

    class PairGrant(models.Model):
        pair = models.ForeignKey(Pair, on_delete=models.CASCADE)
        user = models.ForeignKey(
            User, on_delete=models.CASCADE, related_name='+',
        )
        permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

        class Meta:
            app_label = 'trusts_tests'
            db_table = 'issue333_pairgrant'

    return Mark, Pair, PairGrant


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class NullRuleAgreementTest(TransactionTestCase):
    """Every surface reads one tree and applies one NULL rule."""

    def test_has_perm_permitted_and_permitted_users_follow_the_null_rule(self):
        User = get_user_model()
        Mark, Pair, PairGrant = _pair_models()
        backend = 'tests.core.test_issue333._PairBackend'
        with _tables(Mark, Pair, PairGrant):
            mark_a = Mark.objects.create()
            held = mark_a.pk
            filters = dict(FILTERS)
            filters['holds_a'] = (
                lambda u, p, o, mark=held: o.marks.contains(mark),
                lambda u, r, mark=held: r.marks.filter(pk=mark).exists(),
            )
            factory = compiler(path='tests.core.test_issue333._PairBackend')
            factory.register(
                trust=PairGrant, user='user', permission='permission',
                content='pair',
            )
            for code, (builder, _allowed) in filters.items():
                factory.add_named_filter(Pair, code, builder)
            with published_class_catalog(
                _PairBackend, factory,
            ), override_settings(AUTHENTICATION_BACKENDS=(backend,)):
                when = timezone.now().replace(microsecond=0)
                alice = User.objects.create_user('alice-333', password='x')
                bob = User.objects.create_user('bob-333', password='x')
                bob.last_login = when
                bob.is_staff = True
                bob.save(update_fields=['last_login', 'is_staff'])
                mark_b = Mark.objects.create()
                group_a = Group.objects.create(name='a-333')
                group_b = Group.objects.create(name='b-333')
                alice.groups.add(group_a)
                change = Permission.objects.create(
                    content_type=ContentType.objects.get_for_model(Pair),
                    codename='change_pair',
                    name='Can change pair',
                )
                rows = (
                    Pair.objects.create(),
                    Pair.objects.create(
                        left=1, right=1, owner=alice, flag=True,
                        label=mark_a, team=group_a,
                    ),
                    Pair.objects.create(
                        left=1, right=2, owner=bob, flag=False,
                        label=mark_b, team=group_b,
                    ),
                    Pair.objects.create(left=5, right=5, label=mark_a),
                    Pair.objects.create(
                        opened=when, flag=True, label=mark_a, team=group_a,
                    ),
                    Pair.objects.create(
                        opened=when + timedelta(hours=1), flag=False,
                    ),
                )
                rows[1].marks.add(mark_a)
                rows[2].marks.add(mark_a)
                rows[3].marks.add(mark_a)
                for row in rows:
                    for holder in (alice, bob):
                        PairGrant.objects.create(
                            pair=row, user=holder, permission=change,
                        )
                users = tuple(User.objects.get(pk=u.pk) for u in (alice, bob))
                rows = tuple(Pair.objects.get(pk=row.pk) for row in rows)
                for code, (_builder, allowed) in filters.items():
                    filtered = '%s:%s' % (PERM, code)
                    for user in users:
                        expected = {
                            row.pk for row in rows if allowed(user, row)
                        }
                        with self.subTest(code=code, user=user.username):
                            listed = Pair.objects.permitted(
                                PERM, user, conditions=(code,),
                            ).values_list('pk', flat=True)
                            self.assertEqual(set(listed), expected)
                            held = {
                                row.pk for row in rows
                                if user.has_perm(filtered, row)
                            }
                            self.assertEqual(held, expected)
                    for row in rows:
                        expected = {u.pk for u in users if allowed(u, row)}
                        with self.subTest(code=code, row=row.pk):
                            found = row.get_permitted_users(filtered)
                            self.assertEqual(
                                set(found.values_list('pk', flat=True)),
                                expected,
                            )


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class DuplicateNamedFilterTest(SimpleTestCase):

    def test_second_filter_with_one_code_raises_and_is_never_built(self):
        _Mark, Pair, _PairGrant = _pair_models()
        calls = []

        def second(u, p, o):
            calls.append(1)
            return o.left == 2

        registry = compiler()
        registry.add_named_filter(
            Pair, 'pick', lambda u, p, o: o.left == 1,
        )
        with self.assertRaisesRegex(
            PermissionConditionError, "'pick' is already registered",
        ):
            registry.add_named_filter(Pair, 'pick', second)
        self.assertEqual(calls, [])
