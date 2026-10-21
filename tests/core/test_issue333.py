"""#333: one condition tree, one NULL rule, and one duplicate rule.

A field compared with a constant follows Python. Two fields never match
when either side is NULL. ``has_perm``, ``permitted()``, and
``get_permitted_users`` give the same answer for every named filter.
"""
from contextlib import contextmanager
from datetime import timedelta

from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.test import SimpleTestCase, TransactionTestCase, override_settings
from django.test.utils import isolate_apps
from django.utils import timezone

import tests as tests_module
from trusts.apps import Recorder, TrustsConfigMixin
from trusts.backends import TrustModelBackendMixin
from trusts.conditions import PermissionConditionError
from trusts.models import PermittedQuerySet, PermittedUsersMixin
from tests.support import compiler, published_class_catalog

PERM = 'trusts_tests.change_pair'


class _PairBackend(TrustModelBackendMixin, ModelBackend):
    pass


def _both_set(left, right):
    return left is not None and right is not None


def _owner(row):
    return row.owner_id


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
    'both': (
        lambda u, p, o: (o.left != 5) & (u != o.owner),
        lambda u, r: (
            r.left != 5 and _owner(r) is not None and _owner(r) != u.pk
        ),
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

    class Pair(PermittedUsersMixin, models.Model):
        left = models.IntegerField(null=True)
        right = models.IntegerField(null=True)
        owner = models.ForeignKey(
            User, null=True, on_delete=models.CASCADE, related_name='+',
        )
        opened = models.DateTimeField(null=True)
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

    return Pair, PairGrant


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class NullRuleAgreementTest(TransactionTestCase):
    """Every surface reads one tree and applies one NULL rule."""

    def test_has_perm_permitted_and_permitted_users_follow_the_null_rule(self):
        User = get_user_model()
        Pair, PairGrant = _pair_models()
        recorder = Recorder()
        recorder.register(
            trust=PairGrant, user='user', permission='permission',
            content='pair',
        )
        for code, (builder, _allowed) in FILTERS.items():
            recorder.add_named_filter(Pair, code, builder)
        recorder.freeze()
        factory = compiler(path='tests.core.test_issue333._PairBackend')
        recorder.play(factory.get_recorder_target())
        backend = 'tests.core.test_issue333._PairBackend'
        with _tables(Pair, PairGrant), published_class_catalog(
            _PairBackend, factory,
        ), override_settings(AUTHENTICATION_BACKENDS=(backend,)):
            when = timezone.now().replace(microsecond=0)
            alice = User.objects.create_user('alice-333', password='x')
            bob = User.objects.create_user('bob-333', password='x')
            bob.last_login = when
            bob.save(update_fields=['last_login'])
            change = Permission.objects.create(
                content_type=ContentType.objects.get_for_model(Pair),
                codename='change_pair',
                name='Can change pair',
            )
            rows = (
                Pair.objects.create(),
                Pair.objects.create(left=1, right=1, owner=alice),
                Pair.objects.create(left=1, right=2, owner=bob),
                Pair.objects.create(left=5, right=5),
                Pair.objects.create(opened=when),
                Pair.objects.create(opened=when + timedelta(hours=1)),
            )
            for row in rows:
                for holder in (alice, bob):
                    PairGrant.objects.create(
                        pair=row, user=holder, permission=change,
                    )
            users = tuple(User.objects.get(pk=u.pk) for u in (alice, bob))
            rows = tuple(Pair.objects.get(pk=row.pk) for row in rows)
            for code, (_builder, allowed) in FILTERS.items():
                filtered = '%s:%s' % (PERM, code)
                for user in users:
                    expected = {row.pk for row in rows if allowed(user, row)}
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
        Pair, _PairGrant = _pair_models()

        class _Config(TrustsConfigMixin):
            name = 'tests.core.fresh333'
            label = 'fresh333'

        calls = []

        def second(u, p, o):
            calls.append(1)
            return o.left == 2

        config = _Config('tests.core.fresh333', tests_module)
        config.recorder.add_named_filter(
            Pair, 'pick', lambda u, p, o: o.left == 1,
        )
        config.recorder.add_named_filter(Pair, 'pick', second)
        with self.assertRaisesRegex(
            PermissionConditionError, "'pick' is already registered",
        ):
            config.ready()
        self.assertEqual(calls, [])
