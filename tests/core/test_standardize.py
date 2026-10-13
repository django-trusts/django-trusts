"""Private standardize() rewrite. Not a public contract.

The flag defaults off. These tests turn it on inside ``scope`` only.
"""

from contextlib import contextmanager

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.db.models import Exists, Q
from django.test import TestCase, TransactionTestCase

from trusts._standardize import (
    BIND_ALIAS,
    BindRef,
    _StandardWalk,
    enabled,
    execute_exists,
    scope,
    standardize,
)
from trusts.core import (
    Along,
    GrantReach,
    Ref,
    TrustsRegistry,
    _as_q,
)
from trusts.policy_lock import _compile_queryset


def _sql(qs):
    sql, params = qs.query.get_compiler(using='default').as_sql()
    return sql, tuple(params)


class StandardizeFlagTest(TestCase):
    def test_flag_defaults_off(self):
        self.assertIs(enabled(), False)

    def test_off_returns_the_queryset_unchanged(self):
        User = get_user_model()
        qs = User.objects.filter(is_active=True).filter(is_active=True)
        before, before_params = _sql(qs)
        out = standardize(qs)
        self.assertIs(out, qs)
        after, after_params = _sql(qs)
        self.assertEqual(after, before)
        self.assertEqual(after_params, before_params)
        self.assertNotIn(BIND_ALIAS, after)
        self.assertGreater(after_params.count(True), 1)

    def test_on_binds_a_repeated_value_once(self):
        User = get_user_model()
        qs = User.objects.filter(is_active=True).filter(is_active=True)
        before, _before_params = _sql(qs)
        with scope(True):
            out = standardize(qs)
            sql, params = _sql(out)
            again, again_params = _sql(standardize(out))
        self.assertIn(BIND_ALIAS, sql)
        self.assertIn('CROSS JOIN (SELECT ', sql)
        self.assertEqual(sql.count('%s'), len(params))
        self.assertEqual(params.count(True), 1)
        self.assertEqual(again, sql)
        self.assertEqual(again_params, params)
        original, _params = _sql(qs)
        self.assertEqual(original, before)
        self.assertNotIn(BIND_ALIAS, original)

    def test_a_single_value_stays_in_place(self):
        User = get_user_model()
        qs = User.objects.filter(is_active=True)
        with scope(True):
            out = standardize(qs)
        sql, _params = _sql(out)
        self.assertNotIn(BIND_ALIAS, sql)
        self.assertIs(out, qs)

    def test_in_list_and_isnull_are_not_hoisted(self):
        User = get_user_model()
        qs = User.objects.filter(pk__in=[5, 5]).filter(email__isnull=True)
        with scope(True):
            out = standardize(qs)
        sql, _params = _sql(out)
        self.assertNotIn(BIND_ALIAS, sql)

    def test_exists_value_is_included(self):
        User = get_user_model()
        qs = User.objects.filter(
            Exists(User.objects.filter(is_active=True)),
            Exists(User.objects.filter(is_active=True)),
        )
        plain, plain_params = _sql(qs)
        with scope(True):
            out = standardize(qs)
        sql, params = _sql(out)
        self.assertIn(BIND_ALIAS, sql)
        self.assertEqual(sql.count('%s'), len(params))
        self.assertEqual(sum(param is True for param in params), 1)
        self.assertEqual(sum(param == 1 and param is not True for param in params), 1)
        self.assertNotIn('LIMIT 1) =', sql)
        self.assertGreater(sum(param is True for param in plain_params), 1)
        self.assertGreater(
            sum(param == 1 and param is not True for param in plain_params), 1,
        )

    def test_execute_exists_matches_plain_result(self):
        User = get_user_model()
        user = User.objects.create_user(username='std-exists', password='x')
        qs = User.objects.filter(pk=user.pk).filter(pk=user.pk)
        self.assertIs(execute_exists(qs), True)
        with scope(True):
            self.assertIs(execute_exists(qs), True)
        missing = User.objects.filter(pk=user.pk).filter(username='missing')
        with scope(True):
            self.assertIs(execute_exists(missing), False)

    def test_lockfile_compiler_classifies_the_bind_row(self):
        User = get_user_model()
        qs = User.objects.filter(is_active=True).filter(is_active=True)
        with scope(True):
            sql, symbols = _compile_queryset(
                qs, 'default', record=None, expr=None,
            )
        self.assertIn(BIND_ALIAS, sql)
        self.assertEqual(len(symbols), sql.count('%s'))
        self.assertEqual(symbols, [{
            'const': True,
            'hint': 'active',
        }])


class _DepthProbe(object):
    def as_sql(self, compiler, connection):
        del compiler, connection
        return '("g"."depth" < %s)', (4,)

    def resolve_expression(self, *args, **kwargs):
        del args, kwargs
        return self

    def relabeled_clone(self, change_map):
        del change_map
        return self

    @property
    def output_field(self):
        from django.db.models import BooleanField
        return BooleanField()

    def get_source_expressions(self):
        return []

    contains_aggregate = False
    contains_over_clause = False
    filterable = True


class StandardizeDepthTest(TestCase):
    def test_depth_cap_placeholder_becomes_a_column(self):
        from django.db.models import IntegerField

        walk = _StandardWalk(
            _DepthProbe(),
            BindRef(BIND_ALIAS, 'along_bound', IntegerField()),
        )
        compiler = get_user_model().objects.all().query.get_compiler('default')
        sql, params = walk.as_sql(compiler, connection)
        self.assertIn('"g"."depth" < "trusts_bind"."along_bound"', sql)
        self.assertNotIn('%s', sql)
        self.assertEqual(params, ())


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


class StandardizeAlongTest(TransactionTestCase):
    def test_two_walks_share_one_depth_cap(self):
        User = get_user_model()

        class Node(models.Model):
            parent = models.ForeignKey(
                'self', null=True, related_name='std_children',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class NodeGrant(models.Model):
            node = models.ForeignKey(Node, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with _tables(Node, NodeGrant):
            alice = User.objects.create_user(username='std-along', password='x')
            content_type, _created = ContentType.objects.get_or_create(
                app_label='trusts_tests', model='stdnode',
            )
            read, _created = Permission.objects.get_or_create(
                content_type=content_type,
                codename='read_std',
                defaults={'name': 'read_std'},
            )
            registry = TrustsRegistry()
            grant = Ref(NodeGrant)
            record = registry.register(
                content=grant.node,
                user=grant.user,
                permission=grant.permission,
                along=Along(grant.node.parent, bound=4),
            )
            left = GrantReach(record, alice, read)
            right = GrantReach(record, alice, read)
            qs = Node.objects.filter(_as_q(left) | _as_q(right))
            plain, plain_params = _sql(qs)
            with scope(True):
                sql, params = _sql(standardize(qs))
        self.assertEqual(plain_params.count(4), 2)
        self.assertIn(BIND_ALIAS, sql)
        self.assertEqual(sql.count('%s'), len(params))
        self.assertEqual(params.count(4), 1)
        self.assertIn('depth', sql)
        self.assertIn(BIND_ALIAS, sql.split('depth')[-1])
        self.assertNotIn(BIND_ALIAS, plain)
