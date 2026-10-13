"""One placeholder per inquiry value, and ``is_active`` in the statement (#300)."""

from collections import Counter

from django.contrib.auth.models import Permission, User
from django.contrib.contenttypes.models import ContentType
from django.db.models import FloatField, IntegerField, OuterRef, Value
from django.test import SimpleTestCase, TestCase

from tests.core.test_issue147.test_sql_export import _document_handle
from tests.myapp.models import Document
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.binds import (
    BIND_ALIAS,
    BindRef,
    BindTable,
    SqlInt,
    bind_scope,
    hoist,
    seal,
    strip_exists_marker,
)
from trusts.core import TrustsConfigurationError
from trusts.policy_lock import _load_policy_sql_document, render_policy_sql_bytes
from trusts.query import stored_user_is_inactive
from trusts.reverse import compile_permitted_users


PERM = 'myapp.change_document'


def _repeat_count(params):
    keys = []
    for param in params:
        if 'bind' in param:
            keys.append(('bind', param['bind']))
        else:
            keys.append(('const', param.get('hint'), repr(param.get('const'))))
    counts = Counter(keys)
    return sum(count - 1 for count in counts.values() if count > 1)


class Issue300SuiteRegistrationTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue300', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue300', PAIR_KERNEL_SUITE)


class Issue300LockfileTest(SimpleTestCase):
    def test_each_distinct_value_is_one_placeholder_and_content_type_stays(self):
        document = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[_document_handle()]),
        )
        content = document['backends'][0]['contents'][0]
        for key in (
            'permitted', 'has_perm', 'get_all_permissions', 'get_permitted_users',
        ):
            row = content[key]
            self.assertEqual(_repeat_count(row['params']), 0, key)
            self.assertEqual(row['sql'].count('%s'), len(row['params']))
            self.assertIn('trusts_bind', row['sql'])
            self.assertIn('SELECT 1 AS "a"', row['sql'])
            hints = [param.get('hint') for param in row['params']]
            self.assertIn('content type app', hints)
            self.assertIn('content type model', hints)
        users = content['get_permitted_users']
        self.assertIn({'const': True, 'hint': 'active'}, users['params'])
        self.assertIn('"is_active" = %s', users['sql'])
        self.assertNotIn('allow_inactive', users['sql'])
        for key in (
            'permitted', 'has_perm', 'get_all_permissions', 'get_permitted_users',
        ):
            self.assertFalse(any(
                param.get('hint') == 'allow inactive'
                for param in content[key]['params']
            ))


class Issue300EligibilitySqlTest(SimpleTestCase):
    def test_is_active_equality_is_added_only_when_inactive_users_are_denied(self):
        document = Document(title='note-300', pk=1)
        denied = compile_permitted_users(
            document, PERM, allow_inactive=False,
        )
        included = compile_permitted_users(
            document, PERM, allow_inactive=True,
        )
        denied_sql, _denied_params = denied.query.sql_with_params()
        included_sql, _included_params = included.query.sql_with_params()
        self.assertNotEqual(denied_sql, included_sql)
        self.assertNotIn('allow_inactive', denied_sql)
        self.assertNotIn('allow_inactive', included_sql)
        self.assertNotIn('OR "auth_user"."is_active"', denied_sql)
        # The superuser branch always compares is_active. The Trusts
        # branch adds that comparison only when inactive users are denied.
        self.assertGreater(
            denied_sql.count('"is_active" = %s'),
            included_sql.count('"is_active" = %s'),
        )


class Issue300BooleanFieldTest(TestCase):
    def test_authorized_denies_a_non_model_without_is_active_and_none_raises(self):
        class Authenticated(object):
            is_authenticated = True
            is_anonymous = False
            pk = 1

        content_type = ContentType.objects.get_for_model(Document)
        permission, _created = Permission.objects.get_or_create(
            content_type=content_type,
            codename='change_document',
            defaults={'name': 'Can change document'},
        )
        self.assertTrue(stored_user_is_inactive(Authenticated()))
        self.assertFalse(stored_user_is_inactive(object()))
        with self.assertNumQueries(0):
            self.assertFalse(
                Document.objects.authorized(Authenticated(), permission).exists()
            )
        with self.assertRaises(TrustsConfigurationError):
            Document.objects.authorized(None, permission)
        with self.assertRaises(TrustsConfigurationError):
            Document.objects.authorized(object(), permission)


class Issue300BindRowTest(SimpleTestCase):
    def test_distinct_tokens_nulls_and_digit_names_are_one_row(self):
        with bind_scope():
            hoist(1.0, FloatField(), hint='along bound')
            hoist(1.0, FloatField(), hint='along bound')
            hoist(1, IntegerField(), hint='along bound')
            hoist(None, IntegerField(), hint='content pk')
            hoist(None, None, hint='2nd')
            queryset = User.objects.all()
            seal(queryset)
        sql, params = queryset.query.sql_with_params()
        self.assertIn('AS "along_bound"', sql)
        self.assertIn('AS "along_bound_2"', sql)
        self.assertIn('NULL AS "content_pk"', sql)
        self.assertIn('NULL AS "v_2nd"', sql)
        self.assertEqual(sql.count('%s'), 2)
        self.assertEqual(list(params), [1.0, 1])
        table = queryset.query.alias_map[BIND_ALIAS]
        self.assertIs(table.promote(), table)
        self.assertIs(table.demote(), table)
        self.assertEqual(hash(table), hash(BindTable(table.columns)))
        classified = [table.next_column().sql_name for _ in range(4)]
        self.assertEqual(
            classified,
            ['along_bound', 'along_bound_2', 'content_pk', 'v_2nd'],
        )
        with self.assertRaises(IndexError):
            table.next_column()

    def test_nested_scope_reuses_the_row_and_a_later_scope_replaces_it(self):
        outer_ref = OuterRef('pk')
        with bind_scope() as outer_sheet:
            with bind_scope() as inner_sheet:
                self.assertIs(inner_sheet, outer_sheet)
                self.assertIs(
                    hoist(outer_ref, IntegerField(), bind='user.id'),
                    outer_ref,
                )
                hoist(4, IntegerField())
            queryset = User.objects.all()
            seal(queryset)
            installed = queryset.query.alias_map[BIND_ALIAS]
            outer_sheet.sealed = False
            seal(queryset)
            self.assertIs(queryset.query.alias_map[BIND_ALIAS], installed)
        sql, params = queryset.query.sql_with_params()
        self.assertIn('AS "literal"', sql)
        self.assertEqual(list(params), [4])
        self.assertEqual(sql.count('CROSS JOIN'), 1)

        with bind_scope():
            hoist(4, IntegerField())
            hoist(False, IntegerField(), hint='second flag')
            seal(queryset)
        replaced, replaced_params = queryset.query.sql_with_params()
        self.assertIn('AS "literal"', replaced)
        self.assertIn('AS "second_flag"', replaced)
        self.assertEqual(replaced.count('CROSS JOIN'), 1)
        self.assertEqual(len(replaced_params), 2)
        self.assertEqual(replaced_params[0], 4)
        self.assertFalse(replaced_params[1])

    def test_exists_marker_strip_ignores_other_queries(self):
        query = User.objects.all().query
        self.assertIs(strip_exists_marker(query), query)
        self.assertNotIn('a', query.annotations)

    def test_predicates_reject_source_expressions_that_would_add_placeholders(self):
        ref = BindRef(BIND_ALIAS, 'user_id', IntegerField())
        self.assertEqual(ref.get_group_by_cols(), [])
        ref.set_source_expressions([])
        with self.assertRaises(TypeError):
            ref.set_source_expressions([Value(1)])

        marker = SqlInt(1)
        marker.set_source_expressions([])
        with self.assertRaises(TypeError):
            marker.set_source_expressions([Value(1)])
