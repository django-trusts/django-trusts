"""One placeholder per inquiry value, and ``is_active`` in the statement (#300)."""

from collections import Counter
from unittest.mock import patch

from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import Permission, User
from django.contrib.contenttypes.models import ContentType
from django.db import models
from django.db.models import BooleanField, F, FloatField, IntegerField, OuterRef, Value
from django.test import SimpleTestCase, TestCase

from tests.core.test_issue147.test_sql_export import _document_handle
from tests.myapp.models import Document, DocumentGrant
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts.binds import (
    BIND_ALIAS,
    AllowOr,
    BindRef,
    BindTable,
    BooleanPredicate,
    SqlInt,
    SqlTrue,
    bind_scope,
    hoist,
    seal,
    strip_exists_marker,
)
from trusts.checks import CHECK_ID_INACTIVE_PRINCIPAL, check_principal_is_active
from trusts.core import TrustsConfigurationError
from trusts.policy_lock import _load_policy_sql_document, render_policy_sql_bytes
from trusts.query import (
    active_eligibility_q,
    principal_attribute_kind,
    stored_user_is_inactive,
)
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
        self.assertIn(
            {'const': False, 'hint': 'allow inactive'}, users['params'],
        )
        self.assertIn('OR "auth_user"."is_active"', users['sql'])
        self.assertNotIn('is_active" = %s', users['sql'])


class Issue300PrincipalCheckTest(SimpleTestCase):
    def test_configured_user_model_has_no_e010(self):
        self.assertEqual(check_principal_is_active(None), [])

    def test_missing_is_active_is_e010_and_refuses_to_compile(self):
        class Plain(models.Model):
            name = models.CharField(max_length=20)

            class Meta:
                app_label = 'myapp'

        with patch(
            'trusts.checks._configured_principal_models',
            return_value=[Plain],
        ):
            messages = check_principal_is_active(None)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].id, CHECK_ID_INACTIVE_PRINCIPAL)
        self.assertIn('Plain', messages[0].msg)
        with self.assertRaises(TrustsConfigurationError) as caught:
            active_eligibility_q(Plain, 'is_active')
        self.assertIn('no is_active', str(caught.exception))

    def test_non_boolean_column_and_custom_property_are_e010(self):
        class Flag(models.Model):
            is_active = models.IntegerField()

            class Meta:
                app_label = 'myapp'

        class Computed(models.Model):
            class Meta:
                app_label = 'myapp'

            @property
            def is_active(self):
                return True

        class Tagged(models.Model):
            is_active = models.ManyToManyField(User, related_name='+')

            class Meta:
                app_label = 'myapp'

        for model in (Flag, Computed, Tagged):
            with self.assertRaises(TrustsConfigurationError):
                active_eligibility_q(model, 'is_active')
        self.assertEqual(principal_attribute_kind(Flag, 'missing'), 'absent')
        with patch(
            'trusts.checks._configured_principal_models',
            return_value=[Flag, Computed, Tagged],
        ):
            messages = check_principal_is_active(None)
        self.assertEqual(
            [message.id for message in messages],
            [CHECK_ID_INACTIVE_PRINCIPAL] * 3,
        )
        self.assertTrue(all(
            'not a concrete BooleanField' in message.msg for message in messages
        ))

    def test_broken_paths_and_unclassifiable_principals_do_not_crash_the_check(self):
        class BrokenPaths(object):
            def _configured_trusts_paths(self):
                raise TrustsConfigurationError('paths')

        class BrokenBackend(object):
            def _configured_trusts_paths(self):
                return ('example.Backend',)

            def configured_backend(self, path=None):
                raise RuntimeError('backend')

        with patch(
            'django.contrib.auth.get_user_model',
            side_effect=RuntimeError('user'),
        ):
            with patch(
                'trusts.apps.implementation_configs',
                return_value=(BrokenPaths(), BrokenBackend()),
            ):
                self.assertEqual(check_principal_is_active(None), [])

        with patch(
            'trusts.checks._configured_principal_models',
            return_value=[object(), User],
        ):
            self.assertEqual(check_principal_is_active(None), [])

        with patch(
            'trusts.checks._configured_principal_models',
            return_value=[User],
        ):
            with patch(
                'trusts.query.principal_attribute_kind',
                side_effect=RuntimeError('boom'),
            ):
                messages = check_principal_is_active(None)
        self.assertEqual(len(messages), 1)
        self.assertEqual(messages[0].id, CHECK_ID_INACTIVE_PRINCIPAL)
        self.assertIn('cannot be classified', messages[0].msg)
        self.assertIn('boom', messages[0].msg)

    def test_stock_abstract_base_user_is_sql_true_for_both_flag_values(self):
        class StockUser(AbstractBaseUser):
            identifier = models.CharField(max_length=20, unique=True)
            USERNAME_FIELD = 'identifier'

            class Meta:
                app_label = 'myapp'

        false_q = active_eligibility_q(
            StockUser, 'is_active', allow_inactive=False,
        )
        true_q = active_eligibility_q(
            StockUser, 'is_active', allow_inactive=True,
        )
        false_sql = str(StockUser.objects.filter(false_q).query)
        true_sql = str(StockUser.objects.filter(true_q).query)
        self.assertEqual(false_sql, true_sql)
        self.assertIn('TRUE', false_sql)
        self.assertNotIn('%s', false_sql)
        self.assertNotIn('is_active', false_sql)


class Issue300BooleanFieldTest(TestCase):
    def setUp(self):
        content_type = ContentType.objects.get_for_model(Document)
        self.change, _created = Permission.objects.get_or_create(
            content_type=content_type,
            codename='change_document',
            defaults={'name': 'Can change document'},
        )
        self.alice = User.objects.create_user('alice-300', password='x')
        self.inactive = User.objects.create_user('inactive-300', password='x')
        self.inactive.is_active = False
        self.inactive.save(update_fields=['is_active'])
        self.document = Document.objects.create(title='note-300')
        DocumentGrant.objects.create(
            document=self.document, user=self.alice, permission=self.change,
        )
        DocumentGrant.objects.create(
            document=self.document, user=self.inactive, permission=self.change,
        )

    def test_both_flag_values_share_sql_and_the_false_flag_denies_inactive(self):
        denied = compile_permitted_users(
            self.document, PERM, allow_inactive=False,
        )
        included = compile_permitted_users(
            self.document, PERM, allow_inactive=True,
        )
        denied_sql, denied_params = denied.query.sql_with_params()
        included_sql, included_params = included.query.sql_with_params()
        self.assertEqual(denied_sql, included_sql)
        self.assertNotEqual(denied_params, included_params)
        self.assertIn('OR "auth_user"."is_active"', denied_sql)
        self.assertIn('"trusts_bind"."allow_inactive"', denied_sql)
        self.assertEqual(set(denied), {self.alice})
        self.assertEqual(set(included), {self.alice, self.inactive})

    def test_authorized_denies_a_non_model_without_is_active_and_none_raises(self):
        class Authenticated(object):
            is_authenticated = True
            is_anonymous = False
            pk = self.alice.pk

        self.assertTrue(stored_user_is_inactive(Authenticated()))
        self.assertFalse(stored_user_is_inactive(object()))
        with self.assertNumQueries(0):
            self.assertFalse(
                Document.objects.authorized(Authenticated(), self.change).exists()
            )
        with self.assertRaises(TrustsConfigurationError):
            Document.objects.authorized(None, self.change)
        with self.assertRaises(TrustsConfigurationError):
            Document.objects.authorized(object(), self.change)


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
            hoist(False, BooleanField(), hint='allow inactive')
            seal(queryset)
        replaced, replaced_params = queryset.query.sql_with_params()
        self.assertIn('AS "literal"', replaced)
        self.assertIn('AS "allow_inactive"', replaced)
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

        flag = SqlTrue()
        self.assertIs(flag.get_prep_lookup(), True)
        flag.set_source_expressions([])
        with self.assertRaises(TypeError):
            flag.set_source_expressions([Value(1)])

        predicate = BooleanPredicate(Value(True, output_field=BooleanField()))
        self.assertIs(predicate.get_prep_lookup(), True)
        allowed = AllowOr(F('is_active'), False)
        self.assertIs(allowed.get_prep_lookup(), False)
