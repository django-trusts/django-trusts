"""One placeholder per inquiry value, and ``is_active`` in the statement (#300)."""

from django.contrib.auth.models import Permission, User
from django.contrib.contenttypes.models import ContentType
from django.db.models import IntegerField, OuterRef, Value
from django.test import SimpleTestCase, TestCase, override_settings

from tests.core.test_issue147.test_sql_export import (
    Document as GuideDocument,
    _document_handle,
)
from tests.myapp.models import Document
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
from trusts._bind_once import (
    BIND_ALIAS,
    BindRef,
    BindTable,
    SqlInt,
    bind_once,
    strip_exists_marker,
    trusts_bind_once,
)
from trusts.core import TrustsConfigurationError, granted
from trusts.policy_lock import _load_policy_sql_document, render_policy_sql_bytes
from trusts.query import stored_user_is_inactive
from trusts.reverse import _trusts_eligibility_q


def _document_rows():
    document = _load_policy_sql_document(
        render_policy_sql_bytes(handles=[_document_handle()]),
    )
    return document['backends'][0]['contents'][0]


class Issue300SuiteRegistrationTest(SimpleTestCase):
    def test_module_is_on_kernel_and_pair_suites(self):
        self.assertIn('tests.core.test_issue300', KERNEL_SUITE)
        self.assertIn('tests.core.test_issue300', PAIR_KERNEL_SUITE)


class Issue300LockfileTest(SimpleTestCase):
    def test_each_distinct_value_is_one_placeholder_and_content_type_stays(self):
        content = _document_rows()
        for key in (
            'permitted', 'has_perm', 'get_all_permissions', 'get_permitted_users',
        ):
            row = content[key]
            self.assertEqual(row['sql'].count('%s'), len(row['params']), key)
            self.assertIn('trusts_bind', row['sql'])
            self.assertIn('SELECT 1 AS "a"', row['sql'])
            hints = [param.get('hint') for param in row['params']]
            self.assertIn('content type app', hints)
            self.assertIn('content type model', hints)
            seen = set()
            for param in row['params']:
                if 'bind' in param:
                    token = ('bind', param['bind'], param.get('hint'))
                else:
                    token = ('const', param.get('hint'), repr(param.get('const')))
                self.assertNotIn(token, seen, key)
                seen.add(token)
        users = content['get_permitted_users']
        self.assertIn({'const': True, 'hint': 'active'}, users['params'])
        self.assertIn('"is_active" = %s', users['sql'])
        self.assertNotIn('allow_inactive', users['sql'])

    def test_flag_off_records_the_plain_queryset(self):
        with override_settings(TRUSTS_BIND_ONCE=False):
            content = _document_rows()
        for key in (
            'permitted', 'has_perm', 'get_all_permissions', 'get_permitted_users',
        ):
            row = content[key]
            self.assertNotIn('trusts_bind', row['sql'], key)
            self.assertNotIn('SELECT 1 AS "a"', row['sql'])
            self.assertIn('SELECT %s AS "a"', row['sql'])
            self.assertEqual(row['sql'].count('%s'), len(row['params']))
        users = content['get_permitted_users']
        self.assertIn('"is_active" = %s', users['sql'])
        self.assertGreater(
            len(content['permitted']['params']),
            len(_document_rows()['permitted']['params']),
        )


class Issue300EligibilitySqlTest(SimpleTestCase):
    def test_is_active_equality_is_added_only_when_inactive_users_are_denied(self):
        denied = User.objects.filter(
            _trusts_eligibility_q(User, allow_inactive=False),
        )
        included = User.objects.filter(
            _trusts_eligibility_q(User, allow_inactive=True),
        )
        denied_where = str(denied.query.where)
        included_where = str(included.query.where)
        self.assertIn('is_active', denied_where)
        self.assertNotIn('is_active', included_where)
        self.assertNotIn('allow_inactive', denied_where)
        self.assertNotIn('allow_inactive', included_where)
        self.assertNotIn('OR', denied_where)


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
        handle = _document_handle()
        content = GuideDocument(title='note-300', pk=1)
        with self.assertRaises(TrustsConfigurationError):
            granted((handle,), content, None, permission)
        with self.assertRaises(TrustsConfigurationError):
            granted((handle,), content, object(), permission)


class Issue300BindOnceTest(SimpleTestCase):
    def test_repeated_user_id_is_one_column_and_the_caller_is_unchanged(self):
        original = User.objects.filter(id=5).filter(pk=5)
        bound = bind_once(original)
        sql, params = bound.query.sql_with_params()
        self.assertIn('trusts_bind', sql)
        self.assertIn('AS "user_id"', sql)
        self.assertEqual(list(params), [5])
        self.assertEqual(sql.count('%s'), 1)
        plain, plain_params = original.query.sql_with_params()
        self.assertNotIn('trusts_bind', plain)
        self.assertEqual(list(plain_params), [5, 5])
        again = bind_once(bound)
        self.assertIs(again, bound)

    def test_outer_ref_stays_correlated_and_is_active_stays_a_parameter(self):
        queryset = User.objects.filter(id=OuterRef('pk')).filter(is_active=True)
        bound = bind_once(queryset)
        self.assertNotIn(BIND_ALIAS, bound.query.alias_map)
        where = str(bound.query.where)
        self.assertIn('OuterRef', where)
        self.assertIn('is_active', where)
        table_sql, table_params = bind_once(
            User.objects.filter(id=4).filter(is_active=True),
        ).query.sql_with_params()
        self.assertIn('trusts_bind', table_sql)
        self.assertIn('is_active', table_sql)
        self.assertEqual(table_params.count(4), 1)
        self.assertIn(True, table_params)
        self.assertEqual(len(table_params), 2)

    def test_setting_defaults_to_true_and_false_skips_the_bind_row(self):
        self.assertTrue(trusts_bind_once())
        with override_settings(TRUSTS_BIND_ONCE=True):
            self.assertTrue(trusts_bind_once())
            sql, params = bind_once(
                User.objects.filter(id=4).filter(pk=4),
            ).query.sql_with_params()
            self.assertIn('trusts_bind', sql)
            self.assertEqual(list(params), [4])
        with override_settings(TRUSTS_BIND_ONCE=False):
            self.assertFalse(trusts_bind_once())
            skipped = bind_once(User.objects.filter(id=4).filter(pk=4))
            sql, params = skipped.query.sql_with_params()
            self.assertNotIn('trusts_bind', sql)
            self.assertNotIn(BIND_ALIAS, skipped.query.alias_map)
            self.assertEqual(list(params), [4, 4])

    def test_bind_ref_and_exists_marker_reject_source_expressions(self):
        ref = BindRef(BIND_ALIAS, 'user_id', IntegerField())
        self.assertEqual(ref.get_group_by_cols(), [])
        ref.set_source_expressions([])
        with self.assertRaises(TypeError):
            ref.set_source_expressions([Value(1)])
        marker = SqlInt(1)
        marker.set_source_expressions([])
        with self.assertRaises(TypeError):
            marker.set_source_expressions([Value(1)])
        query = User.objects.all().query
        self.assertIs(strip_exists_marker(query), query)
        self.assertNotIn('a', query.annotations)

    def test_installed_row_classifies_one_symbol_per_placeholder(self):
        bound = bind_once(User.objects.filter(id=4).filter(pk=7))
        table = bound.query.alias_map[BIND_ALIAS]
        self.assertIsInstance(table, BindTable)
        self.assertIs(table.promote(), table)
        self.assertIs(table.demote(), table)
        self.assertEqual(hash(table), hash(BindTable(table.columns)))
        compiler = bound.query.get_compiler(using='default')
        _sql, params = table.as_sql(compiler, compiler.connection)
        self.assertEqual(len(params), 2)
        names = [table.next_column().sql_name for _ in params]
        self.assertEqual(names, ['user_id', 'user_id_2'])
        with self.assertRaises(IndexError):
            table.next_column()


def _engine_connection(engine):
    """Database wrapper for one engine, or ``None`` when its driver is absent.

    The kernel job installs SQLite only. MySQL and PostgreSQL drivers are
    present on the along jobs and in a local checkout that has them.
    """
    from django.core.exceptions import ImproperlyConfigured
    from django.db.utils import load_backend

    try:
        backend = load_backend(engine)
    except ImproperlyConfigured:
        return None
    return backend.DatabaseWrapper({
        'ENGINE': engine,
        'NAME': ':memory:',
        'USER': '',
        'PASSWORD': '',
        'HOST': '',
        'PORT': '',
        'TIME_ZONE': None,
        'CONN_MAX_AGE': 0,
        'CONN_HEALTH_CHECKS': False,
        'OPTIONS': {},
        'AUTOCOMMIT': True,
        'ATOMIC_REQUESTS': False,
    })


class Issue300ExistsMarkerTest(SimpleTestCase):
    def test_literal_one_is_standard_sql_on_sqlite_mysql_and_postgresql(self):
        from django.db.models import Exists

        from trusts._bind_once import LiteralExists

        inner = User.objects.filter(pk=1)
        exists = LiteralExists(inner)
        self.assertIsInstance(exists.query.annotations['a'], SqlInt)
        bare = Exists(User.objects.filter(pk=1))
        self.assertEqual(bare.query.annotations['a'].value, 1)

        engines = (
            'django.db.backends.sqlite3',
            'django.db.backends.mysql',
            'django.db.backends.postgresql',
        )
        for engine in engines:
            with self.subTest(engine=engine):
                connection = _engine_connection(engine)
                if connection is None:
                    self.skipTest('%s driver is not installed' % engine)
                sql, params = exists.query.get_compiler(
                    connection=connection,
                ).as_sql()
                quote = connection.ops.quote_name('a')
                self.assertIn('SELECT 1 AS %s' % quote, sql)
                self.assertNotIn('SELECT %%s AS %s' % quote, sql)
                head = sql.split(' FROM ', 1)[0]
                self.assertNotIn('%s', head)
                self.assertEqual(sql.count('%s'), len(params))
                self.assertEqual(list(params), [1])

    def test_is_active_true_stays_a_bound_parameter_on_each_engine(self):
        query = bind_once(User.objects.filter(
            _trusts_eligibility_q(User, allow_inactive=False),
        )).query
        engines = (
            'django.db.backends.sqlite3',
            'django.db.backends.mysql',
            'django.db.backends.postgresql',
        )
        for engine in engines:
            with self.subTest(engine=engine):
                connection = _engine_connection(engine)
                if connection is None:
                    self.skipTest('%s driver is not installed' % engine)
                sql, params = query.get_compiler(connection=connection).as_sql()
                quote = connection.ops.quote_name('is_active')
                self.assertIn('%s = %%s' % quote, sql)
                self.assertNotIn('%s = true' % quote, sql.lower())
                self.assertNotIn('%s = 1' % quote, sql)
                self.assertIn(True, params)

    def test_flag_off_compiles_the_plain_is_active_comparison(self):
        with override_settings(TRUSTS_BIND_ONCE=False):
            plain = bind_once(User.objects.filter(is_active=True))
            bound_shape = User.objects.filter(is_active=True)
        plain_sql, plain_params = plain.query.sql_with_params()
        raw_sql, raw_params = bound_shape.query.sql_with_params()
        self.assertEqual(plain_sql, raw_sql)
        self.assertEqual(list(plain_params), list(raw_params))
        self.assertNotIn('trusts_bind', plain_sql)
