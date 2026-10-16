"""One placeholder per inquiry value, and ``is_active`` in the statement (#300)."""

import re
from collections import Counter
from contextlib import contextmanager
from unittest.mock import patch

import django
from django.contrib.auth.models import Permission, User
from django.contrib.contenttypes.models import ContentType
from django.db import connection, models
from django.db.models import CharField, IntegerField, OuterRef, Value
from django.db.models.sql.query import Query
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.test.utils import CaptureQueriesContext, isolate_apps

from tests.core import KernelHostRequiredMixin
from tests.core.test_issue147.test_sql_export import (
    Document as GuideDocument,
    _document_handle,
)
from tests.myapp.models import Document
from tests.runtests import KERNEL_SUITE, PAIR_KERNEL_SUITE
import trusts.plan.rewrites as bind_once_module
from trusts._bind_once import (
    BIND_ALIAS,
    BindRef,
    BindTable,
    SqlInt,
    bind_once,
    strip_exists_marker,
    trusts_bind_once,
)
from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    TrustsConfigurationError,
    TrustsRegistry,
    _render_reach_sql,
    granted,
)
from trusts.policy_lock import _load_policy_sql_document, render_policy_sql_bytes
from trusts.reverse import _trusts_eligibility_q


def _document_rows():
    document = _load_policy_sql_document(
        render_policy_sql_bytes(handles=[_document_handle()]),
    )
    return document['backends'][0]['contents'][0]


def _repeat_count(params):
    """Extra copies of one full token.

    Two ``True`` values with different sources are distinct.
    """
    counts = Counter(params)
    return sum(count - 1 for count in counts.values() if count > 1)


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
            self.assertEqual(_repeat_count(row['params']), 0, key)
            self.assertIn('$content.app_label="documents"', row['params'])
            self.assertIn('$content.model="document"', row['params'])
        users = content['get_permitted_users']
        self.assertEqual(users['params'].count('user.is_active=True'), 1)
        self.assertIn(
            '"is_active" = ("trusts_bind"."is_active")', users['sql'],
        )
        self.assertNotIn('"is_active" = %s', users['sql'])
        self.assertNotIn('skip_is_active', users['sql'])

    def test_flag_off_records_the_plain_queryset(self):
        with override_settings(TRUSTS_SQL_BIND_ONCE=False):
            content = _document_rows()
        for key in (
            'permitted', 'has_perm', 'get_all_permissions', 'get_permitted_users',
        ):
            row = content[key]
            self.assertNotIn('trusts_bind', row['sql'], key)
            self.assertNotIn('SELECT 1 AS "a"', row['sql'])
            self.assertIn('SELECT %s AS "a"', row['sql'])
            self.assertEqual(row['sql'].count('%s'), len(row['params']))
            self.assertFalse(any('allow inactive' in param for param in row['params']))
        users = content['get_permitted_users']
        self.assertIn('"is_active" = %s', users['sql'])
        self.assertGreater(
            len(content['permitted']['params']),
            len(_document_rows()['permitted']['params']),
        )


class Issue300EligibilitySqlTest(SimpleTestCase):
    def test_skip_is_active_keeps_the_condition_in_one_statement(self):
        from trusts.user_rules import compile_user_rules

        denied = bind_once(User.objects.filter(compile_user_rules(
            User, '', None, role='user', values={'is_active': False},
        )))
        included = bind_once(User.objects.filter(compile_user_rules(
            User, '', None, role='user', values={'is_active': True},
        )))
        denied_sql, denied_params = denied.query.sql_with_params()
        included_sql, included_params = included.query.sql_with_params()
        self.assertEqual(denied_sql, included_sql)
        self.assertIn('is_active', denied_sql)
        self.assertIn('OR', str(denied.query.where))
        self.assertIn(False, denied_params)
        self.assertNotIn(False, included_params)
        eligibility = str(User.objects.filter(
            _trusts_eligibility_q(User),
        ).query.where)
        self.assertNotIn('is_active', eligibility)


class Issue300BooleanFieldTest(KernelHostRequiredMixin, TestCase):
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
        with self.assertNumQueries(0):
            with self.assertRaises(TrustsConfigurationError):
                Document.objects.authorized(Authenticated(), permission)
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

    def test_outer_ref_stays_correlated_and_is_active_is_bound_once(self):
        queryset = User.objects.filter(id=OuterRef('pk')).filter(is_active=True)
        bound = bind_once(queryset)
        where = str(bound.query.where)
        self.assertIn('OuterRef', where)
        self.assertIn(BIND_ALIAS, bound.query.alias_map)
        active = bound.query.alias_map[BIND_ALIAS]
        self.assertEqual(
            [column.label for column in active.columns],
            ['active'],
        )
        self.assertEqual(active.columns[0].value, True)
        repeated = User.objects.filter(is_active=True)
        for _index in range(3):
            repeated = repeated.filter(is_active=True)
        repeated_sql, repeated_params = bind_once(repeated).query.sql_with_params()
        self.assertEqual(list(repeated_params), [True])
        self.assertEqual(repeated_sql.count('%s'), 1)
        self.assertEqual(
            repeated_sql.count('"is_active" = ("trusts_bind"."is_active")'),
            4,
        )
        table_sql, table_params = bind_once(
            User.objects.filter(id=4).filter(is_active=True),
        ).query.sql_with_params()
        self.assertIn('trusts_bind', table_sql)
        self.assertIn('is_active', table_sql)
        self.assertEqual(table_params.count(4), 1)
        self.assertEqual(list(table_params).count(True), 1)
        self.assertEqual(len(table_params), 2)

    def test_setting_defaults_to_true_and_false_skips_the_bind_row(self):
        self.assertTrue(trusts_bind_once())
        with override_settings(TRUSTS_SQL_BIND_ONCE=True):
            self.assertTrue(trusts_bind_once())
            sql, params = bind_once(
                User.objects.filter(id=4).filter(pk=4),
            ).query.sql_with_params()
            self.assertIn('trusts_bind', sql)
            self.assertEqual(list(params), [4])
        with override_settings(TRUSTS_SQL_BIND_ONCE=False):
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
        from trusts.user_rules import compile_user_rules

        query = bind_once(User.objects.filter(compile_user_rules(
            User, '', None, role='user', values={},
        ))).query
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
                self.assertIn('%s = (' % quote, sql)
                self.assertIn('trusts_bind', sql)
                self.assertNotIn('%s = %%s' % quote, sql)
                self.assertNotIn('%s = true' % quote, sql.lower())
                self.assertNotIn('%s = 1' % quote, sql)
                self.assertEqual(list(params).count(True), 1)

    def test_flag_off_compiles_the_plain_is_active_comparison(self):
        with override_settings(TRUSTS_SQL_BIND_ONCE=False):
            plain = bind_once(User.objects.filter(is_active=True))
            bound_shape = User.objects.filter(is_active=True)
        plain_sql, plain_params = plain.query.sql_with_params()
        raw_sql, raw_params = bound_shape.query.sql_with_params()
        self.assertEqual(plain_sql, raw_sql)
        self.assertEqual(list(plain_params), list(raw_params))
        self.assertNotIn('trusts_bind', plain_sql)


class Issue300ShapeFallbackTest(TestCase):
    def setUp(self):
        bind_once_module._warned = False

    def tearDown(self):
        bind_once_module._warned = False

    def test_unexpected_shape_matches_the_plain_path(self):
        user = User.objects.create_user(username='shape-300', password='x')
        outsider = User.objects.create_user(username='shape-300-out', password='x')
        queryset = User.objects.filter(id=user.pk).filter(pk=user.pk)
        queryset.query.combined_queries = []
        plain = User.objects.filter(id=user.pk).filter(pk=user.pk)
        with override_settings(TRUSTS_SQL_BIND_ONCE=False):
            plain_bound = bind_once(plain)
        with self.assertLogs('trusts', level='WARNING') as logs:
            returned = bind_once(queryset)
            again = User.objects.filter(id=user.pk).filter(pk=user.pk)
            again.query.combined_queries = []
            bind_once(again)
        self.assertEqual(len(logs.records), 1)
        message = logs.records[0].getMessage()
        self.assertIn('combined_queries', message)
        self.assertIn('list', message)
        self.assertIn(django.get_version(), message)
        self.assertIs(returned, queryset)
        self.assertEqual(
            returned.query.sql_with_params(),
            plain_bound.query.sql_with_params(),
        )
        self.assertEqual(list(returned), [user])
        self.assertEqual(list(plain_bound), [user])
        self.assertNotIn(outsider, list(returned))
        self.assertEqual(returned.exists(), plain_bound.exists())

    def test_unexpected_shape_records_the_plain_policy_sql(self):
        with override_settings(TRUSTS_SQL_BIND_ONCE=False):
            plain = _document_rows()
        old = Query.combined_queries
        Query.combined_queries = []
        try:
            with self.assertLogs('trusts', level='WARNING') as logs:
                fallback = _document_rows()
                _document_rows()
        finally:
            Query.combined_queries = old
        self.assertEqual(len(logs.records), 1)
        message = logs.records[0].getMessage()
        self.assertIn('combined_queries', message)
        self.assertIn(django.get_version(), message)
        self.assertEqual(fallback, plain)
        for key in (
            'permitted', 'has_perm', 'get_all_permissions', 'get_permitted_users',
        ):
            self.assertNotIn('trusts_bind', fallback[key]['sql'], key)
            self.assertIn('SELECT %s AS "a"', fallback[key]['sql'], key)

    def test_rewrite_error_returns_the_original_queryset(self):
        user = User.objects.create_user(username='rewrite-300', password='x')
        queryset = User.objects.filter(id=user.pk).filter(pk=user.pk)
        before = queryset.query.sql_with_params()

        def boom(*args, **kwargs):
            raise RuntimeError('bind row failed')

        with patch('trusts.plan.rewrites._install', boom):
            with self.assertLogs('trusts', level='WARNING') as logs:
                returned = bind_once(queryset)
                other = User.objects.filter(id=user.pk).filter(pk=user.pk)
                bind_once(other)
        self.assertEqual(len(logs.records), 1)
        message = logs.records[0].getMessage()
        self.assertIn('RuntimeError', message)
        self.assertIn('bind row failed', message)
        self.assertIn(django.get_version(), message)
        self.assertIs(returned, queryset)
        self.assertEqual(returned.query.sql_with_params(), before)
        self.assertNotIn('trusts_bind', before[0])
        self.assertEqual(list(returned), [user])
        with override_settings(TRUSTS_SQL_BIND_ONCE=False):
            plain = bind_once(User.objects.filter(id=user.pk).filter(pk=user.pk))
        self.assertEqual(returned.query.sql_with_params(), plain.query.sql_with_params())

    def test_exists_keeps_the_bound_sql(self):
        user = User.objects.create_user(username='exists-300', password='x')
        bound = bind_once(User.objects.filter(id=user.pk).filter(pk=user.pk))
        with CaptureQueriesContext(connection) as captured:
            self.assertTrue(bound.exists())
        sql = captured.captured_queries[-1]['sql']
        self.assertIn('SELECT 1 AS "a"', sql)
        self.assertNotIn('SELECT ? AS "a"', sql)
        self.assertNotIn('SELECT %s AS "a"', sql)
        self.assertIn(' AS "user_id") "trusts_bind"', sql)
        self.assertEqual(
            sql.count('"auth_user"."id" = ("trusts_bind"."user_id")'), 2, sql,
        )


@contextmanager
def _model_tables(*model_classes):
    with connection.schema_editor() as editor:
        for model in model_classes:
            editor.create_model(model)
    try:
        yield
    finally:
        with connection.schema_editor() as editor:
            for model in reversed(model_classes):
                editor.delete_model(model)


def _render_parenthesized_depth(walk, seed_sql, seed_params, connection, neighbor=None):
    """The review repro: ``depth < %s`` becomes ``depth < (%s)``."""
    sql, params = _render_reach_sql(
        walk, seed_sql, seed_params, connection, neighbor=neighbor,
    )
    rewritten, count = re.subn(
        r'(["`]depth["`]\s*<\s*)%s',
        r'\1(%s)',
        sql,
        count=1,
    )
    if count != 1:
        raise AssertionError(sql)
    return rewritten, params


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class Issue300UserAnnotationTest(TransactionTestCase):
    def test_annotation_named_a_keeps_its_value_and_output_type(self):
        class Note(models.Model):
            title = models.CharField(max_length=40)

            class Meta:
                app_label = 'trusts_tests'

        class NoteGrant(models.Model):
            note = models.ForeignKey(Note, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with _model_tables(Note, NoteGrant):
            user = User.objects.create_user(username='ann-a-300', password='x')
            content_type, _created = ContentType.objects.get_or_create(
                app_label='trusts_tests', model='note',
            )
            permission, _created = Permission.objects.get_or_create(
                content_type=content_type,
                codename='read_note_a',
                defaults={'name': 'read_note_a'},
            )
            note = Note.objects.create(title='kept')
            NoteGrant.objects.create(note=note, user=user, permission=permission)
            registry = TrustsRegistry()
            handle = BackendHandle(
                path='tests.annotation.a',
                registry=registry,
                compiler=PlanQueryCompiler(),
            )
            handle.register(
                trust=NoteGrant,
                user='user',
                permission='permission',
                content='note',
            )
            candidates = Note.objects.annotate(
                a=Value(1, output_field=CharField()),
            )
            with override_settings(TRUSTS_SQL_BIND_ONCE=False):
                plain = handle.registry.filter_authorized(
                    candidates, user, permission,
                )
                plain_values = list(plain.values_list('a', flat=True))
            bound = handle.registry.filter_authorized(
                candidates, user, permission,
            )
            bound_values = list(bound.values_list('a', flat=True))
            self.assertEqual(plain_values, ['1'])
            self.assertEqual(bound_values, ['1'])
            self.assertIsInstance(bound_values[0], str)
            annotation = bound.query.annotations['a']
            self.assertIsInstance(annotation, Value)
            self.assertNotIsInstance(annotation, SqlInt)
            self.assertEqual(annotation.value, 1)
            self.assertIsInstance(annotation.output_field, CharField)
            sql, _params = bound.query.sql_with_params()
            self.assertIn('SELECT 1 AS "a"', sql)
            self.assertNotIn('SELECT %s AS "a"', sql)
            self.assertIn('trusts_bind', sql)


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class Issue300AlongRetargetFallbackTest(TransactionTestCase):
    def setUp(self):
        bind_once_module._warned = False

    def tearDown(self):
        bind_once_module._warned = False

    def test_parenthesized_depth_cap_falls_back_for_execution_and_lock(self):
        class RetargetNode(models.Model):
            parent = models.ForeignKey(
                'self', null=True, related_name='children',
                on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'

        class RetargetGrant(models.Model):
            node = models.ForeignKey(RetargetNode, on_delete=models.CASCADE)
            user = models.ForeignKey(User, on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'

        with _model_tables(RetargetNode, RetargetGrant):
            user = User.objects.create_user(username='along-cap-300', password='x')
            content_type, _created = ContentType.objects.get_or_create(
                app_label='trusts_tests', model='retargetnode',
            )
            permission, _created = Permission.objects.get_or_create(
                content_type=content_type,
                codename='read_retarget',
                defaults={'name': 'read_retarget'},
            )
            node = RetargetNode.objects.create()
            RetargetGrant.objects.create(
                node=node, user=user, permission=permission,
            )
            registry = TrustsRegistry()
            handle = BackendHandle(
                path='tests.along.retarget',
                registry=registry,
                compiler=PlanQueryCompiler(),
            )
            handle.register(
                trust=RetargetGrant,
                user='user',
                permission='permission',
                content='node',
                along=('node__parent', 4),
            )
            candidates = RetargetNode.objects.order_by('pk')
            with patch(
                'trusts.core._render_reach_sql', _render_parenthesized_depth,
            ):
                with override_settings(TRUSTS_SQL_BIND_ONCE=False):
                    plain = handle.registry.filter_authorized(
                        candidates, user, permission,
                    )
                    plain_rows = list(plain)
                    plain_sql = plain.query.sql_with_params()
                    plain_has = handle.registry.has_permission(
                        user, node, permission,
                    )
                    plain_doc = _load_policy_sql_document(
                        render_policy_sql_bytes(handles=[handle]),
                    )
                bind_once_module._warned = False
                with self.assertLogs('trusts', level='WARNING') as logs:
                    bound = handle.registry.filter_authorized(
                        candidates, user, permission,
                    )
                    bound_rows = list(bound)
                    bound_sql = bound.query.sql_with_params()
                    bound_has = handle.registry.has_permission(
                        user, node, permission,
                    )
                    bound_doc = _load_policy_sql_document(
                        render_policy_sql_bytes(handles=[handle]),
                    )
                    list(handle.registry.filter_authorized(
                        candidates, user, permission,
                    ))
                    render_policy_sql_bytes(handles=[handle])
            self.assertEqual(len(logs.records), 1)
            message = logs.records[0].getMessage()
            self.assertIn('TrustsConfigurationError', message)
            self.assertIn('could not retarget the along depth cap', message)
            self.assertIn(django.get_version(), message)
            self.assertEqual(bound_rows, plain_rows)
            self.assertEqual(bound_rows, [node])
            self.assertIs(bound_has, plain_has)
            self.assertIs(bound_has, True)
            self.assertEqual(bound_sql, plain_sql)
            self.assertNotIn('trusts_bind', bound_sql[0])
            self.assertRegex(bound_sql[0], r'["`]depth["`]\s*<\s*\(%s\)')
            self.assertEqual(bound_doc, plain_doc)
            for content in bound_doc['backends'][0]['contents']:
                for key in (
                    'permitted', 'has_perm', 'get_all_permissions',
                    'get_permitted_users',
                ):
                    self.assertNotIn('trusts_bind', content[key]['sql'], key)
                    self.assertRegex(
                        content[key]['sql'],
                        r'["`]depth["`]\s*<\s*\(%s\)',
                        key,
                    )


class ReviewManager(models.Manager):
    def get_queryset(self):
        return super().get_queryset().annotate(
            review_annotation=Value(1, output_field=IntegerField()),
        )


class ReviewDocument(models.Model):
    title = models.CharField(max_length=40)
    published = models.BooleanField(default=False)
    objects = ReviewManager()

    class Meta:
        app_label = 'documents'


class ReviewGrant(models.Model):
    document = models.ForeignKey(ReviewDocument, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        app_label = 'documents'


def _published(user, permission, obj):
    del user, permission
    return obj.published == True


class Issue300ManagerAnnotationTest(SimpleTestCase):
    def test_value_annotation_stays_in_the_lockfile_for_both_settings(self):
        from trusts.core import _compile_granted
        from trusts.policy_lock import _content_manager, _role_sentinel

        for enabled in (True, False):
            with self.subTest(TRUSTS_SQL_BIND_ONCE=enabled):
                with override_settings(TRUSTS_SQL_BIND_ONCE=enabled):
                    handle = BackendHandle(
                        path='documents.backends.ReviewBackend',
                        registry=TrustsRegistry(),
                        compiler=PlanQueryCompiler(),
                    )
                    handle.register(
                        trust=ReviewGrant,
                        user='user',
                        permission='permission',
                        content='document',
                    )
                    handle.add_named_filter(
                        ReviewDocument, 'published', _published,
                    )
                    document = _load_policy_sql_document(
                        render_policy_sql_bytes(handles=[handle]),
                    )
                    content = document['backends'][0]['contents'][0]
                    permitted = content['permitted']
                    named = content['named_filters'][0]
                    records = handle.registry.plan_for(ReviewDocument).records
                    user = _role_sentinel(records[0], 'user', 'default')
                    permission = _role_sentinel(
                        records[0], 'permission', 'default',
                    )
                    queryset = _content_manager(ReviewDocument).all()
                    granted = _compile_granted(
                        (handle,), queryset, user, permission,
                        kind='complete', sponsor_handles=(handle,),
                    )
                    raw_sql, raw_params = bind_once(
                        queryset.filter(granted).distinct(),
                    ).query.sql_with_params()
                    self._assert_cardinality_and_order(
                        permitted, raw_params,
                    )
                    self.assertEqual(raw_sql.count('%s'), len(raw_params))
                    self.assertIn('review_annotation=1', permitted['params'])
                    self.assertEqual(
                        permitted['params'].count('review_annotation=1'), 1,
                    )
                    named_sql, named_params = (
                        ReviewDocument.objects.filter(published=True)
                        .query.sql_with_params()
                    )
                    self._assert_cardinality_and_order(named, named_params)
                    self.assertEqual(named_sql.count('%s'), len(named_params))
                    self.assertIn('review_annotation=1', named['params'])
                    self.assertEqual(len(named['params']), 2)

    def _assert_cardinality_and_order(self, row, raw_params):
        tokens = row['params']
        self.assertEqual(row['sql'].count('%s'), len(tokens))
        self.assertEqual(len(tokens), len(list(raw_params)))
        for token, raw in zip(tokens, raw_params):
            if '=' not in token:
                continue
            self.assertEqual(_presented_const_for(token), raw)


def _presented_const_for(token):
    from trusts.policy_lock import _presented_const

    return _presented_const(token)
