"""Executed permission SQL matches the one locked row."""
from pathlib import Path
import tempfile

import yaml
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import connection
from django.test import SimpleTestCase, TransactionTestCase
from django.test.utils import CaptureQueriesContext, override_settings

from tests.core.test_issue147.test_sql_export import (
    GOLDEN_SQLITE,
    Document,
    DocumentPermission,
    _document_handle,
    _e009,
)
from tests.myapp.apps import DOCUMENT_BACKEND
from tests.myapp.backends import DocumentBackend
from tests.support import published_class_catalog
from trusts.inspect.format import _format_policy_sql
from trusts.inspect.snapshot import (
    CONVENTIONAL_LOCKFILE_NAME,
    render_policy_sql_bytes,
)
from trusts.models import PermittedQuerySet, PermittedUsersMixin

_CODE = 'documents.change_document'
_CONDITIONAL = 'documents.change_document:non_confidential'
_CODENAME = 'change_document'


def _runtime_value(token, *, user, content, permission):
    """Value one lockfile token takes in this inquiry."""
    if token == '$user.id':
        return user.pk
    if token == '$content.id':
        return content.pk
    if token == '$permission.id':
        return permission.pk
    if token == '$permission.codename':
        return _CODENAME
    source, raw = token.split('=', 1)
    if raw == 'True':
        return True
    if raw == 'False':
        return False
    if raw.startswith('"') and raw.endswith('"'):
        return raw[1:-1]
    if source.startswith('$along_bound'):
        return int(raw)
    raise AssertionError('unrecognized lockfile token %r' % token)


def _where_clause(query):
    """The ``WHERE`` text of one compiled statement."""
    sql, _params = query.get_compiler(using='default').as_sql()
    formatted = _format_policy_sql(sql)
    marker = '\nWHERE '
    start = formatted.find(marker)
    if start < 0:
        raise AssertionError(formatted)
    return formatted[start + len(marker):]


def _statements(run):
    """SQL and params of each statement ``run`` executes."""
    recorded = []

    def wrapper(execute, sql, params, many, context):
        if not many:
            recorded.append((sql, params))
        return execute(sql, params, many, context)

    with CaptureQueriesContext(connection) as captured:
        with connection.execute_wrapper(wrapper):
            run()
    if len(captured) != len(recorded):
        raise AssertionError(
            'expected %s statements, captured %r' % (
                len(recorded), [row['sql'] for row in captured],
            )
        )
    return recorded


def _grant(statements):
    """The authorization statement. A permission lookup is not one."""
    grants = [item for item in statements if 'documents_' in item[0]]
    if len(grants) != 1:
        raise AssertionError(
            'expected one grant, captured %r' % [sql for sql, _params in statements]
        )
    return grants[0]


class ExecutedEqualsLockTest(TransactionTestCase):

    def setUp(self):
        with connection.schema_editor() as editor:
            editor.create_model(Document)
            editor.create_model(DocumentPermission)
        content_type, _created = ContentType.objects.get_or_create(
            app_label='documents', model='document',
        )
        self.permission = Permission.objects.create(
            content_type=content_type,
            codename=_CODENAME,
            name='Can change document',
        )

    def tearDown(self):
        with connection.schema_editor() as editor:
            editor.delete_model(DocumentPermission)
            editor.delete_model(Document)

    def test_string_and_permission_inquiries_match_the_lockfile_row(self):
        User = get_user_model()
        user = User.objects.create_user('lock-permission', password='x')
        doc = Document.objects.create(title='specs', confidential=False)
        permission = self.permission
        golden = yaml.safe_load(GOLDEN_SQLITE)['backends'][0]['contents'][0]
        with published_class_catalog(DocumentBackend, _document_handle()) as catalog:
            del catalog
            content = DocumentBackend().policy_document()['backends'][0]['contents'][0]
            cases = (
                (
                    'has_perm',
                    lambda: DocumentBackend().has_perm(user, _CODE, doc),
                ),
                (
                    'permitted',
                    lambda: list(PermittedQuerySet(model=Document).permitted(
                        _CODE, user, backend=DOCUMENT_BACKEND,
                    )),
                ),
                (
                    'get_permitted_users',
                    lambda: list(PermittedUsersMixin.get_permitted_users(
                        doc, _CODE, backend=DOCUMENT_BACKEND,
                    )),
                ),
            )
            for key, run in cases:
                with self.subTest(key=key):
                    self.assertEqual(content[key], golden[key])
                    self._matches(content[key], run, user, doc, permission)
            permitted_string = list(PermittedQuerySet(model=Document).permitted(
                _CODE, user, backend=DOCUMENT_BACKEND,
            ))
            permitted_object = list(PermittedQuerySet(model=Document).permitted(
                permission, user, backend=DOCUMENT_BACKEND,
            ))
            self.assertEqual(permitted_string, permitted_object)
            users_string = list(PermittedUsersMixin.get_permitted_users(
                doc, _CODE, backend=DOCUMENT_BACKEND,
            ))
            users_object = list(PermittedUsersMixin.get_permitted_users(
                doc, permission, backend=DOCUMENT_BACKEND,
            ))
            self.assertEqual(users_string, users_object)
            self._binding_differs(
                lambda: list(PermittedQuerySet(model=Document).permitted(
                    _CODE, user, backend=DOCUMENT_BACKEND,
                )),
                lambda: list(PermittedQuerySet(model=Document).permitted(
                    permission, user, backend=DOCUMENT_BACKEND,
                )),
            )
            named = content['named_filters'][0]
            golden_named = golden['named_filters'][0]
            self.assertEqual(named['has_perm'], golden_named['has_perm'])
            self._matches(
                named['has_perm'],
                lambda: DocumentBackend().has_perm(user, _CONDITIONAL, doc),
                user, doc, permission,
            )
            self.assertEqual(named['permitted'], golden_named['permitted'])
            self._matches(
                named['permitted'],
                lambda: list(PermittedQuerySet(model=Document).permitted(
                    _CODE, user, conditions=('non_confidential',),
                    backend=DOCUMENT_BACKEND,
                )),
                user, doc, permission,
            )
            named_string = list(PermittedQuerySet(model=Document).permitted(
                _CODE, user, conditions=('non_confidential',),
                backend=DOCUMENT_BACKEND,
            ))
            named_object = list(PermittedQuerySet(model=Document).permitted(
                permission, user, conditions=('non_confidential',),
                backend=DOCUMENT_BACKEND,
            ))
            self.assertEqual(named_string, named_object)

    def test_skip_flag_changes_only_the_bound_value(self):
        User = get_user_model()
        user = User.objects.create_user('lock-skip', password='x')
        doc = Document.objects.create(title='specs', confidential=False)
        with published_class_catalog(DocumentBackend, _document_handle()):
            def permitted(skip):
                return lambda: list(PermittedQuerySet(model=Document).permitted(
                    _CODE, user, conditions=('non_confidential',),
                    backend=DOCUMENT_BACKEND, skip_is_active=skip,
                ))
            self._skip_changes_one_param(permitted(False), permitted(True))
            def check(skip):
                return lambda: DocumentBackend().has_perm(
                    user, _CONDITIONAL, doc, skip_is_active=skip,
                )
            self._skip_changes_one_param(check(False), check(True))

    def _skip_changes_one_param(self, off, on):
        sql_off, params_off = _grant(_statements(off))
        sql_on, params_on = _grant(_statements(on))
        self.assertEqual(sql_off, sql_on)
        self.assertEqual(len(params_off), len(params_on))
        diffs = [
            index for index, (left, right) in enumerate(zip(params_off, params_on))
            if left != right
        ]
        self.assertEqual(len(diffs), 1)
        self.assertIs(params_off[diffs[0]], False)
        self.assertIs(params_on[diffs[0]], True)

    def test_all_match_negation_is_the_locked_grant(self):
        from trusts.plan.aggregates import _bound_all_match
        from trusts.plan.contents import _compile_granted
        User = get_user_model()
        user = User(pk=7, is_active=True, username='grant')
        user._state.adding = False
        permission = Permission(pk=3)
        permission._state.adding = False
        with published_class_catalog(DocumentBackend, _document_handle()) as catalog:
            subject = Document.objects.all()
            _denied, values = catalog._resolve_skipped(user, {})
            granted = _compile_granted(
                catalog, subject, user, permission,
                kind='complete', skipped=values,
            )
            bound = _bound_all_match(
                catalog, subject, user, permission,
                kind='complete', skipped=values,
            )
            self.assertIsNotNone(granted)
            self.assertIsNotNone(bound)
            _queryset, grant_q = bound
            locked = catalog._question_content_grant(Document, user, permission)
            grant_where = _where_clause(Document.objects.filter(grant_q).query)
            locked_where = _where_clause(locked.query)
            negated_where = _where_clause(Document.objects.filter(~grant_q).query)
            self.assertEqual(grant_where, locked_where)
            self.assertEqual(negated_where, 'NOT ' + grant_where)

    def _matches(self, row, run, user, doc, permission):
        statements = _statements(run)
        self.assertEqual(len(statements), 1)
        sql, params = statements[0]
        self.assertEqual(_format_policy_sql(sql), row['sql'])
        expected = tuple(
            _runtime_value(token, user=user, content=doc, permission=permission)
            for token in row['params']
        )
        self.assertEqual(tuple(params), expected)

    def _binding_differs(self, string_run, object_run):
        string_sql, _params = _statements(string_run)[0]
        object_sql, _params = _statements(object_run)[0]
        self.assertNotEqual(string_sql, object_sql)
        self.assertIn('codename', string_sql)
        self.assertIn('permission_id', object_sql)


class LockRoundTripTest(SimpleTestCase):

    def test_e009_accepts_the_rendered_rows(self):
        payload = render_policy_sql_bytes()
        document = yaml.safe_load(payload)
        rows = [
            content
            for backend in document['backends']
            for content in backend['contents']
            if 'has_perm' in content
        ]
        self.assertTrue(rows)
        for content in rows:
            self.assertNotIn('permitted_by_codename', content)
            self.assertNotIn('get_permitted_users_by_codename', content)
            self.assertIn('$permission.codename', content['has_perm']['params'])
            self.assertNotIn('$permission.id', content['has_perm']['params'])
            self.assertIn('$permission.codename', content['permitted']['params'])
            self.assertIn('$permission.codename', content['get_permitted_users']['params'])
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / CONVENTIONAL_LOCKFILE_NAME
            target.write_bytes(payload)
            with override_settings(
                TRUSTS_POLICY_LOCKFILE=str(target),
                TRUSTS_POLICY_DATABASE=None,
            ):
                self.assertEqual(_e009(), [])
                target.write_bytes(payload.replace(
                    b'has_perm:', b'has_perX:', 1,
                ))
                errors = _e009()
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].id, 'trusts.E009')
        self.assertIn('bytes differ', errors[0].msg)
