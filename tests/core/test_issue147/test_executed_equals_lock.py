"""Executed codename SQL matches the lockfile row text."""
from pathlib import Path
import tempfile

import yaml
from django.contrib.auth import get_user_model
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
    _classify_compiled,
    render_policy_sql_bytes,
)
from trusts.models import PermittedQuerySet, PermittedUsersMixin
from trusts.plan.rewrites import CallInput

_CODE = 'documents.change_document'
_CONDITIONAL = 'documents.change_document:non_confidential'
_CODENAME = 'change_document'


def _runtime_value(token, *, user, content, codename):
    """Value one lockfile token takes in this inquiry."""
    if token == '$user.id':
        return user.pk
    if token == '$content.id':
        return content.pk
    if token == '$permission.codename':
        return codename
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


def _capture(run):
    """SQL and params of the one statement ``run`` executes."""
    recorded = []

    def wrapper(execute, sql, params, many, context):
        if not many:
            recorded.append((sql, params))
        return execute(sql, params, many, context)

    with CaptureQueriesContext(connection) as captured:
        with connection.execute_wrapper(wrapper):
            run()
    if len(captured) != 1 or len(recorded) != 1:
        raise AssertionError(
            'expected one statement, captured %r' % [row['sql'] for row in captured]
        )
    return recorded[0]


class CallInputClassifierTest(SimpleTestCase):

    def test_call_input_classifies_as_its_bind_name(self):
        node = CallInput('change_document', 'permission.codename')
        sql, params = _classify_compiled(node, '%s', ('change_document',))
        self.assertEqual(sql, '%s')
        self.assertEqual(params[0].payload, {
            'bind': 'permission.codename',
            'hint': '$permission.codename',
        })


class ExecutedEqualsLockTest(TransactionTestCase):

    def setUp(self):
        with connection.schema_editor() as editor:
            editor.create_model(Document)
            editor.create_model(DocumentPermission)

    def tearDown(self):
        with connection.schema_editor() as editor:
            editor.delete_model(DocumentPermission)
            editor.delete_model(Document)

    def test_string_inquiries_match_the_lockfile_rows(self):
        User = get_user_model()
        user = User.objects.create_user('lock-codename', password='x')
        doc = Document.objects.create(title='specs', confidential=False)
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
                    'permitted_by_codename',
                    lambda: list(PermittedQuerySet(model=Document).permitted(
                        _CODE, user, backend=DOCUMENT_BACKEND,
                    )),
                ),
                (
                    'get_permitted_users_by_codename',
                    lambda: list(PermittedUsersMixin.get_permitted_users(
                        doc, _CODE, backend=DOCUMENT_BACKEND,
                    )),
                ),
            )
            for key, run in cases:
                with self.subTest(key=key):
                    self._matches(content[key], golden[key], run, user, doc)
            conditional = content['named_filters'][0]['has_perm']
            self._matches(
                conditional,
                golden['named_filters'][0]['has_perm'],
                lambda: DocumentBackend().has_perm(user, _CONDITIONAL, doc),
                user, doc,
            )

    def _matches(self, row, golden_row, run, user, doc):
        self.assertEqual(row, golden_row)
        sql, params = _capture(run)
        self.assertEqual(_format_policy_sql(sql), row['sql'])
        expected = tuple(
            _runtime_value(token, user=user, content=doc, codename=_CODENAME)
            for token in row['params']
        )
        self.assertEqual(tuple(params), expected)


class CodenameLockRoundTripTest(SimpleTestCase):

    def test_e009_accepts_the_rendered_codename_rows(self):
        payload = render_policy_sql_bytes()
        document = yaml.safe_load(payload)
        rows = [
            content
            for backend in document['backends']
            for content in backend['contents']
            if 'permitted_by_codename' in content
        ]
        self.assertTrue(rows)
        for content in rows:
            self.assertIn('$permission.codename', content['has_perm']['params'])
            self.assertIn(
                '$permission.codename', content['permitted_by_codename']['params'],
            )
            self.assertIn(
                '$permission.codename',
                content['get_permitted_users_by_codename']['params'],
            )
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / CONVENTIONAL_LOCKFILE_NAME
            target.write_bytes(payload)
            with override_settings(
                TRUSTS_POLICY_LOCKFILE=str(target),
                TRUSTS_POLICY_DATABASE=None,
            ):
                self.assertEqual(_e009(), [])
                target.write_bytes(payload.replace(
                    b'permitted_by_codename:', b'permitted_by_codenamX:', 1,
                ))
                errors = _e009()
        self.assertEqual(len(errors), 1)
        self.assertEqual(errors[0].id, 'trusts.E009')
        self.assertIn('bytes differ', errors[0].msg)
