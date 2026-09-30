"""Schema-1 SQL policy export, lockfile bytes, and trusts.E009."""

import json
import tempfile
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth.models import Permission
from django.core import checks as django_checks
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection, models
from django.test import SimpleTestCase, override_settings

from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    TrustsConfigurationError,
    TrustsRegistry,
)
from trusts.policy_lock import (
    CHECK_ID_POLICY_LOCK,
    render_policy_sql_bytes,
)

GOLDEN_SQLITE = (
    Path(__file__).with_name('golden_document_sqlite.json').read_bytes()
)

_FORBIDDEN = (
    'change_document',
    'fingerprint',
    'sha256',
    '"expr"',
    '"handles"',
    '"kind"',
    '"family"',
    '"compiler"',
    'codename',
)


class Document(models.Model):
    title = models.CharField(max_length=200)
    confidential = models.BooleanField(default=False)

    class Meta:
        app_label = 'documents'


class DocumentPermission(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        app_label = 'documents'


class Team(models.Model):
    name = models.CharField(max_length=40)
    members = models.ManyToManyField(
        'auth.User', related_name='policy_sql_teams',
    )

    class Meta:
        app_label = 'documents'


class TeamDocumentPermission(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    team = models.ForeignKey(Team, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        app_label = 'documents'


class OtherDocument(models.Model):
    title = models.CharField(max_length=40)
    confidential = models.BooleanField(default=False)

    class Meta:
        app_label = 'documents'


class OtherPermission(models.Model):
    other = models.ForeignKey(OtherDocument, on_delete=models.CASCADE)
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        app_label = 'documents'


class Folder(models.Model):
    parent = models.ForeignKey(
        'self', null=True, related_name='children',
        on_delete=models.CASCADE,
    )

    class Meta:
        app_label = 'documents'


class FolderGrant(models.Model):
    folder = models.ForeignKey(Folder, on_delete=models.CASCADE)
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        app_label = 'documents'


def _handle(path, registry=None):
    if registry is None:
        registry = TrustsRegistry()
    return BackendHandle(
        path=path,
        registry=registry,
        compiler=PlanQueryCompiler(),
    )


def _non_confidential(user, permission, obj):
    del user, permission
    return obj.confidential != True


def _document_handle(path='documents.backends.DocumentBackend'):
    handle = _handle(path)
    handle.register(
        trust=DocumentPermission,
        user='user',
        permission='permission',
        content='document',
    )
    handle.add_named_filter(Document, 'non_confidential', _non_confidential)
    return handle


def _e009():
    return [
        item for item in django_checks.run_checks()
        if item.id == CHECK_ID_POLICY_LOCK
    ]


class PolicySqlGoldenTest(SimpleTestCase):
    def test_sqlite_document_matches_the_guide_bytes(self):
        payload = render_policy_sql_bytes(handles=[_document_handle()])
        self.assertEqual(payload, GOLDEN_SQLITE)
        self.assertTrue(payload.endswith(b'\n'))
        self.assertFalse(payload.startswith(b'\xef\xbb\xbf'))
        text = payload.decode('utf-8')
        self.assertNotIn('\r', text)
        document = json.loads(text)
        trust = document['backends'][0]['trusts'][0]
        self.assertNotIn('or_group', trust)
        self.assertEqual(list(document['database']), ['engine'])
        self.assertEqual(trust['params'], [
            {'const': 1},
            {'bind': 'permission.id'},
            {'bind': 'user.id'},
        ])
        named = document['backends'][0]['named_filters'][0]
        self.assertEqual(named['params'], [{'const': True}])
        self.assertNotIn('documents_documentpermission', named['sql'])
        self.assertNotIn('confidential" IS NULL', trust['sql'])
        self.assertNotIn('confidential" = %s', trust['sql'])
        for token in _FORBIDDEN:
            self.assertNotIn(token, text)

    def test_register_and_named_filter_order_changes_bytes(self):
        def render(trusts, filters):
            handle = _handle('documents.backends.DocumentBackend')
            for trust, content_field in trusts:
                handle.register(
                    trust=trust,
                    user='user',
                    permission='permission',
                    content=content_field,
                )
            for model, code in filters:
                handle.add_named_filter(model, code, _non_confidential)
            return render_policy_sql_bytes(handles=[handle])

        forward_trusts = (
            (DocumentPermission, 'document'),
            (OtherPermission, 'other'),
        )
        forward_filters = (
            (Document, 'a_code'),
            (OtherDocument, 'z_code'),
        )
        forward = render(forward_trusts, forward_filters)
        reversed_trusts = render(
            tuple(reversed(forward_trusts)), forward_filters,
        )
        reversed_filters = render(
            forward_trusts, tuple(reversed(forward_filters)),
        )
        self.assertNotEqual(forward, reversed_trusts)
        self.assertNotEqual(forward, reversed_filters)
        forward_text = forward.decode('utf-8')
        reversed_text = reversed_trusts.decode('utf-8')
        doc_id = '"id": "documents.DocumentPermission:document"'
        other_id = '"id": "documents.OtherPermission:other"'
        self.assertLess(forward_text.index(doc_id), forward_text.index(other_id))
        self.assertLess(reversed_text.index(other_id), reversed_text.index(doc_id))
        filter_text = reversed_filters.decode('utf-8')
        self.assertLess(
            forward_text.index('"code": "a_code"'),
            forward_text.index('"code": "z_code"'),
        )
        self.assertLess(
            filter_text.index('"code": "z_code"'),
            filter_text.index('"code": "a_code"'),
        )

    def test_or_siblings_share_or_group_and_keep_separate_sql(self):
        handle = _handle('documents.backends.DocumentBackend')
        handle.register(
            trust=DocumentPermission,
            user='user',
            permission='permission',
            content='document',
        )
        handle.register(
            trust=TeamDocumentPermission,
            user='team__members',
            permission='permission',
            content='document',
        )
        document = json.loads(render_policy_sql_bytes(handles=[handle]))
        trusts = document['backends'][0]['trusts']
        self.assertEqual(len(trusts), 2)
        self.assertEqual(trusts[0]['or_group'], 'documents.Document')
        self.assertEqual(trusts[1]['or_group'], 'documents.Document')
        self.assertIn('documents_documentpermission', trusts[0]['sql'])
        self.assertNotIn('documents_team', trusts[0]['sql'])
        self.assertIn('"documents_team"', trusts[1]['sql'])
        self.assertIn('documents_team_members', trusts[1]['sql'])
        self.assertNotIn(' OR ', trusts[0]['sql'])
        self.assertNotIn(' OR ', trusts[1]['sql'])
        self.assertEqual(trusts[0]['user']['path'], 'user')
        self.assertEqual(trusts[1]['user']['path'], 'team__members')
        self.assertEqual(trusts[0]['params'], trusts[1]['params'])
        self.assertEqual(trusts[0]['params'], [
            {'const': 1},
            {'bind': 'permission.id'},
            {'bind': 'user.id'},
        ])

    def test_empty_relationship_backend_is_still_emitted(self):
        populated = _document_handle('aaa.backends.DocumentBackend')
        empty = _handle('zzz.backends.EmptyBackend')
        document = json.loads(render_policy_sql_bytes(handles=[empty, populated]))
        paths = [row['path'] for row in document['backends']]
        self.assertEqual(paths, [
            'aaa.backends.DocumentBackend',
            'zzz.backends.EmptyBackend',
        ])
        self.assertEqual(document['backends'][1]['trusts'], [])
        self.assertEqual(document['backends'][1]['named_filters'], [])

    def test_unsupported_family_fails_closed(self):
        with patch(
            'trusts.apps._handle_authorization_family',
            return_value='ordered_fold',
        ):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                render_policy_sql_bytes(handles=[_document_handle()])
        self.assertIn('ordered_fold', str(ctx.exception))

    def test_sqlite_export_does_not_execute_authorization_sql(self):
        # Django's sqlite backend ignores close() for an in-memory database.
        # Drop the DB-API handle directly so an earlier test cannot hide a
        # connect that this render performs.
        connection.connection = None
        with override_settings(DEBUG=True):
            connection.queries_log.clear()
            with patch('trusts.core.probe_along_capabilities') as probe:
                payload = render_policy_sql_bytes(handles=[_document_handle()])
            probe.assert_not_called()
            recorded = ' '.join(item['sql'] for item in connection.queries)
        self.assertIsNone(connection.connection)
        self.assertNotIn('documents_documentpermission', recorded)
        self.assertIn(b'documents_documentpermission', payload)

    def test_along_failure_does_not_return_a_partial_document(self):
        handle = _handle('documents.backends.FolderBackend')
        handle.register(
            trust=FolderGrant,
            user='user',
            permission='permission',
            content='folder',
            along=('folder__parent', 2),
        )
        with patch('trusts.core.probe_along_capabilities') as probe:
            with patch(
                'trusts.core.along_connection_supported', return_value=False,
            ):
                with self.assertRaises(TrustsConfigurationError):
                    render_policy_sql_bytes(handles=[handle])
            probe.assert_not_called()


class PolicySqlCommandTest(SimpleTestCase):
    def test_lock_writes_the_same_bytes_as_stdout(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'trusts-policy.lock.json'
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(target)):
                locked = StringIO()
                call_command('trusts_policy_sql', lock=True, stdout=locked)
                printed = StringIO()
                call_command('trusts_policy_sql', stdout=printed)
            file_bytes = target.read_bytes()
            self.assertEqual(locked.getvalue().encode('utf-8'), file_bytes)
            self.assertEqual(printed.getvalue().encode('utf-8'), file_bytes)
            self.assertNotIn(b'"alias"', file_bytes)

    def test_database_override_is_not_stored_and_bad_alias_writes_nothing(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'trusts-policy.lock.json'
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(target)):
                stdout = StringIO()
                call_command(
                    'trusts_policy_sql', database='default', stdout=stdout,
                )
                document = json.loads(stdout.getvalue())
                self.assertEqual(list(document['database']), ['engine'])
                self.assertEqual(
                    document['database']['engine'],
                    'django.db.backends.sqlite3',
                )
                self.assertNotIn('default', stdout.getvalue())
                with self.assertRaises(CommandError):
                    call_command(
                        'trusts_policy_sql',
                        database='missing-alias',
                        lock=True,
                        stdout=StringIO(),
                    )
            self.assertFalse(target.exists())

    def test_lock_does_not_create_a_missing_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / 'missing-parent'
            target = parent / 'trusts-policy.lock.json'
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(target)):
                with self.assertRaises(CommandError):
                    call_command(
                        'trusts_policy_sql', lock=True, stdout=StringIO(),
                    )
            self.assertFalse(parent.exists())

    def test_render_failure_writes_no_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'trusts-policy.lock.json'

            def boom(*args, **kwargs):
                del args, kwargs
                raise TrustsConfigurationError('render failed')

            with override_settings(TRUSTS_POLICY_LOCKFILE=str(target)):
                with patch(
                    'trusts.policy_commands.render_policy_sql_bytes', boom,
                ):
                    with patch(
                        'trusts.core.probe_along_capabilities',
                    ) as probe:
                        with self.assertRaises(CommandError) as ctx:
                            call_command(
                                'trusts_policy_sql',
                                lock=True,
                                stdout=StringIO(),
                            )
                        probe.assert_not_called()
            self.assertIn('render failed', str(ctx.exception))
            self.assertFalse(target.exists())


class PolicySqlCheckTest(SimpleTestCase):
    def test_missing_conventional_lockfile_emits_no_e009(self):
        with tempfile.TemporaryDirectory() as tmp:
            with override_settings(
                BASE_DIR=tmp,
                TRUSTS_POLICY_LOCKFILE=None,
                TRUSTS_POLICY_DATABASE=None,
            ):
                self.assertEqual(_e009(), [])

    def test_explicit_missing_file_is_e009(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'trusts-policy.lock.json'
            with override_settings(
                TRUSTS_POLICY_LOCKFILE=str(target),
                TRUSTS_POLICY_DATABASE=None,
            ):
                errors = _e009()
        self.assertEqual(len(errors), 1)
        self.assertIn('missing', errors[0].msg)

    def test_one_byte_edit_and_old_semantic_document_fail_e009(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / 'trusts-policy.lock.json'
            payload = render_policy_sql_bytes()
            target.write_bytes(payload)
            with override_settings(
                TRUSTS_POLICY_LOCKFILE=str(target),
                TRUSTS_POLICY_DATABASE=None,
            ):
                self.assertEqual(_e009(), [])
                edited = bytearray(payload)
                edited[10] = edited[10] ^ 0x01
                target.write_bytes(bytes(edited))
                drifted = _e009()
                self.assertEqual(len(drifted), 1)
                self.assertIn('bytes differ', drifted[0].msg)
                target.write_text(json.dumps({
                    'schema_version': 1,
                    'compiler_version': 1,
                    'handles': [],
                    'family': 'relationship',
                    'fingerprint': 'sha256:' + ('ab' * 32),
                }), encoding='utf-8')
                incompatible = _e009()
        self.assertEqual(len(incompatible), 1)
        self.assertEqual(incompatible[0].id, CHECK_ID_POLICY_LOCK)
        self.assertIn('bytes differ', incompatible[0].msg)

    def test_bad_policy_database_is_e009_without_a_lockfile(self):
        with override_settings(
            TRUSTS_POLICY_DATABASE='',
            TRUSTS_POLICY_LOCKFILE=None,
        ):
            blank = _e009()
        self.assertEqual(len(blank), 1)
        self.assertIn('TRUSTS_POLICY_DATABASE', blank[0].msg)
        with override_settings(
            TRUSTS_POLICY_DATABASE='missing-alias',
            TRUSTS_POLICY_LOCKFILE=None,
        ):
            unknown = _e009()
        self.assertEqual(len(unknown), 1)
        self.assertIn('missing-alias', unknown[0].msg)

    def test_relative_explicit_path_is_e009(self):
        with override_settings(
            TRUSTS_POLICY_LOCKFILE='trusts-policy.lock.json',
            TRUSTS_POLICY_DATABASE=None,
        ):
            errors = _e009()
        self.assertEqual(len(errors), 1)
        self.assertIn('absolute', errors[0].msg)
