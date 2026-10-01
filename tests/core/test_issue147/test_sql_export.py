"""Schema-1 SQL policy export, lockfile bytes, and trusts.E009."""

import datetime
import json
import math
import tempfile
import threading
import uuid
from decimal import Decimal
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth.models import Permission, User
from django.core import checks as django_checks
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection, models
from django.db.models.sql.compiler import SQLCompiler
from django.test import SimpleTestCase, TestCase, override_settings

from trusts.conditions._ir import ModelIdentity
from trusts.core import (
    BackendHandle,
    PlanQueryCompiler,
    TrustsConfigurationError,
    TrustsRegistry,
)
from trusts.policy_lock import (
    CHECK_ID_POLICY_LOCK,
    CONVENTIONAL_LOCKFILE_NAME,
    _Symbol,
    _classify_compiled,
    _const_from_json,
    _json_const,
    _sentinel,
    _load_policy_sql_document,
    render_policy_sql_bytes,
)

GOLDEN_SQLITE = (
    Path(__file__).with_name('golden_document_sqlite.yaml').read_bytes()
)
GOLDEN_CONSTANTS = (
    Path(__file__).with_name(
        'golden_condition_constants_sqlite.yaml',
    ).read_bytes()
)

_FORBIDDEN = (
    'fingerprint',
    'sha256',
    '\nexpr:',
    '\nhandles:',
    '\nfamily:',
    '\ncompiler:',
)


class HiddenDocument(models.Model):
    """Content model whose default manager is not named ``objects``."""

    title = models.CharField(max_length=40)
    entries = models.Manager()

    class Meta:
        app_label = 'documents'


class HiddenGrant(models.Model):
    document = models.ForeignKey(HiddenDocument, on_delete=models.CASCADE)
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        app_label = 'documents'


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


class PolicyActor(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)

    class Meta:
        app_label = 'documents'


class PolicyActorGrant(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    user = models.ForeignKey(PolicyActor, on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        app_label = 'documents'


class PolicyAccount(models.Model):
    code = models.CharField(max_length=16, unique=True)

    class Meta:
        app_label = 'documents'


class PolicyAccountGrant(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    user = models.ForeignKey(
        PolicyAccount, to_field='code', on_delete=models.CASCADE,
    )
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

    class Meta:
        app_label = 'documents'


class ConstantDocument(models.Model):
    amount = models.FloatField(default=0)
    payload = models.BinaryField(null=True)
    price = models.DecimalField(max_digits=8, decimal_places=2, default=0)
    token = models.UUIDField(null=True)
    day = models.DateField(null=True)
    clock = models.TimeField(null=True)
    stamp = models.DateTimeField(null=True)
    span = models.DurationField(null=True)
    label = models.CharField(max_length=40, default='')
    owner = models.ForeignKey(User, null=True, on_delete=models.CASCADE)

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


def _constant_family_handle():
    """One named filter for each IR constant family the export must record."""
    handle = _handle('documents.backends.ConstantBackend')

    def amount(user, permission, obj):
        del user, permission
        return obj.amount == 1.5

    def negzero(user, permission, obj):
        del user, permission
        return obj.amount == -0.0

    def nan(user, permission, obj):
        del user, permission
        return obj.amount == float('nan')

    def infinity(user, permission, obj):
        del user, permission
        return obj.amount == float('inf')

    def negative_infinity(user, permission, obj):
        del user, permission
        return obj.amount == float('-inf')

    def payload(user, permission, obj):
        del user, permission
        return obj.payload == b'\x00\xff'

    def price(user, permission, obj):
        del user, permission
        return obj.price == Decimal('12.50')

    def token(user, permission, obj):
        del user, permission
        return obj.token == uuid.UUID('12345678-1234-5678-1234-567812345678')

    def day(user, permission, obj):
        del user, permission
        return obj.day == datetime.date(2024, 3, 4)

    def clock(user, permission, obj):
        del user, permission
        return obj.clock == datetime.time(5, 6, 7)

    def stamp(user, permission, obj):
        del user, permission
        return obj.stamp == datetime.datetime(
            2024, 3, 4, 5, 6, 7, tzinfo=datetime.timezone.utc,
        )

    def span(user, permission, obj):
        del user, permission
        return obj.span == datetime.timedelta(
            days=1, seconds=2, microseconds=3,
        )

    def owner(user, permission, obj):
        del user, permission
        saved = User(pk=7)
        saved._state.adding = False
        return obj.owner == saved

    def label(user, permission, obj):
        del user, permission
        return obj.label == 'alpha'

    filters = (
        ('amount', amount),
        ('negzero', negzero),
        ('nan', nan),
        ('infinity', infinity),
        ('negative_infinity', negative_infinity),
        ('payload', payload),
        ('price', price),
        ('token', token),
        ('day', day),
        ('clock', clock),
        ('stamp', stamp),
        ('span', span),
        ('owner', owner),
        ('label', label),
    )
    for code, builder in filters:
        handle.add_named_filter(ConstantDocument, code, builder)
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
        self.assertFalse(payload.endswith(b'\n\n'))
        self.assertFalse(payload.startswith(b'\xef\xbb\xbf'))
        self.assertIn(b'sql: |-\n', payload)
        self.assertNotIn(b'!!', payload)
        text = payload.decode('utf-8')
        self.assertNotIn('\r', text)
        document = _load_policy_sql_document(payload)
        content = document['backends'][0]['contents'][0]
        trust = content['trusts'][0]
        self.assertNotIn('or_group', trust)
        self.assertEqual(trust['content']['path'], 'document')
        self.assertEqual(list(document['database']), ['engine'])
        self.assertEqual(content['permitted']['params'], [
            {'const': 1},
            {'bind': 'permission.id'},
            {'bind': 'user.id'},
        ])
        named = content['named_filters'][0]
        self.assertEqual(named['id'], 'non_confidential')
        self.assertEqual(named['params'], [{'const': True}])
        self.assertNotIn('documents_documentpermission', named['sql'])
        self.assertNotIn('confidential" IS NULL', content['permitted']['sql'])
        self.assertNotIn('confidential" = %s', content['permitted']['sql'])
        self.assertNotIn('sql', trust)
        self.assertNotIn('kind', trust)
        self.assertNotIn('kind', named)
        self.assertIn('EXISTS(', content['has_perm']['sql'])
        self.assertIn({'bind': 'permission.id'}, content['has_perm']['params'])
        self.assertIn('auth_permission', content['get_all_permissions']['sql'])
        for token in ('change_document', 'codename'):
            self.assertNotIn(token, content['permitted']['sql'])
            self.assertNotIn(token, named['sql'])
            self.assertNotIn(token, content['has_perm']['sql'])
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
            (Document, 'z_code'),
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
        doc_id = 'id: "documents.DocumentPermission__document"'
        other_id = 'id: "documents.OtherPermission__other"'
        self.assertLess(forward_text.index(doc_id), forward_text.index(other_id))
        self.assertLess(reversed_text.index(other_id), reversed_text.index(doc_id))
        filter_text = reversed_filters.decode('utf-8')
        self.assertLess(
            forward_text.index('id: "a_code"'),
            forward_text.index('id: "z_code"'),
        )
        self.assertLess(
            filter_text.index('id: "z_code"'),
            filter_text.index('id: "a_code"'),
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
        document = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[handle]),
        )
        content = document['backends'][0]['contents'][0]
        trusts = content['trusts']
        self.assertEqual(len(trusts), 2)
        self.assertIs(trusts[0]['or_group'], True)
        self.assertIs(trusts[1]['or_group'], True)
        self.assertNotIn('sql', trusts[0])
        self.assertNotIn('sql', trusts[1])
        self.assertEqual(trusts[0]['user']['path'], 'user')
        self.assertEqual(trusts[1]['user']['path'], 'team__members')
        self.assertEqual(trusts[0]['content']['target'], 'id')
        permitted = content['permitted']
        self.assertIn(' OR ', permitted['sql'])
        self.assertIn('documents_documentpermission', permitted['sql'])
        self.assertIn('"documents_team"', permitted['sql'])
        self.assertNotIn('{{', permitted['sql'])
        self.assertNotIn('composition', document['backends'][0])

    def test_empty_relationship_backend_is_still_emitted(self):
        populated = _document_handle('aaa.backends.DocumentBackend')
        empty = _handle('zzz.backends.EmptyBackend')
        document = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[empty, populated]),
        )
        paths = [row['path'] for row in document['backends']]
        self.assertEqual(paths, [
            'aaa.backends.DocumentBackend',
            'zzz.backends.EmptyBackend',
        ])
        self.assertEqual(document['backends'][1]['contents'], [])
        self.assertNotIn('composition', document['backends'][1])
        self.assertNotIn('composition', document['backends'][0])
        self.assertIn('contents', document['backends'][0])

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
            target = Path(tmp) / CONVENTIONAL_LOCKFILE_NAME
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
            target = Path(tmp) / CONVENTIONAL_LOCKFILE_NAME
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(target)):
                stdout = StringIO()
                call_command(
                    'trusts_policy_sql', database='default', stdout=stdout,
                )
                document = _load_policy_sql_document(stdout.getvalue())
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
            target = parent / CONVENTIONAL_LOCKFILE_NAME
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(target)):
                with self.assertRaises(CommandError):
                    call_command(
                        'trusts_policy_sql', lock=True, stdout=StringIO(),
                    )
            self.assertFalse(parent.exists())

    def test_render_failure_writes_no_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / CONVENTIONAL_LOCKFILE_NAME

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
            target = Path(tmp) / CONVENTIONAL_LOCKFILE_NAME
            with override_settings(
                TRUSTS_POLICY_LOCKFILE=str(target),
                TRUSTS_POLICY_DATABASE=None,
            ):
                errors = _e009()
        self.assertEqual(len(errors), 1)
        self.assertIn('missing', errors[0].msg)

    def test_one_byte_edit_and_old_semantic_document_fail_e009(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / CONVENTIONAL_LOCKFILE_NAME
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

    def test_conventional_absence_is_quiet_before_database_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            with override_settings(
                BASE_DIR=tmp,
                TRUSTS_POLICY_LOCKFILE=None,
                TRUSTS_POLICY_DATABASE='',
            ):
                self.assertEqual(_e009(), [])
            with override_settings(
                BASE_DIR=tmp,
                TRUSTS_POLICY_LOCKFILE=None,
                TRUSTS_POLICY_DATABASE='missing-alias',
            ):
                self.assertEqual(_e009(), [])
            target = Path(tmp) / CONVENTIONAL_LOCKFILE_NAME
            target.write_bytes(b'{}\n')
            with override_settings(
                BASE_DIR=tmp,
                TRUSTS_POLICY_LOCKFILE=None,
                TRUSTS_POLICY_DATABASE='missing-alias',
            ):
                present = _e009()
        self.assertEqual(len(present), 1)
        self.assertIn('missing-alias', present[0].msg)
        with tempfile.TemporaryDirectory() as tmp:
            explicit = Path(tmp) / CONVENTIONAL_LOCKFILE_NAME
            with override_settings(
                TRUSTS_POLICY_LOCKFILE=str(explicit),
                TRUSTS_POLICY_DATABASE='missing-alias',
            ):
                errors = _e009()
        self.assertEqual(len(errors), 1)
        self.assertIn('missing-alias', errors[0].msg)

    def test_relative_explicit_path_is_e009(self):
        with override_settings(
            TRUSTS_POLICY_LOCKFILE=CONVENTIONAL_LOCKFILE_NAME,
            TRUSTS_POLICY_DATABASE=None,
        ):
            errors = _e009()
        self.assertEqual(len(errors), 1)
        self.assertIn('absolute', errors[0].msg)


class PolicySqlSentinelTest(SimpleTestCase):
    def test_uuid_pk_and_non_integer_target_export(self):
        actor = _sentinel(PolicyActor, 'id', alias='default')
        self.assertIsInstance(actor.pk, uuid.UUID)
        self.assertEqual(actor.pk, uuid.UUID(int=1))

        account = _sentinel(PolicyAccount, 'code', alias='default')
        self.assertIsInstance(account.pk, int)
        self.assertIsInstance(account.code, str)
        self.assertEqual(account.code, '1')

        actor_handle = _handle('documents.backends.ActorBackend')
        actor_handle.register(
            trust=PolicyActorGrant,
            user='user',
            permission='permission',
            content='document',
        )
        actor_doc = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[actor_handle]),
        )
        actor_content = actor_doc['backends'][0]['contents'][0]
        actor_trust = actor_content['trusts'][0]
        self.assertEqual(actor_trust['user']['target'], 'id')
        self.assertEqual(actor_content['permitted']['params'], [
            {'const': 1},
            {'bind': 'permission.id'},
            {'bind': 'user.id'},
        ])

        account_handle = _handle('documents.backends.AccountBackend')
        account_handle.register(
            trust=PolicyAccountGrant,
            user='user',
            permission='permission',
            content='document',
        )
        account_doc = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[account_handle]),
        )
        account_content = account_doc['backends'][0]['contents'][0]
        account_trust = account_content['trusts'][0]
        self.assertEqual(account_trust['user'], {
            'path': 'user',
            'model': 'documents.PolicyAccount',
            'target': 'code',
        })
        self.assertEqual(account_content['permitted']['params'], [
            {'const': 1},
            {'bind': 'permission.id'},
            {'bind': 'user.code'},
        ])


class PolicySqlConstantTest(SimpleTestCase):
    def test_supported_constant_families_match_golden_and_round_trip(self):
        payload = render_policy_sql_bytes(handles=[_constant_family_handle()])
        self.assertEqual(payload, GOLDEN_CONSTANTS)
        document = _load_policy_sql_document(payload)
        by_code = {
            row['id']: row['params']
            for row in document['backends'][0]['contents'][0]['named_filters']
        }

        def restored(code):
            return _const_from_json(by_code[code][0]['const'])

        self.assertEqual(restored('amount'), 1.5)
        self.assertEqual(restored('negzero'), 0.0)
        self.assertTrue(math.copysign(1.0, restored('negzero')) < 0)
        self.assertTrue(math.isnan(restored('nan')))
        self.assertEqual(restored('infinity'), float('inf'))
        self.assertEqual(restored('negative_infinity'), float('-inf'))
        self.assertEqual(restored('payload'), b'\x00\xff')
        self.assertEqual(restored('price'), Decimal('12.50'))
        self.assertEqual(
            restored('token'),
            uuid.UUID('12345678-1234-5678-1234-567812345678'),
        )
        self.assertEqual(restored('day'), datetime.date(2024, 3, 4))
        self.assertEqual(restored('clock'), datetime.time(5, 6, 7))
        self.assertEqual(restored('stamp'), datetime.datetime(
            2024, 3, 4, 5, 6, 7, tzinfo=datetime.timezone.utc,
        ))
        self.assertEqual(restored('span'), datetime.timedelta(
            days=1, seconds=2, microseconds=3,
        ))
        self.assertEqual(
            restored('owner'),
            ModelIdentity('auth', 'user', 7),
        )
        self.assertEqual(restored('label'), 'alpha')

    def test_nonfinite_decimal_constants_round_trip(self):
        for text in ('NaN', 'Infinity', '-Infinity'):
            encoded = _json_const(Decimal(text))
            self.assertEqual(encoded['type'], 'decimal')
            self.assertEqual(encoded['value'], text)
            restored = _const_from_json(encoded)
            if text == 'NaN':
                self.assertTrue(restored.is_nan())
            else:
                self.assertEqual(restored, Decimal(text))


class PolicySqlConcurrencyTest(TestCase):
    def test_normal_query_is_unchanged_while_export_compile_is_paused(self):
        original_compile = SQLCompiler.compile
        User.objects.create(username='export-neighbor')
        queryset = User.objects.filter(username='export-neighbor')
        control_sql, control_params = queryset.query.get_compiler(
            using='default',
        ).as_sql()
        control_rows = list(queryset.values_list('username', flat=True))
        expected = render_policy_sql_bytes(handles=[_document_handle()])

        entered = threading.Event()
        release = threading.Event()
        outcome = []
        export_ident = []

        def classifying(node, sql, params):
            if (
                threading.get_ident() == export_ident[0]
                and not classifying.paused
            ):
                classifying.paused = True
                entered.set()
                if not release.wait(5):
                    raise TimeoutError(
                        'export compilation was not released'
                    )
            return _classify_compiled(node, sql, params)

        classifying.paused = False

        def run_export():
            export_ident.append(threading.get_ident())
            try:
                with patch(
                    'trusts.policy_lock._classify_compiled', classifying,
                ):
                    outcome.append(render_policy_sql_bytes(
                        handles=[_document_handle()],
                    ))
            except Exception as exc:
                outcome.append(exc)

        worker = threading.Thread(target=run_export)
        worker.start()
        self.assertTrue(
            entered.wait(5),
            'export compilation did not pause: %r' % (outcome,),
        )
        try:
            self.assertIs(SQLCompiler.compile, original_compile)
            live_sql, live_params = queryset.query.get_compiler(
                using='default',
            ).as_sql()
            live_rows = list(queryset.values_list('username', flat=True))
            self.assertEqual(live_sql, control_sql)
            self.assertEqual(list(live_params), list(control_params))
            self.assertEqual(live_rows, ['export-neighbor'])
            self.assertEqual(live_rows, control_rows)
            for param in live_params:
                self.assertNotIsInstance(param, _Symbol)
        finally:
            release.set()
        worker.join(5)
        self.assertFalse(worker.is_alive())
        self.assertEqual(outcome, [expected])
        self.assertIs(SQLCompiler.compile, original_compile)
