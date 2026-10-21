"""Schema-1 SQL policy export, lockfile bytes, and trusts.E009."""
from tests.support import (
    compiler,
    installed_databases,
    listed_relationship,
    render_configured_policy,
)
from tests.unsupported_db_settings import DATABASES as UNSUPPORTED_DATABASES
import datetime
import json
import tempfile
import uuid
import yaml
from decimal import Decimal
from io import StringIO
from pathlib import Path
from django.contrib.auth.models import Permission, User
from django.core import checks as django_checks
from django.core.management import call_command
from django.core.management.base import CommandError
from django.db import connection, connections, models
from django.test import SimpleTestCase, override_settings
from trusts.errors import TrustsConfigurationError
from trusts.inspect.snapshot import CHECK_ID_POLICY_LOCK, CONVENTIONAL_LOCKFILE_NAME, check_policy_sql_lockfile, render_policy_sql_bytes
from trusts.inspect.yaml import dump_policy_yaml
GOLDEN_SQLITE = Path(__file__).with_name('golden_document_sqlite.yaml').read_bytes()
GOLDEN_CONSTANTS = Path(__file__).with_name('golden_condition_constants_sqlite.yaml').read_bytes()
GOLDEN_ALONG = Path(__file__).with_name('golden_along_sqlite.yaml').read_bytes()
_FORBIDDEN = ('fingerprint', 'sha256', '\nexpr:', '\nhandles:', '\nfamily:', '\ncompiler:')

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
    members = models.ManyToManyField('auth.User', related_name='policy_sql_teams')

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
    parent = models.ForeignKey('self', null=True, related_name='children', on_delete=models.CASCADE)

    class Meta:
        app_label = 'documents'

class PolicyActor(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4)
    is_active = models.BooleanField(default=True)

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
    is_active = models.BooleanField(default=True)

    class Meta:
        app_label = 'documents'

class CappedDocumentPermission(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    permission = models.ForeignKey(Permission, on_delete=models.CASCADE)
    caps = models.ManyToManyField(Permission, related_name='+')

    class Meta:
        app_label = 'documents'

class PolicyDelegation(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    delegate = models.ForeignKey('auth.User', related_name='+', on_delete=models.CASCADE)
    sponsor = models.ForeignKey('auth.User', related_name='+', on_delete=models.CASCADE)
    permissions = models.ManyToManyField(Permission, related_name='+')

    class Meta:
        app_label = 'documents'

class Operation(models.Model):
    code = models.CharField(max_length=32, primary_key=True)

    class Meta:
        app_label = 'documents'

class OperationGrant(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
    permission = models.ForeignKey(Operation, on_delete=models.CASCADE)
    caps = models.ManyToManyField(Operation, related_name='+')

    class Meta:
        app_label = 'documents'

class PolicyAccountGrant(models.Model):
    document = models.ForeignKey(Document, on_delete=models.CASCADE)
    user = models.ForeignKey(PolicyAccount, to_field='code', on_delete=models.CASCADE)
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
        registry = compiler()
    registry.path = path
    return registry

def _non_confidential(user, permission, obj):
    del user, permission
    return obj.confidential != True

def _document_handle(path='documents.backends.DocumentBackend'):
    handle = _handle(path)
    handle.register(trust=DocumentPermission, user='user', permission='permission', content='document')
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
        return obj.stamp == datetime.datetime(2024, 3, 4, 5, 6, 7, tzinfo=datetime.timezone.utc)

    def span(user, permission, obj):
        del user, permission
        return obj.span == datetime.timedelta(days=1, seconds=2, microseconds=3)

    def owner(user, permission, obj):
        del user, permission
        saved = User(pk=7)
        saved._state.adding = False
        return obj.owner == saved

    def label(user, permission, obj):
        del user, permission
        return obj.label == 'alpha'
    filters = (('amount', amount), ('negzero', negzero), ('nan', nan), ('infinity', infinity), ('negative_infinity', negative_infinity), ('payload', payload), ('price', price), ('token', token), ('day', day), ('clock', clock), ('stamp', stamp), ('span', span), ('owner', owner), ('label', label))
    for code, builder in filters:
        handle.add_named_filter(ConstantDocument, code, builder)
    return handle

def _e009():
    return [item for item in django_checks.run_checks() if item.id == CHECK_ID_POLICY_LOCK]

class PolicySqlGoldenTest(SimpleTestCase):

    def test_sqlite_document_matches_the_guide_bytes(self):
        payload = render_configured_policy(_document_handle())
        self.assertEqual(payload, GOLDEN_SQLITE)
        self.assertTrue(payload.endswith(b'\n'))
        self.assertFalse(payload.endswith(b'\n\n'))
        self.assertFalse(payload.startswith(b'\xef\xbb\xbf'))
        self.assertIn(b'sql: |-\n', payload)
        self.assertNotIn(b'!!', payload)
        text = payload.decode('utf-8')
        self.assertNotIn('\r', text)
        document = yaml.safe_load(payload)
        content = document['backends'][0]['contents'][0]
        trust = content['trusts'][0]
        self.assertNotIn('or_group', trust)
        self.assertEqual(trust['content']['path'], 'document')
        self.assertEqual(list(document['database']), ['engine'])
        self.assertEqual(list(content['permitted']), ['params', 'sql'])
        self.assertEqual(content['permitted']['params'], ['$user.id', '$permission.id', 'user.is_active=True', '$content.app_label="documents"', '$content.model="document"', 'skip_is_active=False'])
        named = content['named_filters'][0]
        self.assertEqual(list(named), ['id', 'params', 'sql'])
        self.assertEqual(named['id'], 'documents__Document__non_confidential')
        self.assertNotIn('.', named['id'])
        self.assertNotIn('.', trust['id'])
        self.assertEqual(named['params'], ['confidential=True'])
        self.assertNotIn('documents_documentpermission', named['sql'])
        self.assertNotIn('confidential" IS NULL', content['permitted']['sql'])
        self.assertNotIn('confidential" = %s', content['permitted']['sql'])
        self.assertNotIn('sql', trust)
        self.assertNotIn('kind', trust)
        self.assertNotIn('kind', named)
        self.assertIn('EXISTS (', content['has_perm']['sql'])
        self.assertIn('$permission.id', content['has_perm']['params'])
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
                handle.register(trust=trust, user='user', permission='permission', content=content_field)
            for model, code in filters:
                handle.add_named_filter(model, code, _non_confidential)
            return render_configured_policy(handle)
        forward_trusts = ((DocumentPermission, 'document'), (OtherPermission, 'other'))
        forward_filters = ((Document, 'a_code'), (Document, 'z_code'))
        forward = render(forward_trusts, forward_filters)
        reversed_trusts = render(tuple(reversed(forward_trusts)), forward_filters)
        reversed_filters = render(forward_trusts, tuple(reversed(forward_filters)))
        self.assertNotEqual(forward, reversed_trusts)
        self.assertNotEqual(forward, reversed_filters)
        forward_text = forward.decode('utf-8')
        reversed_text = reversed_trusts.decode('utf-8')
        doc_id = 'id: "documents__DocumentPermission__document"'
        other_id = 'id: "documents__OtherPermission__other"'
        self.assertLess(forward_text.index(doc_id), forward_text.index(other_id))
        self.assertLess(reversed_text.index(other_id), reversed_text.index(doc_id))
        filter_text = reversed_filters.decode('utf-8')
        a_code = 'id: "documents__Document__a_code"'
        z_code = 'id: "documents__Document__z_code"'
        self.assertLess(forward_text.index(a_code), forward_text.index(z_code))
        self.assertLess(filter_text.index(z_code), filter_text.index(a_code))

    def test_named_filter_code_outside_id_alphabet_is_rejected(self):
        handle = _handle('documents.backends.DocumentBackend')
        handle.add_named_filter(Document, 'needs-review', _non_confidential)
        with self.assertRaises(TrustsConfigurationError) as ctx:
            render_configured_policy(handle)
        self.assertIn('needs-review', str(ctx.exception))
        self.assertIn('non-portable', str(ctx.exception))
        portable = _handle('documents.backends.DocumentBackend')
        portable.add_named_filter(Document, 'needs_review', _non_confidential)
        document = yaml.safe_load(render_configured_policy(portable))
        self.assertEqual(document['backends'][0]['contents'][0]['named_filters'][0]['id'], 'documents__Document__needs_review')

    def test_cond_entries_show_conditions_and_delegations_use_flow_maps(self):
        handle = _handle('documents.backends.DocumentBackend')
        handle.register(trust=DocumentPermission, user='user', permission='permission', content='document')
        handle.register(trust=CappedDocumentPermission, user='user', permission='permission', content='document', condition=lambda trust: trust.caps.contains(trust.permission) & (trust.user == trust.user))
        handle.register(trust=PolicyDelegation, delegate='delegate', sponsor='sponsor', content='document', condition=lambda row, permission: row.permissions.contains(permission) & (row.delegate == row.sponsor))
        document = yaml.safe_load(render_configured_policy(handle))
        content = document['backends'][0]['contents'][0]
        plain, capped, delegated = (content['trusts'][0], content['trusts'][1], content['delegations'][0])
        self.assertEqual(plain['id'], 'documents__DocumentPermission__document')
        self.assertNotIn('condition', plain)
        self.assertEqual(capped['id'], 'documents__CappedDocumentPermission__document__cond')
        self.assertEqual(capped['condition'], '$permission.id in caps and user == user')
        self.assertEqual(delegated['id'], 'documents__PolicyDelegation__document__cond')
        self.assertEqual(delegated['delegate'], {'path': 'delegate', 'model': 'auth.User', 'target': 'id'})
        self.assertEqual(delegated['sponsor'], {'path': 'sponsor', 'model': 'auth.User', 'target': 'id'})
        self.assertEqual(delegated['condition'], '$permission.id in permissions and delegate == sponsor')
        text = render_configured_policy(handle).decode('utf-8')
        self.assertIn('delegate: {path: "delegate", model: "auth.User", target: "id"}\n', text)
        self.assertIn('sponsor: {path: "sponsor", model: "auth.User", target: "id"}\n', text)
        self.assertIn('condition: "$permission.id in caps and user == user"\n', text)
        self.assertIn('condition: "$permission.id in permissions and delegate == sponsor"\n', text)
        loaded = yaml.safe_load(text)
        rendered = []

        def walk(node):
            if isinstance(node, dict):
                if 'condition' in node:
                    rendered.append(node['condition'])
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)
        walk(loaded)
        self.assertEqual(rendered, ['$permission.id in caps and user == user', '$permission.id in permissions and delegate == sponsor'])
        self.assertNotIn('delegate:\n', text)
        self.assertNotIn('sponsor:\n', text)

    def test_condition_line_quotes_round_trip_through_safe_load(self):
        samples = (
            '$permission.id in team__allowed_operations and team__organization == repository__organization',
            'repository__organization__personal_user == sponsor',
            '$permission.id in caps and user == user',
            '$permission.id in permissions',
            '(a == b and c == d) and e == f',
            'a:b == c#d',
            'a\'b == a"b',
            'a[b == a{b',
            '-yes == no',
            '!no == null',
            '&star == *true',
            'yes == true',
            'a\\b == c"d',
            '$permission.code in permissions',
        )
        for text in samples:
            payload = dump_policy_yaml({'condition': text})
            loaded = yaml.safe_load(payload.decode('utf-8'))
            self.assertEqual(loaded['condition'], text)
            self.assertIn(b'\ncondition: "', b'\n' + payload)
            self.assertNotIn(b"condition: '", payload)

    def test_condition_along_and_duplicate_suffixes_are_in_the_trust_id(self):
        handle = _handle('documents.backends.DocumentBackend')
        handle.register(trust=DocumentPermission, user='user', permission='permission', content='document', condition=lambda trust: trust.user == trust.user)
        handle.register(trust=DocumentPermission, user='user', permission='permission', content='document', condition=lambda trust: trust.permission == trust.permission)
        document = yaml.safe_load(render_configured_policy(handle))
        cond_ids = [row['id'] for row in document['backends'][0]['contents'][0]['trusts']]
        self.assertEqual(cond_ids, ['documents__DocumentPermission__document__cond', 'documents__DocumentPermission__document__cond__2'])
        along = _handle('documents.backends.FolderBackend')
        along.register(trust=FolderGrant, user='user', permission='permission', content='folder', along=('folder__parent', 2))
        along_document = yaml.safe_load(render_configured_policy(along))
        along_ids = [row['id'] for row in along_document['backends'][0]['contents'][0]['trusts']]
        self.assertEqual(along_ids, ['documents__FolderGrant__folder__along_folder__parent_S_2'])
        for trust_id in cond_ids + along_ids:
            self.assertNotIn('.', trust_id)
            self.assertNotIn('-', trust_id)

    def test_or_siblings_share_or_group_and_keep_separate_sql(self):
        handle = _handle('documents.backends.DocumentBackend')
        handle.register(trust=DocumentPermission, user='user', permission='permission', content='document')
        handle.register(trust=TeamDocumentPermission, user='team__members', permission='permission', content='document')
        document = yaml.safe_load(render_configured_policy(handle))
        content = document['backends'][0]['contents'][0]
        trusts = content['trusts']
        self.assertEqual(len(trusts), 2)
        self.assertIs(trusts[0]['or_group'], True)
        self.assertIs(trusts[1]['or_group'], True)
        self.assertNotIn('sql', trusts[0])
        self.assertNotIn('sql', trusts[1])
        self.assertEqual(trusts[0]['id'], 'documents__DocumentPermission__document')
        self.assertEqual(trusts[1]['id'], 'documents__TeamDocumentPermission__document')
        self.assertNotIn('.', trusts[0]['id'])
        self.assertNotIn('.', trusts[1]['id'])
        self.assertEqual(trusts[0]['user']['path'], 'user')
        self.assertEqual(trusts[1]['user']['path'], 'team__members')
        self.assertEqual(trusts[0]['content']['target'], 'id')
        permitted = content['permitted']
        self.assertRegex(permitted['sql'], '\\bOR\\b')
        self.assertIn('documents_documentpermission', permitted['sql'])
        self.assertIn('"documents_team"', permitted['sql'])
        self.assertNotIn('{{', permitted['sql'])
        self.assertNotIn('composition', document['backends'][0])

    def test_empty_relationship_backend_is_omitted(self):
        populated = _document_handle('aaa.backends.DocumentBackend')
        empty = _handle('zzz.backends.EmptyBackend')
        document = yaml.safe_load(render_configured_policy(empty, populated))
        paths = [row['path'] for row in document['backends']]
        self.assertEqual(paths, ['aaa.backends.DocumentBackend'])
        self.assertTrue(all(row['contents'] for row in document['backends']))
        self.assertNotIn('composition', document['backends'][0])

    def test_unsupported_family_fails_closed(self):
        factory = _document_handle()
        factory.family = 'ordered_fold'
        with self.assertRaises(TrustsConfigurationError) as ctx:
            render_configured_policy(factory)
        self.assertIn('ordered_fold', str(ctx.exception))

    def test_sqlite_export_does_not_execute_authorization_sql(self):
        preserved = connection.connection
        connection.connection = None
        try:
            with override_settings(DEBUG=True):
                connection.queries_log.clear()
                payload = render_configured_policy(_document_handle())
                recorded = ' '.join((item['sql'] for item in connection.queries))
            self.assertIsNone(connection.connection)
            self.assertNotIn('documents_documentpermission', recorded)
            self.assertIn(b'documents_documentpermission', payload)
        finally:
            if connection.connection is None:
                connection.connection = preserved

    def test_along_forward_lockfile_is_portable_recursive_sql(self):
        handle = _handle('documents.backends.FolderAlongBackend')
        handle.register(trust=FolderGrant, user='user', permission='permission', content='folder', along=('folder__parent', 2))
        payload = render_configured_policy(handle)
        document = yaml.safe_load(payload)
        golden = yaml.safe_load(GOLDEN_ALONG)
        content = document['backends'][0]['contents'][0]
        golden_content = golden['backends'][0]['contents'][0]
        for key in ('permitted', 'has_perm', 'get_all_permissions', 'get_permitted_users'):
            self.assertEqual(content[key], golden_content[key])
        text = payload.decode('utf-8')
        self.assertNotIn('json_', text.lower())
        self.assertNotIn('CYCLE', text)
        self.assertIn('WITH RECURSIVE', text)
        self.assertIn('UNION ALL', text)
        self.assertIn('FROM "gen" AS "g"', text)
        self.assertEqual(text.count('"$along_bound=2"'), 4)
        for key in ('permitted', 'has_perm', 'get_all_permissions', 'get_permitted_users'):
            params = content[key]['params']
            self.assertEqual([param for param in params if param.startswith('$along_bound=')], ['$along_bound=2'])
            self.assertEqual(content[key]['sql'].count('%s'), len(params))


    def test_along_failure_does_not_return_a_partial_document(self):
        handle = _handle('documents.backends.FolderBackend')
        handle.register(
            trust=FolderGrant,
            user='user',
            permission='permission',
            content='folder',
            along=('folder__parent', 2),
        )
        databases = {
            alias: dict(config)
            for alias, config in UNSUPPORTED_DATABASES.items()
        }
        databases['default'] = dict(connections.settings['default'])
        with installed_databases(databases):
            with listed_relationship((handle,)):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    render_policy_sql_bytes(alias='other')
        self.assertIn("'other'", str(ctx.exception))
        self.assertIn('tests.unsupported_backend', str(ctx.exception))

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
                call_command('trusts_policy_sql', database='default', stdout=stdout)
                document = yaml.safe_load(stdout.getvalue())
                self.assertEqual(list(document['database']), ['engine'])
                self.assertEqual(document['database']['engine'], 'django.db.backends.sqlite3')
                self.assertNotIn('default', stdout.getvalue())
                with self.assertRaises(CommandError):
                    call_command('trusts_policy_sql', database='missing-alias', lock=True, stdout=StringIO())
            self.assertFalse(target.exists())

    def test_lock_does_not_create_a_missing_parent(self):
        with tempfile.TemporaryDirectory() as tmp:
            parent = Path(tmp) / 'missing-parent'
            target = parent / CONVENTIONAL_LOCKFILE_NAME
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(target)):
                with self.assertRaises(CommandError):
                    call_command('trusts_policy_sql', lock=True, stdout=StringIO())
            self.assertFalse(parent.exists())

    def test_render_failure_writes_no_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / CONVENTIONAL_LOCKFILE_NAME
            databases = {
                'default': {
                    'ENGINE': 'django.db.backends.sqlite3',
                    'NAME': ':memory:',
                },
                'bare': {'NAME': ':memory:'},
            }
            with override_settings(
                TRUSTS_POLICY_LOCKFILE=str(target),
                DATABASES=databases,
            ):
                with self.assertRaises(CommandError) as ctx:
                    call_command(
                        'trusts_policy_sql', database='bare', lock=True,
                        stdout=StringIO(),
                    )
            self.assertIn('no DATABASES ENGINE', str(ctx.exception))
            self.assertIn('bare', str(ctx.exception))
            self.assertFalse(target.exists())

class PolicySqlCheckTest(SimpleTestCase):

    def test_e009_is_a_model_check(self):
        self.assertEqual(check_policy_sql_lockfile.tags, (django_checks.Tags.models,))

    def test_missing_conventional_lockfile_emits_no_e009(self):
        with tempfile.TemporaryDirectory() as tmp:
            with override_settings(BASE_DIR=tmp, TRUSTS_POLICY_LOCKFILE=None, TRUSTS_POLICY_DATABASE=None):
                self.assertEqual(_e009(), [])

    def test_explicit_missing_file_is_e009(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / CONVENTIONAL_LOCKFILE_NAME
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(target), TRUSTS_POLICY_DATABASE=None):
                errors = _e009()
        self.assertEqual(len(errors), 1)
        self.assertIn('missing', errors[0].msg)

    def test_one_byte_edit_and_old_semantic_document_fail_e009(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / CONVENTIONAL_LOCKFILE_NAME
            payload = render_policy_sql_bytes()
            target.write_bytes(payload)
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(target), TRUSTS_POLICY_DATABASE=None):
                self.assertEqual(_e009(), [])
                edited = bytearray(payload)
                edited[10] = edited[10] ^ 1
                target.write_bytes(bytes(edited))
                drifted = _e009()
                self.assertEqual(len(drifted), 1)
                self.assertIn('bytes differ', drifted[0].msg)
                target.write_text(json.dumps({'schema_version': 1, 'compiler_version': 1, 'handles': [], 'family': 'relationship', 'fingerprint': 'sha256:' + 'ab' * 32}), encoding='utf-8')
                incompatible = _e009()
        self.assertEqual(len(incompatible), 1)
        self.assertEqual(incompatible[0].id, CHECK_ID_POLICY_LOCK)
        self.assertIn('bytes differ', incompatible[0].msg)

    def test_conventional_absence_is_quiet_before_database_resolution(self):
        with tempfile.TemporaryDirectory() as tmp:
            with override_settings(BASE_DIR=tmp, TRUSTS_POLICY_LOCKFILE=None, TRUSTS_POLICY_DATABASE=''):
                self.assertEqual(_e009(), [])
            with override_settings(BASE_DIR=tmp, TRUSTS_POLICY_LOCKFILE=None, TRUSTS_POLICY_DATABASE='missing-alias'):
                self.assertEqual(_e009(), [])
            target = Path(tmp) / CONVENTIONAL_LOCKFILE_NAME
            target.write_bytes(b'{}\n')
            with override_settings(BASE_DIR=tmp, TRUSTS_POLICY_LOCKFILE=None, TRUSTS_POLICY_DATABASE='missing-alias'):
                present = _e009()
        self.assertEqual(len(present), 1)
        self.assertIn('missing-alias', present[0].msg)
        with tempfile.TemporaryDirectory() as tmp:
            explicit = Path(tmp) / CONVENTIONAL_LOCKFILE_NAME
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(explicit), TRUSTS_POLICY_DATABASE='missing-alias'):
                errors = _e009()
        self.assertEqual(len(errors), 1)
        self.assertIn('missing-alias', errors[0].msg)

    def test_relative_explicit_path_is_e009(self):
        with override_settings(TRUSTS_POLICY_LOCKFILE=CONVENTIONAL_LOCKFILE_NAME, TRUSTS_POLICY_DATABASE=None):
            errors = _e009()
        self.assertEqual(len(errors), 1)
        self.assertIn('absolute', errors[0].msg)

class PolicySqlSentinelTest(SimpleTestCase):

    def test_uuid_pk_and_non_integer_target_export(self):
        actor_handle = _handle('documents.backends.ActorBackend')
        actor_handle.register(trust=PolicyActorGrant, user='user', permission='permission', content='document')
        actor_doc = yaml.safe_load(render_configured_policy(actor_handle))
        actor_content = actor_doc['backends'][0]['contents'][0]
        actor_trust = actor_content['trusts'][0]
        self.assertEqual(actor_trust['user']['target'], 'id')
        self.assertEqual(actor_content['permitted']['params'], ['$user.id', '$permission.id', '$content.id', 'user.is_active=True', '$content.app_label="documents"', '$content.model="document"', 'skip_is_active=False'])
        account_handle = _handle('documents.backends.AccountBackend')
        account_handle.register(trust=PolicyAccountGrant, user='user', permission='permission', content='document')
        account_doc = yaml.safe_load(render_configured_policy(account_handle))
        account_content = account_doc['backends'][0]['contents'][0]
        account_trust = account_content['trusts'][0]
        self.assertEqual(account_trust['user'], {'path': 'user', 'model': 'documents.PolicyAccount', 'target': 'code'})
        self.assertEqual(account_content['permitted']['params'], ['$user.code', '$permission.id', '$content.id', 'user.is_active=True', '$content.app_label="documents"', '$content.model="document"', 'skip_is_active=False'])

    def test_custom_permission_pk_renders_the_resolved_target(self):
        handle = _handle('documents.backends.OperationBackend')
        handle.register(trust=OperationGrant, user='user', permission='permission', content='document', condition=lambda grant: grant.caps.contains(grant.permission))
        document = yaml.safe_load(render_configured_policy(handle))
        content = document['backends'][0]['contents'][0]
        grant = content['trusts'][0]
        self.assertEqual(grant['permission'], {'path': 'permission', 'model': 'documents.Operation', 'target': 'code'})
        self.assertEqual(grant['condition'], '$permission.code in caps')
        self.assertIn('$permission.code', content['permitted']['params'])
        self.assertNotIn('$permission.id', content['permitted']['params'])
        self.assertEqual(content['permitted']['sql'].count('%s'), len(content['permitted']['params']))

class PolicySqlConstantTest(SimpleTestCase):

    def test_supported_constant_families_match_golden_and_round_trip(self):
        payload = render_configured_policy(_constant_family_handle())
        self.assertEqual(payload, GOLDEN_CONSTANTS)
        document = yaml.safe_load(payload)
        filters = document['backends'][0]['contents'][0]['named_filters']
        by_code = {row['id']: row['params'] for row in filters}
        prefix = 'documents__ConstantDocument__'
        for row in filters:
            self.assertTrue(row['id'].startswith(prefix))
            self.assertNotIn('.', row['id'])
            self.assertEqual(list(row), ['id', 'params', 'sql'])

        def token(code):
            return by_code[prefix + code][0]
        self.assertEqual(token('amount'), 'amount=1.5')
        self.assertEqual(token('negzero'), 'amount=-0.0')
        self.assertEqual(token('nan'), 'amount={"type":"float","value":"NaN"}')
        self.assertEqual(token('infinity'), 'amount={"type":"float","value":"Infinity"}')
        self.assertEqual(token('negative_infinity'), 'amount={"type":"float","value":"-Infinity"}')
        self.assertEqual(token('payload'), 'payload={"type":"bytes","hex":"00ff"}')
        self.assertEqual(token('price'), 'price={"type":"decimal","value":"12.50"}')
        self.assertEqual(token('token'), 'token={"type":"uuid","value":"12345678-1234-5678-1234-567812345678"}')
        self.assertEqual(token('day'), 'day={"type":"date","value":"2024-03-04"}')
        self.assertEqual(token('clock'), 'clock={"type":"time","value":"05:06:07"}')
        self.assertEqual(token('stamp'), 'stamp={"type":"datetime","value":"2024-03-04T05:06:07+00:00"}')
        self.assertEqual(token('span'), 'span={"type":"timedelta","days":1,"seconds":2,"microseconds":3}')
        self.assertEqual(token('owner'), 'owner={"type":"model","app_label":"auth","model":"user","pk":7}')
        self.assertEqual(token('label'), 'label="alpha"')

