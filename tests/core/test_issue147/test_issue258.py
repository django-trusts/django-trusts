"""Behavioral coverage for canonical policy YAML and lockfile failures.

Observable bytes, validation errors, and deterministic sentinels. These
tests do not change the exporter.
"""

import copy
import os
import tempfile
import uuid
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth.models import Permission
from django.core import checks as django_checks
from django.db import models
from django.test import SimpleTestCase, override_settings

from tests.core.test_issue147.test_sql_export import (
    CHECK_ID_POLICY_LOCK,
    ConstantDocument,
    _document_handle,
    _handle,
)
from trusts.core import TrustsConfigurationError
from trusts.policy_lock import (
    _const_from_json,
    _json_const,
    _load_policy_sql_document,
    render_policy_sql_bytes,
    resolve_lockfile_path,
    write_policy_lock,
)
from trusts.policy_yaml import (
    PolicyYamlError,
    canonical_float_scalar,
    dump_policy_yaml,
    parse_canonical_float,
    _load_policy_yaml,
)


def _e009():
    return [
        item for item in django_checks.run_checks()
        if item.id == CHECK_ID_POLICY_LOCK
    ]


def _pk_pair(name, field):
    """Content model whose primary key is ``field``, plus a grant root."""
    field.primary_key = True
    content = type(name, (models.Model,), {
        '__module__': __name__,
        'pk_value': field,
        'Meta': type('Meta', (), {'app_label': 'documents'}),
    })
    grant = type(name + 'Grant', (models.Model,), {
        '__module__': __name__,
        'document': models.ForeignKey(content, on_delete=models.CASCADE),
        'user': models.ForeignKey('auth.User', on_delete=models.CASCADE),
        'permission': models.ForeignKey(
            Permission, on_delete=models.CASCADE,
        ),
        'Meta': type('Meta', (), {'app_label': 'documents'}),
    })
    return content, grant


class _Marker(object):
    """Not a JSON value. The canonical dumper must refuse it."""


class _TypedText(models.CharField):
    """Reports a specific internal type so the sentinel spelling is observable."""

    def __init__(self, internal, *args, **kwargs):
        self._internal = internal
        super().__init__(*args, **kwargs)

    def get_internal_type(self):
        return self._internal

    def db_type(self, connection):
        return 'varchar(%s)' % (self.max_length or 40)


class _AcceptingOddField(models.Field):
    """Field type the exporter does not know, but Decimal preparation fits."""

    def db_type(self, connection):
        return 'varchar(40)'

    def get_internal_type(self):
        return 'AcceptingOddField'

    def get_prep_value(self, value):
        if isinstance(value, Decimal):
            return value
        raise TypeError(type(value).__name__)

    def get_db_prep_value(self, value, connection, prepared=False):
        if isinstance(value, Decimal):
            return str(value)
        raise TypeError(type(value).__name__)


class _RejectingField(models.Field):
    """Field type no sentinel candidate can prepare."""

    def db_type(self, connection):
        return 'varchar(40)'

    def get_internal_type(self):
        return 'RejectingField'

    def get_prep_value(self, value):
        raise ValueError('unprepared %s' % type(value).__name__)


class PolicyYamlRejectionTest(SimpleTestCase):
    def test_float_helpers_reject_noncanonical_values_and_round_trip(self):
        for value in (True, False, 1, '1.0', None):
            with self.subTest(value=value):
                with self.assertRaises(PolicyYamlError) as ctx:
                    canonical_float_scalar(value)
                self.assertIn(type(value).__name__, str(ctx.exception))
        for value in (float('nan'), float('inf'), float('-inf')):
            with self.subTest(value=value):
                with self.assertRaises(PolicyYamlError) as ctx:
                    canonical_float_scalar(value)
                self.assertIn('Non-finite', str(ctx.exception))
        for text in (
            '1', '1.50', '1e16', '+1.0', '-0.00', '01.0', '1.0e16', None, 1.5,
        ):
            with self.subTest(text=text):
                with self.assertRaises(PolicyYamlError) as ctx:
                    parse_canonical_float(text)
                self.assertIn('not canonical', str(ctx.exception))

        self.assertEqual(canonical_float_scalar(0.0), '0.0')
        self.assertEqual(canonical_float_scalar(-0.0), '-0.0')
        self.assertEqual(canonical_float_scalar(1.5), '1.5')
        self.assertEqual(canonical_float_scalar(1e16), '1.0e+16')
        self.assertEqual(canonical_float_scalar(1e-7), '1.0e-07')
        negative_zero = parse_canonical_float('-0.0')
        self.assertEqual(negative_zero, 0.0)
        self.assertLess(math_sign(negative_zero), 0)
        self.assertEqual(parse_canonical_float('0.0'), 0.0)
        self.assertGreater(math_sign(parse_canonical_float('0.0')), 0)
        self.assertEqual(parse_canonical_float('1.0e+16'), 1e16)

        document = {'n': 1.5, 'z': -0.0, 'big': 1e16, 'small': 1e-7}
        first = dump_policy_yaml(document)
        second = dump_policy_yaml(document)
        self.assertEqual(first, second)
        self.assertEqual(dump_policy_yaml(_load_policy_yaml(first)), first)
        loaded = _load_policy_yaml(first)
        self.assertEqual(loaded['n'], 1.5)
        self.assertLess(math_sign(loaded['z']), 0)

    def test_dump_rejects_values_the_codec_cannot_spell(self):
        rejected = (
            ([], 'mapping'),
            ('x', 'mapping'),
            ({'yes': 1}, 'plain identifier'),
            ({'1bad': 1}, 'plain identifier'),
            ({1: 'a'}, 'strings'),
            ({True: 'a'}, 'strings'),
            ({'params': 'nope'}, 'list'),
            ({'params': {'a': 1}}, 'list'),
            ({'sql': 1}, 'SQL'),
            ({'sql': ''}, 'non-empty'),
            ({'sql': 'SELECT 1\n'}, 'trailing'),
            ({'sql': 'a\rb'}, 'CR'),
            ({'n': float('nan')}, 'Non-finite'),
            ({'n': _Marker()}, 'cannot encode'),
            ({'n': {1, 2}}, 'must not emit tags'),
            ({'params': [{'yes': 1}]}, 'plain identifier'),
            ({'params': [{1: 2}]}, 'strings'),
            ({'user': {1: 'a'}}, 'strings'),
        )
        for document, needle in rejected:
            with self.subTest(document=document):
                with self.assertRaises(PolicyYamlError) as ctx:
                    dump_policy_yaml(document)
                self.assertIn(needle, str(ctx.exception))

        nested = {'params': [1, [2, {'bind': 'user.id'}], {'const': -0.0}]}
        first = dump_policy_yaml(nested)
        self.assertEqual(dump_policy_yaml(nested), first)
        self.assertTrue(first.startswith(b'params: ['))
        self.assertTrue(first.endswith(b']\n'))
        self.assertNotIn(b'\n', first[:-1])
        self.assertEqual(_load_policy_yaml(first), {
            'params': [1, [2, {'bind': 'user.id'}], {'const': -0.0}],
        })
        self.assertLess(
            math_sign(_load_policy_yaml(first)['params'][2]['const']), 0,
        )

    def test_loader_rejects_payloads_that_are_not_canonical_text(self):
        rejected = (
            (None, 'bytes or text'),
            (1, 'bytes or text'),
            (b'\xef\xbb\xbfn: "1"\n', 'byte-order'),
            (b'\xff', 'UTF-8'),
            ('n: "1"\r\n', 'LF'),
            ('\ufeffn: "1"\n', 'BOM'),
            ('\ud800', 'UTF-8'),
            (b'true: "1"\n', 'strings'),
            (b'1: "a"\n', 'strings'),
            (b'*anchor\n', 'alias'),
            (b'a: [\n', 'could not be read'),
            (b'n: "1"\n---\nk: "2"\n', 'document marker'),
        )
        for payload, needle in rejected:
            with self.subTest(payload=payload):
                with self.assertRaises(PolicyYamlError) as ctx:
                    _load_policy_yaml(payload)
                self.assertIn(needle, str(ctx.exception))

        with self.assertRaises(TrustsConfigurationError) as ctx:
            _load_policy_sql_document(b'"only"\n')
        self.assertIn('mapping', str(ctx.exception))


class PolicyLockConfigurationTest(SimpleTestCase):
    def test_render_rejects_bad_alias_engine_path_and_registry(self):
        for alias in (True, '', 1, 'missing-alias'):
            with self.subTest(alias=alias):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    render_policy_sql_bytes(
                        alias=alias, handles=[_handle('documents.backends.One')],
                    )
                self.assertIn('TRUSTS_POLICY_DATABASE', str(ctx.exception))

        from django.conf import settings

        databases = copy.deepcopy(settings.DATABASES)
        databases['default'] = dict(databases['default'])
        databases['default']['ENGINE'] = ''
        with override_settings(DATABASES=databases):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                render_policy_sql_bytes(handles=[_handle('documents.backends.One')])
        self.assertIn('no DATABASES ENGINE', str(ctx.exception))

        first = _handle('documents.backends.Same')
        second = _handle('documents.backends.Same')
        with self.assertRaises(TrustsConfigurationError) as ctx:
            render_policy_sql_bytes(handles=[first, second])
        self.assertIn('duplicate backend paths', str(ctx.exception))

        class _BareHandle(object):
            def __init__(self, path, registry):
                self.path = path
                self.registry = registry

        with self.assertRaises(TrustsConfigurationError) as ctx:
            render_policy_sql_bytes(handles=[_BareHandle('', object())])
        self.assertIn('missing a configured path', str(ctx.exception))

        with self.assertRaises(TrustsConfigurationError) as ctx:
            render_policy_sql_bytes(handles=[
                _BareHandle('documents.backends.NoRegistry', None),
            ])
        self.assertIn('requires a registry', str(ctx.exception))

        populated = _document_handle('documents.backends.FilterlessBackend')

        class _NoFilterRegistry(object):
            def __init__(self, inner):
                self._inner = inner
                self.records = inner.records
                self.iter_permission_conditions = None

            def __getattr__(self, name):
                return getattr(self._inner, name)

        class _View(object):
            path = populated.path
            registry = _NoFilterRegistry(populated.registry)
            compiler = populated.compiler

        bare = _View()
        omitted = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[bare]),
        )
        kept = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[populated]),
        )
        omitted_content = omitted['backends'][0]['contents'][0]
        kept_content = kept['backends'][0]['contents'][0]
        self.assertNotIn('named_filters', omitted_content)
        self.assertIn('named_filters', kept_content)
        self.assertEqual(omitted_content['trusts'], kept_content['trusts'])
        self.assertEqual(
            omitted_content['permitted']['sql'],
            kept_content['permitted']['sql'],
        )

    def test_lock_path_resolution_and_write_failures(self):
        with self.assertRaises(TypeError) as ctx:
            write_policy_lock('not-bytes')
        self.assertIn('bytes', str(ctx.exception))

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / 'trusts-policy.lock.yaml'
            payload = dump_policy_yaml({'schema_version': 1})
            written = write_policy_lock(payload, override=target)
            self.assertEqual(written, target)
            self.assertEqual(target.read_bytes(), payload)
            location = resolve_lockfile_path(override=target)
            self.assertTrue(location.explicit)
            self.assertEqual(location.state, 'present')
            self.assertIn('explicit=True', repr(location))
            self.assertIn('present', repr(location))
            self.assertIn(str(target), repr(location))

            again = write_policy_lock(payload, override=str(target))
            self.assertEqual(again.read_bytes(), payload)

            with self.assertRaises(TrustsConfigurationError) as ctx:
                write_policy_lock(payload, override=root)
            self.assertIn('directory', str(ctx.exception))
            self.assertTrue(root.is_dir())

            missing_parent = root / 'missing' / 'trusts-policy.lock.yaml'
            with self.assertRaises(TrustsConfigurationError) as ctx:
                write_policy_lock(payload, override=missing_parent)
            self.assertIn('parent directory is missing', str(ctx.exception))
            self.assertFalse(missing_parent.parent.exists())

            not_dir = root / 'file-parent'
            not_dir.write_text('x', encoding='utf-8')
            nested = not_dir / 'trusts-policy.lock.yaml'
            location = resolve_lockfile_path(override=nested)
            self.assertEqual(location.state, 'not_a_directory')
            self.assertIn('not_a_directory', repr(location))
            with self.assertRaises(TrustsConfigurationError) as ctx:
                write_policy_lock(payload, override=nested)
            self.assertIn('not a directory', str(ctx.exception))
            self.assertFalse(nested.exists())

            relative = 'trusts-policy.lock.yaml'
            with self.assertRaises(TrustsConfigurationError) as ctx:
                resolve_lockfile_path(override=relative)
            self.assertIn('absolute', str(ctx.exception))
            with self.assertRaises(TrustsConfigurationError) as ctx:
                resolve_lockfile_path(override=True)
            self.assertIn('bool', str(ctx.exception))

    def test_permission_and_base_dir_failures_stay_closed(self):
        payload = dump_policy_yaml({'schema_version': 1})
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            secret = root / 'trusts-policy.lock.yaml'
            secret.write_bytes(payload)
            os.chmod(secret, 0)
            try:
                with override_settings(TRUSTS_POLICY_LOCKFILE=str(secret)):
                    errors = _e009()
            finally:
                os.chmod(secret, 0o644)
            self.assertEqual(len(errors), 1)
            self.assertIn('permission denied', errors[0].msg)

            os.chmod(root, 0)
            try:
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    write_policy_lock(payload, override=root / 'other.yaml')
            finally:
                os.chmod(root, 0o755)
            self.assertIn('permission denied', str(ctx.exception))

        quiet_bases = (None, True, 5, '', 'relative/dir', Path('relative'))
        for base in quiet_bases:
            with self.subTest(base=base):
                with override_settings(
                    BASE_DIR=base,
                    TRUSTS_POLICY_LOCKFILE=None,
                ):
                    self.assertEqual(_e009(), [])
                    with self.assertRaises(TrustsConfigurationError) as ctx:
                        resolve_lockfile_path()
                self.assertIn('BASE_DIR', str(ctx.exception))
                self.assertIn('not absolute', str(ctx.exception))

        with tempfile.TemporaryDirectory() as tmp:
            missing = Path(tmp) / 'absent-base'
            with override_settings(
                BASE_DIR=str(missing),
                TRUSTS_POLICY_LOCKFILE=None,
            ):
                self.assertEqual(_e009(), [])
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    write_policy_lock(payload)
            self.assertIn('parent directory is missing', str(ctx.exception))

            parent_file = Path(tmp) / 'not-dir'
            parent_file.write_text('x', encoding='utf-8')
            with override_settings(
                BASE_DIR=str(parent_file),
                TRUSTS_POLICY_LOCKFILE=None,
            ):
                self.assertEqual(_e009(), [])
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    write_policy_lock(payload)
            self.assertIn('not a directory', str(ctx.exception))


class PolicyLockSentinelTest(SimpleTestCase):
    def test_content_primary_key_sentinels_are_deterministic_consts(self):
        cases = (
            ('BoolDoc', models.BooleanField(), True),
            ('UuidDoc', models.UUIDField(), {
                'type': 'uuid',
                'value': str(uuid.UUID(int=1)),
            }),
            ('DecimalDoc', models.DecimalField(max_digits=4, decimal_places=0), {
                'type': 'decimal',
                'value': '1',
            }),
            ('FloatDoc', models.FloatField(), 1.0),
            ('BinaryDoc', models.BinaryField(), {
                'type': 'bytes',
                'hex': '01',
            }),
            ('DateDoc', models.DateField(), {
                'type': 'date',
                'value': '2000-01-01',
            }),
            ('TimeDoc', models.TimeField(), {
                'type': 'time',
                'value': '00:00:00',
            }),
            ('DurationDoc', models.DurationField(), {
                'type': 'timedelta',
                'days': 0,
                'seconds': 1,
                'microseconds': 0,
            }),
            ('EmptyTextDoc', models.CharField(max_length=0), ''),
            ('ShortEmailDoc', models.EmailField(max_length=3), '1'),
            ('ShortUrlDoc', models.URLField(max_length=4), '1'),
            ('ShortIpDoc', models.GenericIPAddressField(), '127.0.0.1'),
            ('OddDoc', _AcceptingOddField(), {
                'type': 'decimal',
                'value': '1',
            }),
            ('EmailTypedDoc', _TypedText('EmailField', max_length=254), 's@e.test'),
            ('UrlTypedDoc', _TypedText('URLField', max_length=200), 'https://e.test/'),
            (
                'ShortEmailTypedDoc',
                _TypedText('EmailField', max_length=3),
                '1',
            ),
        )
        for name, field, expected in cases:
            with self.subTest(name=name):
                consts = _has_perm_consts(name, field)
                self.assertEqual(consts[0], 1)
                self.assertEqual(consts[1], expected)
                self.assertEqual(consts[2], 1)

        aware = _has_perm_consts('AwareDoc', models.DateTimeField())
        self.assertEqual(aware[1], {
            'type': 'datetime',
            'value': '2000-01-01T00:00:00+00:00',
        })
        with override_settings(USE_TZ=False):
            naive = _has_perm_consts('NaiveDoc', models.DateTimeField())
        self.assertEqual(naive[1], {
            'type': 'datetime',
            'value': '2000-01-01T00:00:00',
        })

    def test_unpreparable_primary_key_fails_before_a_document(self):
        content, grant = _pk_pair('RejectDoc', _RejectingField())
        handle = _handle('documents.backends.RejectDocBackend')
        handle.register(
            trust=grant,
            user='user',
            permission='permission',
            content='document',
        )
        with self.assertRaises(TrustsConfigurationError) as ctx:
            render_policy_sql_bytes(handles=[handle])
        message = str(ctx.exception)
        self.assertIn('RejectDoc', message)
        self.assertIn('pk_value', message)
        self.assertIn('RejectingField', message)

    def test_json_primary_key_fails_closed_before_a_document(self):
        content, grant = _pk_pair('JsonDoc', models.JSONField())
        handle = _handle('documents.backends.JsonDocBackend')
        handle.register(
            trust=grant,
            user='user',
            permission='permission',
            content='document',
        )
        with self.assertRaises(TrustsConfigurationError) as ctx:
            render_policy_sql_bytes(handles=[handle])
        self.assertIn('cannot record constant', str(ctx.exception))
        self.assertIn('dict', str(ctx.exception))

    def test_missing_grant_or_permission_query_fails_closed(self):
        handle = _document_handle('documents.backends.MissingQueryBackend')
        with patch('trusts.core._compile_granted', return_value=None):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                render_policy_sql_bytes(handles=[handle])
        self.assertIn('no grant', str(ctx.exception))

        with patch('trusts.core._compile_common_permissions', return_value=None):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                render_policy_sql_bytes(handles=[handle])
        self.assertIn('no permissions query', str(ctx.exception))

    def test_missing_group_permissions_query_fails_closed(self):
        class GroupGrant(models.Model):
            group = models.ForeignKey('auth.Group', on_delete=models.CASCADE)
            paper = models.ForeignKey('auth.User', on_delete=models.CASCADE)

            class Meta:
                app_label = 'documents'

        handle = _handle('documents.backends.GroupQueryBackend')
        handle.register(
            trust=GroupGrant,
            user='group__user',
            group='group',
            content='paper',
        )
        from trusts.core import _compile_common_permissions

        def hide_group(handles, instance, user, kind='complete'):
            if kind == 'group':
                return None
            return _compile_common_permissions(
                handles, instance, user, kind=kind,
            )

        with patch('trusts.core._compile_common_permissions', hide_group):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                render_policy_sql_bytes(handles=[handle])
        self.assertIn('no group-permissions query', str(ctx.exception))


class PolicyLockFilterShapeTest(SimpleTestCase):
    def test_named_filter_and_or_and_binds_are_recorded(self):
        handle = _handle('documents.backends.FilterShapeBackend')

        def both(user, permission, obj):
            return (obj.label == 'alpha') & (obj.amount == 1.5)

        def either(user, permission, obj):
            return (obj.label == 'alpha') | (obj.amount == 1.5)

        def owner(user, permission, obj):
            return obj.owner == user

        def username(user, permission, obj):
            return obj.label == user.username

        def differs(user, permission, obj):
            return obj.label != 'nope'

        handle.add_named_filter(ConstantDocument, 'both', both)
        handle.add_named_filter(ConstantDocument, 'either', either)
        handle.add_named_filter(ConstantDocument, 'owner', owner)
        handle.add_named_filter(ConstantDocument, 'username', username)
        handle.add_named_filter(ConstantDocument, 'differs', differs)
        first = render_policy_sql_bytes(handles=[handle])
        second = render_policy_sql_bytes(handles=[handle])
        self.assertEqual(first, second)
        document = _load_policy_sql_document(first)
        filters = {
            row['id']: row
            for row in document['backends'][0]['contents'][0]['named_filters']
        }
        prefix = 'documents__ConstantDocument__'
        both_row = filters[prefix + 'both']
        either_row = filters[prefix + 'either']
        self.assertIn(' AND ', both_row['sql'])
        self.assertIn(' OR ', either_row['sql'])
        self.assertEqual(both_row['params'], [
            {'const': 'alpha'},
            {'const': 1.5},
        ])
        self.assertEqual(either_row['params'], both_row['params'])
        self.assertEqual(filters[prefix + 'owner']['params'], [
            {'bind': 'user.id'},
        ])
        self.assertEqual(filters[prefix + 'username']['params'], [
            {'bind': 'user.username'},
        ])
        self.assertNotIn('alpha', filters[prefix + 'owner']['sql'])
        self.assertEqual(filters[prefix + 'differs']['params'], [
            {'const': 'nope'},
        ])
        self.assertIn('NOT', filters[prefix + 'differs']['sql'])

        same = _handle('documents.backends.SameFieldBackend')
        same.add_named_filter(
            ConstantDocument, 'same_label',
            lambda user, permission, obj: obj.label == obj.label,
        )
        same_bytes = render_policy_sql_bytes(handles=[same])
        self.assertEqual(same_bytes, render_policy_sql_bytes(handles=[same]))
        same_row = _load_policy_sql_document(same_bytes)['backends'][0]['contents'][0]
        same_filter = same_row['named_filters'][0]
        self.assertEqual(same_filter['params'], [])
        self.assertIn('"label" = ("documents_constantdocument"."label")', same_filter['sql'])
        self.assertNotIn('%s', same_filter['sql'])

    def test_unknown_constant_tag_cannot_be_restored(self):
        with self.assertRaises(TrustsConfigurationError) as ctx:
            _const_from_json({'type': 'nope', 'value': '1'})
        self.assertIn('unknown constant tag', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            _const_from_json(['1'])
        self.assertIn('cannot restore', str(ctx.exception))
        self.assertEqual(_json_const('alpha'), 'alpha')
        self.assertEqual(_const_from_json('alpha'), 'alpha')

    def test_split_content_targets_fail_closed(self):
        class CodeDocument(models.Model):
            code = models.CharField(max_length=8, unique=True)

            class Meta:
                app_label = 'documents'

        class GrantById(models.Model):
            document = models.ForeignKey(CodeDocument, on_delete=models.CASCADE)
            user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'documents'

        class GrantByCode(models.Model):
            document = models.ForeignKey(
                CodeDocument, to_field='code', on_delete=models.CASCADE,
            )
            user = models.ForeignKey('auth.User', on_delete=models.CASCADE)
            permission = models.ForeignKey(Permission, on_delete=models.CASCADE)

            class Meta:
                app_label = 'documents'

        handle = _handle('documents.backends.SplitTargetBackend')
        handle.register(
            trust=GrantById,
            user='user',
            permission='permission',
            content='document',
        )
        handle.register(
            trust=GrantByCode,
            user='user',
            permission='permission',
            content='document',
        )
        with self.assertRaises(TrustsConfigurationError) as ctx:
            render_policy_sql_bytes(handles=[handle])
        message = str(ctx.exception)
        self.assertIn('do not share a target', message)
        self.assertIn('documents.CodeDocument', message)

    def test_directory_lock_path_and_non_text_path_fail_closed(self):
        payload = dump_policy_yaml({'schema_version': 1})
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp) / 'trusts-policy.lock.yaml'
            directory.mkdir()
            with override_settings(TRUSTS_POLICY_LOCKFILE=str(directory)):
                errors = _e009()
            self.assertEqual(len(errors), 1)
            self.assertIn('directory', errors[0].msg)
            self.assertTrue(directory.is_dir())

        class _BytesPath(os.PathLike):
            def __fspath__(self):
                return b'/tmp/trusts-policy.lock.yaml'

        with self.assertRaises(TrustsConfigurationError) as ctx:
            resolve_lockfile_path(override=_BytesPath())
        self.assertIn('bytes', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            write_policy_lock(payload, override=_BytesPath())
        self.assertIn('bytes', str(ctx.exception))


class ShortModelNameTest(SimpleTestCase):
    def test_lower_name_for_strings_models_and_other_classes(self):
        from django.contrib.auth.models import User
        from trusts.utils import get_short_model_name_lower

        self.assertEqual(get_short_model_name_lower('Auth.User'), 'auth.user')
        self.assertEqual(get_short_model_name_lower(User), 'auth.user')

        class Plain(object):
            pass

        self.assertEqual(get_short_model_name_lower(Plain), '')


def math_sign(value):
    import math
    return math.copysign(1.0, value)


def _has_perm_consts(name, field):
    content, grant = _pk_pair(name, field)
    handle = _handle('documents.backends.%sBackend' % name)
    handle.register(
        trust=grant,
        user='user',
        permission='permission',
        content='document',
    )
    first = render_policy_sql_bytes(handles=[handle])
    second = render_policy_sql_bytes(handles=[handle])
    if first != second:
        raise AssertionError('sentinel render was not deterministic for %s' % name)
    document = _load_policy_sql_document(first)
    content_row = document['backends'][0]['contents'][0]
    if content_row['model'] != content._meta.label:
        raise AssertionError(content_row['model'])
    return [
        row['const']
        for row in content_row['has_perm']['params']
        if 'const' in row
    ]
