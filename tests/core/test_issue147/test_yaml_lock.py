"""Canonical YAML lock bytes, constant spelling, and composition."""

import datetime
import importlib.util
import math
import os
import subprocess
import sys
import threading
import uuid
from decimal import Decimal
from pathlib import Path

import yaml
from django.test import SimpleTestCase

from tests.core.test_issue147.test_sql_export import (
    DocumentPermission,
    HiddenDocument,
    HiddenGrant,
    PolicyActorGrant,
    TeamDocumentPermission,
    _document_handle,
    _handle,
)
from trusts.conditions._ir import ModelIdentity
from trusts.core import TrustsConfigurationError
from trusts.policy_lock import (
    _const_from_json,
    _json_const,
    _load_policy_sql_document,
    render_policy_sql_bytes,
)
from trusts.policy_yaml import (
    PolicyYamlDumper,
    PolicyYamlError,
    dump_policy_yaml,
    _load_policy_yaml,
)

ROOT = Path(__file__).resolve().parents[3]
GOLDEN_DOCUMENT = (
    Path(__file__).with_name('golden_document_sqlite.yaml').read_bytes()
)
GOLDEN_COMPOSITION = (
    Path(__file__).with_name('golden_composition_sqlite.yaml').read_bytes()
)

_PROBE = r"""
import hashlib, sys
from trusts.policy_yaml import dump_policy_yaml
doc = {
    "schema_version": 1,
    "database": {"engine": "django.db.backends.sqlite3"},
    "flag": True,
    "other": False,
    "empty": None,
    "count": 1,
    "neg": -2,
    "amount": 1.5,
    "one": 1.0,
    "negzero": -0.0,
    "sci": 1e16,
    "small": 1e-7,
    "label": "yes",
    "day": "2024-03-04",
    "sql": "SELECT \"t\".\"id\" FROM \"t\" WHERE \"t\".\"id\" = %s",
    "params": [
        {"const": {"type": "decimal", "value": "12.50"}},
        {"bind": "user.id"},
    ],
    "trusts": [],
}
first = dump_policy_yaml(doc)
second = dump_policy_yaml(doc)
if first != second:
    sys.exit("repeat mismatch")
sys.stdout.write(hashlib.sha256(first).hexdigest())
"""


def _same(left, right):
    if isinstance(left, float) and isinstance(right, float):
        if math.isnan(left) and math.isnan(right):
            return True
        return math.copysign(1.0, left) == math.copysign(1.0, right) and left == right
    if isinstance(left, Decimal) and isinstance(right, Decimal):
        if left.is_nan() and right.is_nan():
            return True
        return left == right
    return left == right


class PolicyYamlCodecTest(SimpleTestCase):
    def test_dumper_is_the_pure_safe_dumper(self):
        self.assertIs(PolicyYamlDumper.__mro__[1], yaml.dumper.SafeDumper)
        self.assertTrue(PolicyYamlDumper.__mro__[1].__module__.startswith(
            'yaml.dumper',
        ))
        self.assertFalse(any(
            cls.__module__.startswith('yaml._yaml')
            for cls in PolicyYamlDumper.__mro__
        ))
        self.assertEqual(yaml.__version__, '6.0.3')

    def test_every_const_form_round_trips_without_yaml_tags(self):
        values = (
            None,
            True,
            False,
            'alpha',
            'true',
            'null',
            'yes',
            'no',
            'on',
            '2024-03-04',
            '1',
            '00ff',
            '12.50',
            '',
            0,
            1,
            -2,
            0.0,
            -0.0,
            1.0,
            1.5,
            1e16,
            1e-7,
            float('nan'),
            float('inf'),
            float('-inf'),
            b'',
            b'\x00\xff',
            Decimal('12.50'),
            Decimal('NaN'),
            Decimal('Infinity'),
            Decimal('-Infinity'),
            uuid.UUID('12345678-1234-5678-1234-567812345678'),
            datetime.date(2024, 3, 4),
            datetime.time(5, 6, 7),
            datetime.time(5, 6, 7, 8),
            datetime.datetime(2024, 3, 4, 5, 6, 7),
            datetime.datetime(
                2024, 3, 4, 5, 6, 7, tzinfo=datetime.timezone.utc,
            ),
            datetime.timedelta(days=1, seconds=2, microseconds=3),
            datetime.timedelta(days=-1, seconds=2, microseconds=3),
            ModelIdentity('auth', 'user', 7),
            ModelIdentity(
                'auth', 'user',
                uuid.UUID('12345678-1234-5678-1234-567812345678'),
            ),
            ModelIdentity('app', 'row', ModelIdentity('auth', 'user', 7)),
        )
        document = {
            'params': [{'const': _json_const(value)} for value in values],
        }
        first = dump_policy_yaml(document)
        second = dump_policy_yaml(document)
        self.assertEqual(first, second)
        self.assertNotIn(b'!!', first)
        self.assertNotIn(b'\n---', first)
        text = first.decode('utf-8')
        self.assertTrue(text.startswith('params: [') and text.endswith(']\n'))
        self.assertNotIn('\n', text[:-1])
        self.assertIn('{const: -0.0}', text)
        self.assertIn('{const: 1.0}', text)
        self.assertIn('{const: 1.0e+16}', text)
        self.assertIn('value: "2024-03-04"', text)
        self.assertIn('value: "NaN"', text)
        self.assertIn('value: "12.50"', text)
        self.assertIn('hex: "00ff"', text)
        self.assertNotIn('const: yes', text)
        self.assertNotIn('const: 2024-03-04', text)
        loaded = _load_policy_yaml(first)
        self.assertEqual(dump_policy_yaml(loaded), first)
        for original, row in zip(values, loaded['params']):
            self.assertTrue(_same(original, _const_from_json(row['const'])))

    def test_diagnostic_loader_rejects_implicit_and_unsafe_forms(self):
        rejected = (
            b'yes: 1\n',
            b'value: yes\n',
            b'day: 2024-03-04\n',
            b'n: .nan\n',
            b'n: .inf\n',
            b'a: &a 1\nb: *a\n',
            b'!!python/object:x {}\n',
            b'a: 1\na: 2\n',
            b'a: {<<: {b: 1}}\n',
            b'---\nschema_version: 1\n',
            b'n: True\n',
            b'n: +1\n',
            b'n: 1.50\n',
            b"n: 'quoted'\n",
        )
        for sample in rejected:
            with self.subTest(sample=sample):
                with self.assertRaises(PolicyYamlError):
                    _load_policy_yaml(sample)
        self.assertEqual(_load_policy_yaml(b'n: "1"\n'), {'n': '1'})
        self.assertIs(_load_policy_yaml(b'n: true\n')['n'], True)
        self.assertIsNone(_load_policy_yaml(b'n: null\n')['n'])

    def test_loader_rejects_bytes_the_canonical_writer_does_not_emit(self):
        block_map = dump_policy_yaml({'a': {'b': 1}})
        block_seq = dump_policy_yaml({'items': [1, 2]})
        literal = dump_policy_yaml({'sql': 'SELECT 1'})
        self.assertEqual(_load_policy_yaml(block_map), {'a': {'b': 1}})
        self.assertEqual(_load_policy_yaml(block_map.decode('utf-8')), {'a': {'b': 1}})
        self.assertEqual(_load_policy_yaml(block_seq), {'items': [1, 2]})
        self.assertEqual(_load_policy_yaml(literal), {'sql': 'SELECT 1'})
        self.assertIn(b'\n  b: 1\n', block_map)
        self.assertNotIn(b'{', block_map)
        self.assertIn(b'\n  - 1\n', block_seq)
        self.assertNotIn(b'[', block_seq)
        self.assertIn(b'sql: |-\n', literal)
        rejected = (
            b'a: {b: 1}\n',
            b'items: [1, 2]\n',
            b'a:\n- 1\n',
            b'sql: |\n  SELECT 1\n',
            b'sql: |+\n  SELECT 1\n',
            b'sql: >-\n  SELECT 1\n',
            b'sql: |-2\n  SELECT 1\n',
            b'label: |-\n  hello\n',
            b'a: {b: 1}',
            b"n: 'quoted'\n",
            b'n: 01\n',
            b'n: 0x1\n',
        )
        for sample in rejected:
            with self.subTest(sample=sample):
                with self.assertRaises(PolicyYamlError):
                    _load_policy_yaml(sample)
        with self.assertRaises(TrustsConfigurationError):
            _load_policy_sql_document(b'a: {b: 1}\n')
        with self.assertRaises(TrustsConfigurationError):
            _load_policy_sql_document(b'items: [1, 2]\n')

    def test_hash_seed_and_locale_do_not_change_bytes(self):
        env = os.environ.copy()
        env['PYTHONPATH'] = str(ROOT) + os.pathsep + env.get('PYTHONPATH', '')
        env['PYTHONHASHSEED'] = '0'
        env['LC_ALL'] = 'C'
        env['LANG'] = 'C'
        baseline = subprocess.run(
            [sys.executable, '-c', _PROBE],
            check=True, capture_output=True, env=env, text=True,
        ).stdout
        for seed, locale in (
            ('1', 'C'),
            ('random', 'C'),
            ('random', 'C.UTF-8'),
            ('random', 'en_US.UTF-8'),
        ):
            probe_env = dict(env)
            probe_env['PYTHONHASHSEED'] = seed
            probe_env['LC_ALL'] = locale
            probe_env['LANG'] = locale
            result = subprocess.run(
                [sys.executable, '-c', _PROBE],
                check=False, capture_output=True, env=probe_env, text=True,
            )
            if result.returncode != 0 and 'locale' in (result.stderr or '').lower():
                continue
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, baseline)


class PolicyCompositionTest(SimpleTestCase):
    def test_renderer_does_not_replace_sqlcompiler_execute_sql(self):
        from django.db.models.sql.compiler import SQLCompiler

        import trusts.policy_lock as policy_lock

        self.assertIsNone(importlib.util.find_spec('trusts.policy_composition'))
        self.assertIsNone(importlib.util.find_spec(
            'tests.core.test_issue147.composition_evidence',
        ))
        source = Path(policy_lock.__file__).read_text(encoding='utf-8')
        self.assertNotIn('SQLCompiler.execute_sql', source)
        original = SQLCompiler.execute_sql
        samples = []
        stop = threading.Event()

        def watch():
            while not stop.is_set():
                current = SQLCompiler.execute_sql
                if current is not original:
                    samples.append(current)

        watcher = threading.Thread(target=watch)
        watcher.start()
        try:
            payload = render_policy_sql_bytes(handles=self._handles())
        finally:
            stop.set()
            watcher.join()
        self.assertEqual(payload, GOLDEN_COMPOSITION)
        self.assertEqual(samples, [])
        self.assertIs(SQLCompiler.execute_sql, original)

    def _handles(self):
        or_handle = _handle('documents.backends.OrBackend')
        or_handle.register(
            trust=DocumentPermission,
            user='user',
            permission='permission',
            content='document',
        )
        or_handle.register(
            trust=TeamDocumentPermission,
            user='team__members',
            permission='permission',
            content='document',
        )
        return [_document_handle(), or_handle]

    def test_lockfile_composition_matches_golden(self):
        payload = render_policy_sql_bytes(handles=self._handles())
        self.assertEqual(payload, GOLDEN_COMPOSITION)
        self.assertEqual(payload, render_policy_sql_bytes(handles=self._handles()))
        document = _load_policy_sql_document(payload)
        self.assertEqual(document['schema_version'], 1)
        self.assertNotIn('lockfile', document)
        self.assertNotIn('role', document)
        guide = document['backends'][0]['contents'][0]
        trust = guide['trusts'][0]
        named = guide['named_filters'][0]
        self.assertNotIn('sql', trust)
        self.assertNotIn('documents_documentpermission', named['sql'])
        self.assertNotIn('composition', document['backends'][0])
        self.assertNotIn('{{', payload.decode('utf-8'))
        self.assertNotIn('change_document', payload.decode('utf-8'))
        self.assertEqual(set(guide['has_perm']), {'sql', 'params'})
        self.assertIn('EXISTS(', guide['has_perm']['sql'])
        self.assertIn('documents_documentpermission', guide['has_perm']['sql'])
        self.assertIn({'bind': 'permission.id'}, guide['has_perm']['params'])
        self.assertIn({'bind': 'user.id'}, guide['has_perm']['params'])
        self.assertEqual(set(guide['permitted']), {'sql', 'params'})
        self.assertIn('documents_documentpermission', guide['permitted']['sql'])
        self.assertNotIn('confidential" IS NULL', guide['permitted']['sql'])
        self.assertNotIn('confidential" = %s', guide['permitted']['sql'])
        self.assertEqual(named['id'], 'non_confidential')
        self.assertIn('confidential', named['sql'])
        self.assertEqual(set(guide['get_all_permissions']), {'sql', 'params'})
        self.assertIn('auth_permission', guide['get_all_permissions']['sql'])
        combined = document['backends'][1]['contents'][0]
        self.assertIs(combined['trusts'][0]['or_group'], True)
        self.assertIs(combined['trusts'][1]['or_group'], True)
        self.assertIn(' OR ', combined['permitted']['sql'])
        self.assertIn('documents_documentpermission', combined['permitted']['sql'])
        self.assertIn('"documents_team"', combined['permitted']['sql'])
        self.assertNotIn('named_filters', combined)

    def test_document_lockfile_includes_content_sql(self):
        payload = render_policy_sql_bytes(handles=[_document_handle()])
        self.assertEqual(payload, GOLDEN_DOCUMENT)
        text = payload.decode('utf-8')
        self.assertNotIn('composition-evidence', text)
        self.assertNotIn('composition:', text)
        self.assertNotIn('fragments:', text)
        self.assertNotIn('{{', text)
        self.assertIn('\n        permitted:\n', text)
        self.assertIn('\n        has_perm:\n', text)
        self.assertIn('\n        get_all_permissions:\n', text)
        document = _load_policy_sql_document(payload)
        content = document['backends'][0]['contents'][0]
        trust = content['trusts'][0]
        self.assertEqual(
            trust['id'], 'documents.DocumentPermission__document',
        )
        self.assertNotIn('sql', trust)
        self.assertIn('sql', content['permitted'])

    def test_model_without_objects_manager_still_composes(self):
        self.assertFalse(hasattr(HiddenDocument, 'objects'))
        self.assertIs(
            HiddenDocument._meta.concrete_model._default_manager,
            HiddenDocument._default_manager,
        )
        handle = _handle('documents.backends.HiddenBackend')
        handle.register(
            trust=HiddenGrant,
            user='user',
            permission='permission',
            content='document',
        )
        document = _load_policy_sql_document(
            render_policy_sql_bytes(handles=[handle]),
        )
        content = document['backends'][0]['contents'][0]
        trust = content['trusts'][0]
        self.assertNotIn('sql', trust)
        self.assertIn('documents_hiddendocument', content['permitted']['sql'])
        self.assertIn('documents_hiddendocument', content['has_perm']['sql'])
        self.assertEqual(set(content['has_perm']), {'sql', 'params'})

    def test_mixed_user_models_fail_closed(self):
        handle = _handle('documents.backends.MixedBackend')
        handle.register(
            trust=DocumentPermission,
            user='user',
            permission='permission',
            content='document',
        )
        handle.register(
            trust=PolicyActorGrant,
            user='user',
            permission='permission',
            content='document',
        )
        with self.assertRaises(TrustsConfigurationError) as ctx:
            render_policy_sql_bytes(handles=[handle])
        self.assertIn('one user model', str(ctx.exception))
