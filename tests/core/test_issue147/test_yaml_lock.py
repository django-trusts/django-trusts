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
from trusts.policy_composition import (
    _append_operation,
    _factor,
    _verify_composition,
)
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
        self.assertIn('\n  - const: -0.0\n', text)
        self.assertIn('\n  - const: 1.0\n', text)
        self.assertIn('\n  - const: 1.0e+16\n', text)
        self.assertIn('value: "2024-03-04"', text)
        self.assertIn('value: "NaN"', text)
        self.assertIn('value: "12.50"', text)
        self.assertIn('hex: "00ff"', text)
        self.assertNotIn('\n  - const: yes\n', text)
        self.assertNotIn('\n  - const: 2024-03-04\n', text)
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

        import trusts.policy_composition as policy_composition

        self.assertIsNotNone(
            importlib.util.find_spec('trusts.policy_composition'),
        )
        self.assertIsNone(importlib.util.find_spec(
            'tests.core.test_issue147.composition_evidence',
        ))
        source = Path(policy_composition.__file__).read_text(encoding='utf-8')
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

    def test_lockfile_composition_matches_golden_and_expands(self):
        payload = render_policy_sql_bytes(handles=self._handles())
        self.assertEqual(payload, GOLDEN_COMPOSITION)
        self.assertEqual(payload, render_policy_sql_bytes(handles=self._handles()))
        document = _load_policy_sql_document(payload)
        self.assertEqual(document['schema_version'], 1)
        self.assertNotIn('lockfile', document)
        self.assertNotIn('role', document)
        guide = document['backends'][0]
        trust = guide['trusts'][0]
        named = guide['named_filters'][0]
        self.assertNotIn('{{', trust['sql'])
        self.assertNotIn('documents_documentpermission', named['sql'])
        composition = guide['composition']
        _verify_composition(composition)
        by_id = {row['id']: row for row in composition['operations']}
        instance = by_id['has_perm_permission_instance:documents.Document']
        self.assertEqual(instance['representation'], 'structured')
        self.assertIn(
            '{{trust:documents.DocumentPermission:document}}',
            instance['sql'],
        )
        self.assertNotIn(' IN ', instance['expanded']['sql'])
        self.assertEqual(instance['params'], [{'const': 1}, {'const': 1}])
        code = by_id['has_perm_permission_code:documents.Document']
        self.assertEqual(code['representation'], 'full_sql')
        self.assertNotIn('expanded', code)
        self.assertIn('"V0"', code['sql'])
        self.assertIn('"codename"', code['sql'])
        self.assertNotIn(
            '"documents_documentpermission" "U0"',
            code['sql'],
        )
        self.assertIn({'const': 'change_document'}, code['params'])
        composed = by_id[
            'authorized_and_named_filter:documents.Document:non_confidential'
        ]
        self.assertEqual(composed['representation'], 'structured')
        self.assertEqual(composed['params'], [])
        self.assertEqual(
            [ref['fragment'] for ref in composed['refs']],
            [
                'trust:documents.DocumentPermission:document',
                'predicate:documents.Document:non_confidential',
            ],
        )
        queryset_code = by_id[
            'queryset_has_perm_permission_code:documents.Document'
        ]
        self.assertEqual(queryset_code['representation'], 'full_sql')
        self.assertIn('COUNT(DISTINCT', queryset_code['sql'])
        self.assertIn('"V0"', queryset_code['sql'])
        combined = document['backends'][1]['composition']['operations']
        or_group = next(
            row for row in combined if row['kind'] == 'or_group_authorized'
        )
        self.assertEqual(or_group['representation'], 'structured')
        self.assertEqual(
            [ref['fragment'] for ref in or_group['refs']],
            [
                'trust:documents.DocumentPermission:document',
                'trust:documents.TeamDocumentPermission:document',
            ],
        )
        code_or = next(
            row for row in combined
            if row['kind'] == 'has_perm_permission_code'
        )
        self.assertEqual(code_or['representation'], 'full_sql')
        self.assertIn('"V0"', code_or['sql'])
        self.assertIn('"V2"', code_or['sql'])
        _verify_composition(document['backends'][1]['composition'])

    def test_document_lockfile_includes_composition(self):
        payload = render_policy_sql_bytes(handles=[_document_handle()])
        self.assertEqual(payload, GOLDEN_DOCUMENT)
        text = payload.decode('utf-8')
        self.assertNotIn('composition-evidence', text)
        self.assertIn('has_perm_permission_instance:', text)
        self.assertIn('placeholder:', text)
        document = _load_policy_sql_document(payload)
        trust = document['backends'][0]['trusts'][0]
        self.assertNotIn('structured', trust)
        self.assertIn('sql', trust)
        self.assertIn('composition', document['backends'][0])

    def test_duplicate_fragment_id_collides(self):
        composition = self._document_composition()
        composition['fragments'].append(dict(composition['fragments'][0]))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            _verify_composition(composition)
        self.assertIn('collides', str(ctx.exception))

    def test_missing_reference_fails(self):
        composition = self._document_composition()
        operation = composition['operations'][0]
        operation['sql'] = operation['sql'].replace(
            '{{trust:documents.DocumentPermission:document}}',
            '{{trust:missing}}',
        )
        operation['refs'][0]['fragment'] = 'trust:missing'
        operation['refs'][0]['placeholder'] = '{{trust:missing}}'
        with self.assertRaises(TrustsConfigurationError) as ctx:
            _verify_composition(composition)
        self.assertIn('missing fragment', str(ctx.exception))

    def test_fragment_cycle_fails(self):
        composition = self._document_composition()
        grant, predicate = composition['fragments']
        grant['sql'] = '{{%s}}' % predicate['id']
        predicate['sql'] = '{{%s}}' % grant['id']
        with self.assertRaises(TrustsConfigurationError) as ctx:
            _verify_composition(composition)
        self.assertIn('cycle', str(ctx.exception))

    def test_open_fragment_reference_fails(self):
        composition = self._document_composition()
        grant, predicate = composition['fragments']
        grant['sql'] = '{{%s}}' % predicate['id']
        with self.assertRaises(TrustsConfigurationError) as ctx:
            _verify_composition(composition)
        self.assertIn('not closed SQL', str(ctx.exception))

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
        backend = document['backends'][0]
        trust = backend['trusts'][0]
        self.assertIn('documents_hiddendocument', trust['sql'])
        composition = backend['composition']
        _verify_composition(composition)
        by_kind = {row['kind']: row for row in composition['operations']}
        instance = by_kind['has_perm_permission_instance']
        self.assertEqual(instance['representation'], 'structured')
        self.assertIn('documents_hiddendocument', instance['expanded']['sql'])

    def test_repeated_fragment_text_stays_full_sql(self):
        fragment = {
            'id': 'trust:example',
            'kind': 'trust_exists',
            'sql': 'SELECT %s',
            'params': [{'const': 1}],
        }
        sql = 'SELECT %s AND (SELECT %s)'
        params = [{'const': 1}, {'const': 1}]
        self.assertIsNone(_factor(sql, params, [fragment]))
        operations = []
        fragments = {}
        order = []
        _append_operation(
            operations, fragments, order, 'repeated', 'kind', sql, params,
            [fragment],
        )
        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0]['representation'], 'full_sql')
        self.assertEqual(operations[0]['sql'], sql)
        self.assertNotIn('{{', operations[0]['sql'])
        self.assertEqual(fragments, {})
        self.assertEqual(order, [])

    def test_later_fragment_on_both_sides_stays_full_sql(self):
        # Compiled shape B ... A ... B. A occurs once, so a suffix-only
        # check would reference A and the second B and leave the first
        # B as raw SQL. The whole statement has two copies of B.
        piece_a = {
            'id': 'trust:a',
            'kind': 'trust_exists',
            'sql': 'AAA',
            'params': [],
        }
        piece_b = {
            'id': 'trust:b',
            'kind': 'trust_exists',
            'sql': 'BBB',
            'params': [],
        }
        sql = 'BBB AND AAA AND BBB'
        params = []
        self.assertIsNone(_factor(sql, params, [piece_a, piece_b]))
        operations = []
        fragments = {}
        order = []
        _append_operation(
            operations, fragments, order, 'sided', 'kind', sql, params,
            [piece_a, piece_b],
        )
        self.assertEqual(len(operations), 1)
        self.assertEqual(operations[0]['representation'], 'full_sql')
        self.assertEqual(operations[0]['sql'], sql)
        self.assertNotIn('{{', operations[0]['sql'])
        self.assertNotIn('refs', operations[0])
        self.assertEqual(fragments, {})
        self.assertEqual(order, [])

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

    def _document_composition(self):
        document = _load_policy_yaml(GOLDEN_DOCUMENT)
        return document['backends'][0]['composition']
