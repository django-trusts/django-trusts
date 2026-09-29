"""C2. Quiet UTF-8/LF bytes, strict reader, and canonical identity."""

import copy
import json
import os
import subprocess
import sys

from django.test import SimpleTestCase

from trusts.conditions._ir import (
    And,
    ConditionRecord,
    Const,
    Eq,
    Or,
    Ref as FilterRef,
    _Ordering,
)
from trusts.core import (
    TrustsConfigurationError,
    TrustsRegistry,
)
from trusts.policy_lock import (
    ALONG_SUPPORTED,
    COMPILER_VERSION,
    SCHEMA_VERSION,
    SQLITE_JSON1_RCTE_PROFILE,
    build_policy_manifest,
    canonicalize,
    manifest_to_json_data,
    read_canonical_policy,
)

from tests.core.test_issue147.support import (
    REPO_ROOT,
    _OUT_INT,
    _SAFE_INT,
    _data,
    _direct,
    _eq_expr,
    _forbid_sql,
    _handle,
    _lock_document,
    _minimal_along,
    _minimal_registration_payload,
    _owned,
    _policy_models,
    _sha,
)


class PolicyLockCanonicalTest(SimpleTestCase):
    """C2 quiet bytes, strict reader, and canonical identity."""

    def test_quiet_bytes_regenerate_and_match_across_processes(self):
        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        registry.register_permission_condition(
            Doc, 'titled', lambda u, p, o: o.title == 'café',
        )
        handle = _handle(registry, 'tests.policy.quiet')
        with _owned(handle):
            with _forbid_sql():
                manifest = build_policy_manifest([handle])
                blob = canonicalize(manifest)
                again = canonicalize(manifest)
        self.assertIsInstance(blob, bytes)
        self.assertEqual(blob, again)
        self.assertTrue(blob.endswith(b'\n'))
        self.assertNotIn(b'\r', blob)
        self.assertFalse(blob.startswith(b'\xef\xbb\xbf'))
        self.assertIn('café'.encode('utf-8'), blob)
        self.assertNotIn(b'\\u00e9', blob)
        text = blob.decode('utf-8')
        self.assertTrue(text.startswith('{\n  "schema_version": 1,\n'))
        loaded = json.loads(text)
        self.assertEqual(
            list(loaded),
            ['schema_version', 'compiler_version', 'handles'],
        )
        self.assertEqual(
            list(loaded['handles'][0]),
            [
                'path', 'family', 'compiler', 'renderer',
                'registrations', 'named_filters',
            ],
        )
        self.assertEqual(
            read_canonical_policy(blob),
            manifest_to_json_data(manifest),
        )
        self.assertEqual(canonicalize(blob), blob)

        edited = json.loads(text)
        edited['diagnostics'] = {
            'generated_at': '2020-01-01T00:00:00Z',
            'checkout': '/tmp/secret-checkout',
        }
        messy = json.dumps(edited, indent=4, sort_keys=True).replace('\n', '\r\n')
        self.assertIn('\r\n', messy)
        regenerated = canonicalize(messy.encode('utf-8'))
        self.assertEqual(regenerated, blob)
        semantic = read_canonical_policy(messy)
        self.assertNotIn('diagnostics', semantic)
        self.assertNotIn(b'diagnostics', regenerated)
        self.assertNotIn(b'secret-checkout', regenerated)
        self.assertEqual(semantic, manifest_to_json_data(manifest))

        empty = canonicalize({
            'compiler_version': 1,
            'handles': [],
            'diagnostics': {'noise': True},
            'schema_version': 1,
        })
        self.assertEqual(
            empty,
            b'{\n  "schema_version": 1,\n  "compiler_version": 1,\n  "handles": []\n}\n',
        )
        self.assertEqual(canonicalize(empty), empty)

        root = str(REPO_ROOT)
        script = (
            'import json, os, sys\n'
            'os.environ.setdefault("DJANGO_SETTINGS_MODULE", "tests.settings")\n'
            'import django\n'
            'django.setup()\n'
            'from trusts.policy_lock import canonicalize\n'
            'raw = sys.stdin.buffer.read()\n'
            'sys.stdout.buffer.write(canonicalize(json.loads(raw.decode("utf-8"))))\n'
        )
        env = os.environ.copy()
        env['PYTHONPATH'] = root + os.pathsep + env.get('PYTHONPATH', '')
        env['DJANGO_SETTINGS_MODULE'] = 'tests.settings'
        proc = subprocess.run(
            [sys.executable, '-c', script],
            input=json.dumps(json.loads(text)).encode('utf-8'),
            capture_output=True,
            cwd=root,
            env=env,
            check=False,
        )
        self.assertEqual(
            proc.returncode, 0, proc.stderr.decode('utf-8', 'replace'),
        )
        self.assertEqual(proc.stdout, blob)

    def test_diagnostics_are_top_level_only_and_do_not_mutate_input(self):
        document = _lock_document(_eq_expr('rank', {'type': 'int', 'value': 1}))
        document['diagnostics'] = {'note': 'keep out', 'nested': {'x': 1}}
        original = copy.deepcopy(document)
        semantic = read_canonical_policy(document)
        self.assertEqual(document, original)
        self.assertNotIn('diagnostics', semantic)
        self.assertNotIn(b'diagnostics', canonicalize(document))
        nested = copy.deepcopy(document)
        del nested['diagnostics']
        nested['handles'][0]['diagnostics'] = {'note': 'nope'}
        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy(nested)
        self.assertIn('diagnostics', str(ctx.exception))
        self.assertIn('unexpected', str(ctx.exception))

    def test_non_object_diagnostics_are_rejected(self):
        base = _lock_document(_eq_expr('rank', {'type': 'int', 'value': 1}))
        samples = (
            (None, 'NoneType'),
            ('note', 'str'),
            (['a'], 'list'),
            (1, 'int'),
            (1.5, 'float'),
            (True, 'bool'),
        )
        for value, type_name in samples:
            document = copy.deepcopy(base)
            document['diagnostics'] = value
            for source in (document, json.dumps(document), json.dumps(document).encode('utf-8')):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    read_canonical_policy(source)
                message = str(ctx.exception)
                self.assertIn('diagnostics', message)
                self.assertIn('object', message)
                self.assertIn(type_name, message)
                with self.assertRaises(TrustsConfigurationError):
                    canonicalize(source)
        empty = copy.deepcopy(base)
        empty['diagnostics'] = {}
        self.assertNotIn('diagnostics', read_canonical_policy(empty))
        self.assertNotIn(b'diagnostics', canonicalize(empty))
        absent = copy.deepcopy(base)
        self.assertEqual(canonicalize(absent), canonicalize(empty))

    def test_duplicate_semantic_identities_are_rejected(self):
        base = _lock_document(_eq_expr('rank', {'type': 'int', 'value': 1}))
        path = base['handles'][0]['path']
        fingerprint = base['handles'][0]['registrations'][0]['fingerprint']

        def reject(document, needles):
            for source in (document, json.dumps(document).encode('utf-8')):
                with self.assertRaises(TrustsConfigurationError) as ctx:
                    canonicalize(source)
                message = str(ctx.exception)
                self.assertIn('duplicates', message)
                for needle in needles:
                    self.assertIn(needle, message)
                with self.assertRaises(TrustsConfigurationError):
                    read_canonical_policy(source)

        left = copy.deepcopy(base['handles'][0])
        right = copy.deepcopy(base['handles'][0])
        right['renderer']['alias'] = 'other'
        for handles in ((left, right), (right, left)):
            document = copy.deepcopy(base)
            document['handles'] = [copy.deepcopy(item) for item in handles]
            reject(document, (path, 'handle path', 'handles[1]', 'handles[0]'))

        changed_compiler = copy.deepcopy(right)
        changed_compiler['compiler'] = 'tests.core.test_issue147.PortableOtherCompiler'
        document = copy.deepcopy(base)
        document['handles'] = [left, changed_compiler]
        reject(document, (path, 'handle path'))

        third = copy.deepcopy(left)
        third['renderer']['engine'] = 'django.db.backends.postgresql'
        document = copy.deepcopy(base)
        other_path = copy.deepcopy(left)
        other_path['path'] = 'tests.policy.other'
        document['handles'] = [left, other_path, third]
        reject(document, (path, 'handles[2]', 'handles[0]'))

        first_reg = copy.deepcopy(base['handles'][0]['registrations'][0])
        second_reg = copy.deepcopy(first_reg)
        second_reg['label'] = 'app.Grant:other'
        second_reg['content'] = ['other']
        for regs in ((first_reg, second_reg), (second_reg, first_reg)):
            document = copy.deepcopy(base)
            document['handles'][0]['registrations'] = [
                copy.deepcopy(item) for item in regs
            ]
            reject(document, (
                fingerprint,
                'registration fingerprint',
                'registrations[1]',
                'registrations[0]',
            ))

        same_reg = copy.deepcopy(first_reg)
        document = copy.deepcopy(base)
        document['handles'][0]['registrations'] = [first_reg, same_reg]
        reject(document, (fingerprint, 'registration fingerprint'))

        first_filter = copy.deepcopy(base['handles'][0]['named_filters'][0])
        second_filter = copy.deepcopy(first_filter)
        second_filter['fingerprint'] = _sha('cd')
        second_filter['expr'] = _eq_expr('title', {'type': 'str', 'value': 'x'})
        for filters in ((first_filter, second_filter), (second_filter, first_filter)):
            document = copy.deepcopy(base)
            document['handles'][0]['named_filters'] = [
                copy.deepcopy(item) for item in filters
            ]
            reject(document, (
                'app.Doc:ranked',
                'named filter',
                'named_filters[1]',
                'named_filters[0]',
            ))

        same_code = copy.deepcopy(second_filter)
        same_code['model'] = 'app.Other'
        other_model = copy.deepcopy(first_filter)
        other_model['code'] = 'titled'
        other_model['fingerprint'] = _sha('ef')
        document = copy.deepcopy(base)
        document['handles'][0]['named_filters'] = [
            first_filter, same_code, other_model,
        ]
        semantic = read_canonical_policy(document)
        codes = [
            (row['model'], row['code'])
            for row in semantic['handles'][0]['named_filters']
        ]
        self.assertEqual(codes, [
            ('app.Doc', 'ranked'),
            ('app.Doc', 'titled'),
            ('app.Other', 'ranked'),
        ])

        shared = copy.deepcopy(base)
        shared['handles'].append(copy.deepcopy(base['handles'][0]))
        shared['handles'][1]['path'] = 'tests.policy.other'
        semantic = read_canonical_policy(shared)
        self.assertEqual(
            [row['fingerprint'] for row in semantic['handles'][0]['registrations']],
            [row['fingerprint'] for row in semantic['handles'][1]['registrations']],
        )
        self.assertEqual(
            [
                (row['model'], row['code'])
                for row in semantic['handles'][0]['named_filters']
            ],
            [
                (row['model'], row['code'])
                for row in semantic['handles'][1]['named_filters']
            ],
        )

    def test_admitted_documents_have_one_canonical_byte_form(self):
        def registration(label, content, digest, predicates):
            payload = _minimal_registration_payload()
            payload['content'] = [content]
            payload['condition'] = {'op': 'all', 'predicates': predicates}
            row = {'fingerprint': digest, 'label': label}
            row.update(payload)
            return row

        def named(model, code, args, digest):
            return {
                'model': model,
                'code': code,
                'fingerprint': digest,
                'expr': {'op': 'and', 'args': args},
            }

        def handle(path, registrations, named_filters, alias):
            return {
                'path': path,
                'family': 'relationship',
                'compiler': 'trusts.core.PlanQueryCompiler',
                'renderer': {
                    'alias': alias,
                    'engine': 'django.db.backends.sqlite3',
                    'profile': SQLITE_JSON1_RCTE_PROFILE,
                    'profile_version': 1,
                    'along': ALONG_SUPPORTED,
                },
                'registrations': registrations,
                'named_filters': named_filters,
            }

        eq_team = {'op': 'equal', 'left': ['team'], 'right': ['repo']}
        perm_za = {'op': 'permission_in', 'refs': [['z'], ['a']]}
        perm_az = {'op': 'permission_in', 'refs': [['a'], ['z']]}
        arg_rank = _eq_expr('rank', {'type': 'int', 'value': 1})
        arg_title = _eq_expr('title', {'type': 'str', 'value': 'x'})

        def document(reverse):
            def order(items):
                rows = [copy.deepcopy(item) for item in items]
                if reverse:
                    rows.reverse()
                return rows

            if reverse:
                predicates = [perm_az, eq_team]
            else:
                predicates = [eq_team, perm_za]
            low_regs = order((
                registration(
                    'app.Grant:late', 'late', _sha('bb'), predicates,
                ),
                registration(
                    'app.Grant:early', 'early', _sha('aa'),
                    list(reversed(predicates)),
                ),
            ))
            high_regs = order((
                registration('app.Grant:zeta', 'zeta', _sha('dd'), [eq_team, perm_za]),
                registration('app.Grant:mid', 'mid', _sha('cc'), [perm_az, eq_team]),
            ))
            low_named = order((
                named('app.Zed', 'open', [arg_title, arg_rank], _sha('22')),
                named('app.Alpha', 'ranked', [arg_rank, arg_title], _sha('11')),
            ))
            high_named = order((
                named('app.Zed', 'visible', [arg_rank, arg_title], _sha('44')),
                named('app.Mid', 'titled', [arg_title, arg_rank], _sha('33')),
            ))
            handles = [
                handle('tests.policy.z', high_regs, high_named, 'other'),
                handle('tests.policy.a', low_regs, low_named, 'default'),
            ]
            if not reverse:
                handles.reverse()
            return {
                'schema_version': SCHEMA_VERSION,
                'compiler_version': COMPILER_VERSION,
                'handles': handles,
            }

        forward = document(False)
        backward = document(True)
        handles_only = copy.deepcopy(forward)
        handles_only['handles'].reverse()
        blobs = [
            canonicalize(forward),
            canonicalize(backward),
            canonicalize(handles_only),
            canonicalize(json.dumps(backward)),
            canonicalize(json.dumps(forward).encode('utf-8')),
        ]
        self.assertEqual(len(set(blobs)), 1)
        self.assertEqual(canonicalize(blobs[0]), blobs[0])
        semantic = read_canonical_policy(forward)
        self.assertEqual(read_canonical_policy(backward), semantic)
        self.assertEqual(
            [row['path'] for row in semantic['handles']],
            ['tests.policy.a', 'tests.policy.z'],
        )
        self.assertEqual(
            [row['path'] for row in forward['handles']],
            ['tests.policy.a', 'tests.policy.z'],
        )
        self.assertEqual(
            [row['path'] for row in backward['handles']],
            ['tests.policy.z', 'tests.policy.a'],
        )
        low = semantic['handles'][0]
        self.assertEqual(
            [row['fingerprint'] for row in low['registrations']],
            [_sha('aa'), _sha('bb')],
        )
        self.assertEqual(
            [(row['model'], row['code']) for row in low['named_filters']],
            [('app.Alpha', 'ranked'), ('app.Zed', 'open')],
        )
        for row in low['named_filters']:
            args = row['expr']['args']
            self.assertEqual(
                [arg['left']['path'] for arg in args],
                [['rank'], ['title']],
            )
        predicates = low['registrations'][0]['condition']['predicates']
        self.assertEqual(
            [row['op'] for row in predicates],
            ['equal', 'permission_in'],
        )
        self.assertEqual(predicates[1]['refs'], [['a'], ['z']])

    def test_commutative_named_filters_are_byte_stable(self):
        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()

        def build(expr, code):
            registry = TrustsRegistry()
            _direct(registry, Grant)
            registry.conditions._records[(Doc._meta.label, code)] = ConditionRecord(
                expr=expr, model=Doc,
            )
            return _handle(registry, 'tests.policy.commutative')

        def eq(name, value):
            return Eq(FilterRef('object', (name,)), Const(value))

        left_tree = And(
            And(eq('rank', 2), eq('title', 'x')),
            eq('confidential', False),
        )
        right_tree = And(
            eq('confidential', False),
            And(eq('title', 'x'), eq('rank', 2)),
        )
        or_left = Or(Or(eq('rank', 2), eq('title', 'x')), eq('confidential', False))
        or_right = Or(eq('title', 'x'), Or(eq('confidential', False), eq('rank', 2)))
        mixed = Or(And(eq('rank', 2), eq('title', 'x')), eq('confidential', False))
        handles = [
            build(left_tree, 'combo'),
            build(right_tree, 'combo'),
            build(or_left, 'combo'),
            build(or_right, 'combo'),
            build(mixed, 'combo'),
        ]
        with _owned(*handles):
            with _forbid_sql():
                blobs = [canonicalize(build_policy_manifest([item])) for item in handles]
        self.assertEqual(blobs[0], blobs[1])
        self.assertEqual(blobs[2], blobs[3])
        self.assertNotEqual(blobs[0], blobs[2])
        self.assertNotEqual(blobs[0], blobs[4])
        left_expr = json.loads(blobs[0].decode('utf-8'))['handles'][0]['named_filters'][0]['expr']
        self.assertEqual(left_expr['op'], 'and')
        self.assertNotIn('left', left_expr)
        self.assertEqual(len(left_expr['args']), 3)
        paths = [arg['left']['path'] for arg in left_expr['args']]
        self.assertEqual(paths, sorted(paths))

        a = _eq_expr('a', {'type': 'int', 'value': 1})
        b = _eq_expr('b', {'type': 'bool', 'value': True})
        c = _eq_expr('c', {'type': 'str', 'value': 'z'})
        associated = {
            'op': 'and',
            'left': {'op': 'and', 'left': c, 'right': a},
            'right': b,
        }
        unsorted = {'op': 'and', 'args': [c, b, a]}
        self.assertEqual(
            canonicalize(_lock_document(associated)),
            canonicalize(_lock_document(unsorted)),
        )
        ordered_eq = read_canonical_policy(_lock_document(
            {'op': 'eq', 'left': a['left'], 'right': c['left']},
        ))['handles'][0]['named_filters'][0]['expr']
        swapped_eq = read_canonical_policy(_lock_document(
            {'op': 'eq', 'left': c['left'], 'right': a['left']},
        ))['handles'][0]['named_filters'][0]['expr']
        self.assertNotEqual(ordered_eq, swapped_eq)
        self.assertEqual(ordered_eq['left']['path'], ['a'])
        self.assertEqual(swapped_eq['left']['path'], ['c'])

        nested_or = {
            'op': 'or',
            'left': {'op': 'and', 'args': [a, b]},
            'right': c,
        }
        flattened = read_canonical_policy(_lock_document(nested_or))
        expr = flattened['handles'][0]['named_filters'][0]['expr']
        self.assertEqual(expr['op'], 'or')
        self.assertEqual(len(expr['args']), 2)
        self.assertTrue(any(item.get('op') == 'and' for item in expr['args']))

    def test_integer_encoding_boundary(self):
        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        samples = (
            ('zero', 0, 'int', 0),
            ('safe', _SAFE_INT, 'int', _SAFE_INT),
            ('safe_neg', -_SAFE_INT, 'int', -_SAFE_INT),
            ('out', _OUT_INT, 'int_dec', str(_OUT_INT)),
            ('out_neg', -_OUT_INT, 'int_dec', '-' + str(_OUT_INT)),
        )
        for code, number, _kind, _value in samples:
            registry.register_permission_condition(
                Doc, code, lambda u, p, o, number=number: o.rank == number,
            )
        handle = _handle(registry, 'tests.policy.integers')
        with _owned(handle):
            with _forbid_sql():
                data = manifest_to_json_data(build_policy_manifest([handle]))
                blob = canonicalize(build_policy_manifest([handle]))
        rows = {
            row['code']: row['expr']['right']['const']
            for row in data['handles'][0]['named_filters']
        }
        for code, _number, kind, value in samples:
            self.assertEqual(rows[code], {'type': kind, 'value': value})
        self.assertIn(b'"type": "int_dec"', blob)
        self.assertIn(b'"value": "9007199254740992"', blob)
        self.assertIn(b'"value": "-9007199254740992"', blob)
        self.assertNotIn(b'"value": "+', blob)
        self.assertEqual(canonicalize(blob), blob)
        decoded = read_canonical_policy(blob)
        self.assertEqual(decoded, data)

    def test_reader_rejects_cross_shape_and_noncanonical_int_dec(self):
        def expr(kind, value):
            return _eq_expr('rank', {'type': kind, 'value': value})

        accepted = (
            ('int', 0),
            ('int', _SAFE_INT),
            ('int', -_SAFE_INT),
            ('int_dec', str(_OUT_INT)),
            ('int_dec', '-' + str(_OUT_INT)),
        )
        for kind, value in accepted:
            document = _lock_document(expr(kind, value))
            const = read_canonical_policy(document)['handles'][0]['named_filters'][0]['expr']['right']['const']
            self.assertEqual(const, {'type': kind, 'value': value})

        cross = (
            ('int', _OUT_INT),
            ('int', -_OUT_INT),
            ('int', True),
            ('int', str(_SAFE_INT)),
            ('int_dec', str(_SAFE_INT)),
            ('int_dec', '-' + str(_SAFE_INT)),
            ('int_dec', '0'),
            ('int_dec', _OUT_INT),
            ('int_dec', False),
        )
        for kind, value in cross:
            with self.assertRaises(TrustsConfigurationError) as ctx:
                read_canonical_policy(_lock_document(expr(kind, value)))
            self.assertIn('cross-shape', str(ctx.exception))

        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy(_lock_document(expr('int', 1.0)))
        self.assertIn('float', str(ctx.exception))

        noncanonical = (
            '+' + str(_OUT_INT),
            '0' + str(_OUT_INT),
            '-0' + str(_OUT_INT),
            '-0',
            '00',
            str(_OUT_INT) + '.0',
            '9.007199254740992e15',
            ' ' + str(_OUT_INT),
            '',
            '²',
        )
        for spelling in noncanonical:
            with self.assertRaises(TrustsConfigurationError) as ctx:
                canonicalize(_lock_document(expr('int_dec', spelling)))
            message = str(ctx.exception)
            self.assertIn('noncanonical int_dec', message)
            self.assertNotIn('cross-shape', message)

    def test_reader_rejects_unsupported_constants_and_ops(self):
        def reject(expr, needle, hidden=()):
            with self.assertRaises(TrustsConfigurationError) as ctx:
                read_canonical_policy(_lock_document(expr))
            message = str(ctx.exception)
            self.assertIn(needle, message)
            for item in hidden:
                self.assertNotIn(item, message)
            return message

        reject(
            _eq_expr('rank', {'type': 'float', 'value': 1.5}),
            'float',
        )
        reject(
            _eq_expr('title', {
                'type': 'ModelIdentity',
                'value': {'app_label': 'myapp', 'model_name': 'doc', 'pk': 9},
            }),
            'ModelIdentity',
            ('myapp', 'doc'),
        )
        reject(
            _eq_expr('title', {'type': 'bytes', 'value': 'abc'}),
            'bytes',
        )
        reject(
            _eq_expr('title', {'type': 'decimal', 'value': '1.25'}),
            'decimal',
        )
        reject(
            {'op': 'lt', 'left': {'ref': 'object', 'path': ['rank']}, 'right': {'const': {'type': 'int', 'value': 1}}},
            'lt',
        )
        reject(
            {'op': 'and', 'left': _eq_expr('a', {'type': 'int', 'value': 1}), 'right': _eq_expr('b', {'type': 'int', 'value': 2}), 'args': []},
            'both args and left/right',
        )

        _org, Doc, Grant, _node, _item, _node_grant = _policy_models()
        registry = TrustsRegistry()
        _direct(registry, Grant)
        registry.conditions._records[(Doc._meta.label, 'lt')] = ConditionRecord(
            expr=_Ordering('lt', FilterRef('object', ('rank',)), Const(1)),
            model=Doc,
        )
        with self.assertRaises(TrustsConfigurationError) as ctx:
            _data([_handle(registry, 'tests.policy.ordering')])
        self.assertIn('_Ordering', str(ctx.exception))

    def test_unknown_fields_are_rejected_recursively(self):
        base = _lock_document(_eq_expr('rank', {'type': 'int', 'value': 1}))

        def reject(mutate, needle):
            document = copy.deepcopy(base)
            mutate(document)
            with self.assertRaises(TrustsConfigurationError) as ctx:
                read_canonical_policy(document)
            message = str(ctx.exception)
            self.assertIn(needle, message)
            self.assertIn('unexpected', message)

        reject(lambda doc: doc.__setitem__('package_version', '1.0'), 'package_version')
        reject(
            lambda doc: doc['handles'][0].__setitem__('note', True),
            'note',
        )
        reject(
            lambda doc: doc['handles'][0]['renderer'].__setitem__('PASSWORD', 's3cret'),
            'PASSWORD',
        )
        reject(
            lambda doc: doc['handles'][0]['registrations'][0].__setitem__('lineno', 4),
            'lineno',
        )
        reject(
            lambda doc: doc['handles'][0]['registrations'][0].__setitem__(
                'condition', {
                    'op': 'equal',
                    'left': ['team'],
                    'right': ['repo'],
                    'note': 'x',
                },
            ),
            'note',
        )
        reject(
            lambda doc: doc['handles'][0]['registrations'][0].__setitem__(
                'condition', {
                    'op': 'all',
                    'predicates': [{
                        'op': 'equal',
                        'left': ['team'],
                        'right': ['repo'],
                        'extra': 1,
                    }],
                },
            ),
            'extra',
        )
        reject(
            lambda doc: doc['handles'][0]['registrations'][0].__setitem__(
                'along', dict(_minimal_along(), walk_field='node'),
            ),
            'walk_field',
        )
        reject(
            lambda doc: doc['handles'][0]['named_filters'][0].__setitem__('source', 'app.py'),
            'source',
        )
        reject(
            lambda doc: doc['handles'][0]['named_filters'][0]['expr'].__setitem__('note', 1),
            'note',
        )
        reject(
            lambda doc: doc['handles'][0]['named_filters'][0]['expr']['right']['const'].__setitem__('base', 10),
            'base',
        )
        reject(
            lambda doc: doc['handles'][0]['named_filters'][0]['expr']['left'].__setitem__('lineno', 3),
            'lineno',
        )

        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy(b'\xef\xbb\xbf{}')
        self.assertIn('BOM', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy(b'\xff')
        self.assertIn('UTF-8', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy('{')
        self.assertIn('JSON', str(ctx.exception))
        self.assertIsInstance(ctx.exception.__cause__, json.JSONDecodeError)
        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy({'schema_version': True, 'compiler_version': 1, 'handles': []})
        self.assertIn('schema_version', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy({'schema_version': '1', 'compiler_version': 1, 'handles': []})
        self.assertIn('schema_version', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy({'schema_version': 1, 'compiler_version': 2, 'handles': []})
        self.assertIn('compiler_version', str(ctx.exception))
        with self.assertRaises(TrustsConfigurationError) as ctx:
            read_canonical_policy({'schema_version': 1, 'compiler_version': 1})
        self.assertIn('handles', str(ctx.exception))
        with self.assertRaises(TypeError):
            read_canonical_policy(build_policy_manifest([]))

        low = _lock_document()
        high = _lock_document()
        high['handles'][0]['path'] = 'tests.policy.zzz'
        scrambled = {
            'schema_version': 1,
            'compiler_version': 1,
            'handles': [high['handles'][0], low['handles'][0]],
        }
        ordered = {
            'schema_version': 1,
            'compiler_version': 1,
            'handles': [low['handles'][0], high['handles'][0]],
        }
        self.assertEqual(
            read_canonical_policy(scrambled),
            read_canonical_policy(ordered),
        )
        self.assertEqual(
            [item['path'] for item in read_canonical_policy(scrambled)['handles']],
            ['tests.policy.reader', 'tests.policy.zzz'],
        )

