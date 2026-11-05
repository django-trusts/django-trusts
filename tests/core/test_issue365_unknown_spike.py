"""Test-local feasibility spike. Production code and the behavior pins stay.

The candidate run points ``column_q``, ``columns_q``, and ``negate_q`` at
``<>`` and ``NOT (column = TRUE)``. The via walker only drops the constant
``IS NULL OR`` wrapper and negates the boolean column. ``Exists(path)`` is
a test-local tree the grammar does not know. Nothing here is adopted.
"""
import json
import os
import re
import subprocess

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db import connection
from django.db.models import BooleanField, Exists, F, Field, OuterRef, Q
from django.db.models.expressions import BaseExpression
from django.db.models.sql.constants import INNER, LOUTER
from django.db.models.lookups import Lookup
from django.test import TransactionTestCase
from django.test.utils import CaptureQueriesContext, isolate_apps

from tests.core.test_issue365_null_matrix import (
    _add_column,
    _listed,
    _permission,
    _tables,
    _yn,
)
from tests.support import compiler
from trusts.errors import PermissionConditionError
from trusts.compile import compilers
from trusts.plan import grammar, standards, users, via, writers


_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_PRODUCTION = '186e632b0284f453eb7b6f49aabf2bf5c31bed67'
_PIN_COMMIT = '21d1c249aaac71ad908ed7c170f8c54003f5ed88'
_PINS = (
    'tests/core/issue365_expected.json',
    'tests/core/issue365_gap_expected.json',
)

# Candidate projection. Inquiry hold/fail is asserted from this: hold
# only when the value is true. Baseline inquiries are the current writer.
_CANDIDATE = {
    'ne-lit': {
        'miss': 'unknown', 'nullreg': 'unknown', 'west': 'true', 'east': 'false',
    },
    'ne-rhs': {
        'miss': 'unknown', 'nullreg': 'unknown', 'west': 'true', 'east': 'false',
    },
    'not-ban': {
        'ban_true': 'false', 'ban_false': 'true', 'miss': 'unknown',
    },
    'or-own': {
        'miss_own': 'true', 'miss': 'unknown', 'east': 'true', 'west': 'false',
    },
    'rel-none': {
        'miss': 'true', 'miss_own': 'true', 'nullreg': 'false',
        'west': 'false', 'east': 'false',
    },
    'leaf-none': {
        'miss': 'true', 'miss_own': 'true', 'nullreg': 'true',
        'west': 'false', 'east': 'false',
    },
}
# Current writer, filtered result only. NULL on ``!=`` literal is admitted.
_BASELINE_HOLD = {
    'ne-lit': {'miss', 'nullreg', 'west'},
    'ne-rhs': {'west'},
    'not-ban': {'ban_false', 'miss'},
    'or-own': {'miss_own', 'east'},
    'rel-none': {'miss', 'miss_own'},
    'leaf-none': {'miss', 'miss_own', 'nullreg'},
}
_SUBJECTS = {
    'ne-lit': ('miss', 'nullreg', 'west', 'east'),
    'ne-rhs': ('miss', 'nullreg', 'west', 'east'),
    'not-ban': ('ban_true', 'ban_false', 'miss'),
    'or-own': ('miss_own', 'miss', 'east', 'west'),
    'rel-none': ('miss', 'miss_own', 'nullreg', 'west', 'east'),
    'leaf-none': ('miss', 'miss_own', 'nullreg', 'west', 'east'),
}
# (direct, via) for users on the manager walk. ``direct`` has no via=.
# ``via`` is has_perm, permitted, and get_permitted_users through the walk.
# hop_* have no grant. unlinked has no grant and no manager.
_WALK = ('seed', 'hop_true', 'hop_unknown', 'hop_east', 'unlinked')
_WALK_EXPECT = {
    False: {
        'ne-lit': {
            'seed': ('hold', 'hold'),
            'hop_true': ('fail', 'hold'),
            'hop_unknown': ('fail', 'hold'),
            'hop_east': ('fail', 'fail'),
            'unlinked': ('fail', 'fail'),
        },
        'not-ban': {
            'seed': ('hold', 'hold'),
            'hop_true': ('fail', 'hold'),
            'hop_unknown': ('fail', 'hold'),
            'hop_east': ('fail', 'fail'),
            'unlinked': ('fail', 'fail'),
        },
        'or-own': {
            'seed': ('hold', 'hold'),
            'hop_true': ('fail', 'hold'),
            'hop_unknown': ('fail', 'fail'),
            'hop_east': ('fail', 'hold'),
            'unlinked': ('fail', 'fail'),
        },
        'rel-none': {label: ('fail', 'fail') for label in _WALK},
        'leaf-none': {label: ('fail', 'fail') for label in _WALK},
    },
    True: {
        'ne-lit': {
            'seed': ('hold', 'hold'),
            'hop_true': ('fail', 'hold'),
            'hop_unknown': ('fail', 'fail'),
            'hop_east': ('fail', 'fail'),
            'unlinked': ('fail', 'fail'),
        },
        'not-ban': {
            'seed': ('hold', 'hold'),
            'hop_true': ('fail', 'hold'),
            'hop_unknown': ('fail', 'fail'),
            'hop_east': ('fail', 'fail'),
            'unlinked': ('fail', 'fail'),
        },
        'or-own': {
            'seed': ('hold', 'hold'),
            'hop_true': ('fail', 'hold'),
            'hop_unknown': ('fail', 'fail'),
            'hop_east': ('fail', 'hold'),
            'unlinked': ('fail', 'fail'),
        },
        'rel-none': {label: ('fail', 'fail') for label in _WALK},
        'leaf-none': {label: ('fail', 'fail') for label in _WALK},
    },
}
_INQUIRIES = ('has_perm', 'permitted', 'get_permitted_users')
# Classify the candidate predicate. Hop users are included so unknown and
# false are read off the same expression the filter uses.
_CLASSIFY = {
    'ne-lit': {
        'miss': 'unknown', 'nullreg': 'unknown', 'west': 'true', 'east': 'false',
        'hop_true': 'true', 'hop_unknown': 'unknown', 'hop_east': 'false',
    },
    'ne-rhs': {
        'miss': 'unknown', 'nullreg': 'unknown', 'west': 'true', 'east': 'false',
    },
    'not-ban': {
        'ban_true': 'false', 'ban_false': 'true', 'miss': 'unknown',
        'hop_true': 'true', 'hop_unknown': 'unknown', 'hop_east': 'false',
    },
    'or-own': {
        'miss_own': 'true', 'miss': 'unknown', 'east': 'true', 'west': 'false',
        'hop_true': 'true', 'hop_unknown': 'unknown', 'hop_east': 'true',
    },
    'rel-none': {
        'miss': 'true', 'miss_own': 'true', 'nullreg': 'false',
        'west': 'false', 'east': 'false',
        'hop_unknown': 'true', 'hop_true': 'false',
    },
    'leaf-none': {
        'miss': 'true', 'miss_own': 'true', 'nullreg': 'true',
        'west': 'false', 'east': 'false',
        'hop_unknown': 'true', 'hop_east': 'false',
    },
}


class SpikeNotEqual(Lookup):
    """``lhs <> rhs``. NULL stays unknown. No ``IS NOT NULL`` is added."""

    lookup_name = 'spike_ne'

    def as_sql(self, compiler, connection):
        lhs, left = self.process_lhs(compiler, connection)
        rhs, right = self.process_rhs(compiler, connection)
        return '%s <> %s' % (lhs, rhs), tuple(left) + tuple(right)


class SpikeNotTrue(Lookup):
    """``NOT (lhs = TRUE)``. NULL stays unknown, unlike ``NOT (lhs IS TRUE)``."""

    lookup_name = 'spike_not_true'

    def as_sql(self, compiler, connection):
        lhs, left = self.process_lhs(compiler, connection)
        return 'NOT (%s = %%s)' % lhs, tuple(left) + (True,)


def _column_unknown(lookup, value, equal, *, field):
    value = writers.member_pk(value)
    if value is None and field:
        return Q(pk__in=())
    if value is None:
        return Q(**{'%s__isnull' % lookup: equal})
    if equal:
        return Q(**{lookup: value})
    return Q(**{'%s__spike_ne' % lookup: value})


def _columns_unknown(left, right, equal):
    if equal:
        return Q(**{left: F(right)})
    return Q(**{'%s__spike_ne' % left: F(right)})


def _negate_unknown(model, q):
    """SQL ``NOT`` of one ``column = TRUE``. Other shapes stay unsupported."""
    del model
    if (
        isinstance(q, Q) and not q.negated and len(q.children) == 1
        and not isinstance(q.children[0], Q)
    ):
        lookup, value = q.children[0]
        if value is True and isinstance(lookup, str):
            return Q(**{'%s__spike_not_true' % lookup: True})
    raise PermissionConditionError(
        'unknown-preserving NOT needs one boolean column; '
        'this writer shape was not rewritten.'
    )


class ClassifyPredicate(BaseExpression):
    """True arm, SQL ``NOT`` of that same predicate, else unknown.

    The arms are the filter clause. Operand ``IS NULL`` is not tested first.
    """

    def __init__(self, q):
        super().__init__(output_field=BooleanField(null=True))
        self.q = q

    def resolve_expression(
        self, query=None, allow_joins=True, reuse=None,
        summarize=False, for_save=False,
    ):
        clone = self.copy()
        clone.is_summary = summarize
        clause, _aliases = query._add_q(
            self.q,
            reuse if reuse is not None else query.used_aliases,
            allow_joins=allow_joins,
            split_subq=False,
            summarize=summarize,
            update_join_types=False,
        )
        # A nullable hop stays a left join. Promoting it to INNER would
        # drop the candidate before the predicate is read.
        for join in query.alias_map.values():
            if getattr(join, 'nullable', False) and getattr(join, 'join_type', None) == INNER:
                join.join_type = LOUTER
        clone.clause = clause
        return clone

    def as_sql(self, compiler, connection):
        sql, params = self.clause.as_sql(compiler, connection)
        piece = '(%s)' % sql
        return (
            'CASE WHEN %s THEN 1 WHEN NOT %s THEN 0 ELSE NULL END' % (piece, piece),
            tuple(params) + tuple(params),
        )


def _predicate_q():
    """The Q objects the candidate writer returns for each probe."""
    return {
        'ne-lit': Q(probe_dept__region__spike_ne='east'),
        'ne-rhs': Q(probe_dept__region__spike_ne=F('probe_east')),
        'not-ban': Q(is_banned__spike_not_true=True),
        'or-own': Q(probe_dept__region='east') | Q(is_owner=True),
        'rel-none': Q(probe_dept__isnull=True),
        'leaf-none': Q(probe_dept__region__isnull=True),
    }


def _expressions():
    return (
        ('ne-lit', lambda user: user.probe_dept.region != 'east'),
        ('ne-rhs', lambda user: user.probe_dept.region != user.probe_east),
        ('not-ban', lambda user: ~user.is_banned),
        ('or-own', lambda user: (user.probe_dept.region == 'east') | user.is_owner),
        ('rel-none', lambda user: user.probe_dept == None),  # noqa: E711
        ('leaf-none', lambda user: user.probe_dept.region == None),  # noqa: E711
    )


def _mark(value):
    if value is None:
        return 'unknown'
    if value in (True, 1):
        return 'true'
    if value in (False, 0):
        return 'false'
    return 'other:%r' % (value,)


def _freeze(params):
    frozen = []
    for param in params:
        if isinstance(param, (str, int, bool)) or param is None:
            frozen.append(param)
        else:
            frozen.append(repr(param))
    return frozen


def exists(symbol):
    """Test-local tree. The production grammar has no Exists."""
    return grammar.Tree('exists', item=symbol._field())


def _one(exc):
    return '%s: %s' % (type(exc).__name__, exc)


def _check_exists_path(model, path):
    if not path:
        raise PermissionConditionError('Exists needs a relationship path.')
    current = model
    for name in path:
        try:
            field = current._meta.get_field(name)
        except Exception as exc:
            raise PermissionConditionError(
                'Exists path missing %s.' % name
            ) from exc
        if not getattr(field, 'is_relation', False):
            raise PermissionConditionError(
                'Exists does not accept scalar leaf %s.' % name
            )
        if getattr(field, 'many_to_many', False) or getattr(field, 'one_to_many', False):
            raise PermissionConditionError(
                'Exists does not accept collection %s.' % name
            )
        current = field.remote_field.model


def _exists_q(world, path):
    Dept = world['Dept']
    Unit = world['Unit']
    if path == ('probe_dept',):
        return Q(Exists(Dept.objects.filter(pk=OuterRef('probe_dept_id'))))
    if path == ('probe_dept', 'unit'):
        return Q(Exists(Dept.objects.filter(
            pk=OuterRef('probe_dept_id'),
            unit__in=Unit.objects.all(),
        )))
    raise PermissionConditionError('Exists path %s is outside this spike.' % (path,))


def _exists_sql(user_model, path, qn):
    dept_field = user_model._meta.get_field('probe_dept')
    dept_model = dept_field.remote_field.model
    if path == ('probe_dept',):
        return (
            'EXISTS (SELECT 1 FROM %s AS %s WHERE %s.%s = {alias}.%s)'
            % (
                qn(dept_model._meta.db_table), qn('ex0'),
                qn('ex0'), qn(dept_field.target_field.column),
                qn(dept_field.column),
            )
        )
    if path == ('probe_dept', 'unit'):
        unit_field = dept_model._meta.get_field('unit')
        return (
            'EXISTS (SELECT 1 FROM %s AS %s INNER JOIN %s AS %s '
            'ON %s.%s = %s.%s WHERE %s.%s = {alias}.%s)'
            % (
                qn(dept_model._meta.db_table), qn('ex0'),
                qn(unit_field.remote_field.model._meta.db_table), qn('ex1'),
                qn('ex1'), qn(unit_field.target_field.column),
                qn('ex0'), qn(unit_field.column),
                qn('ex0'), qn(dept_field.target_field.column),
                qn(dept_field.column),
            )
        )
    raise PermissionConditionError('via Exists path is outside this spike.')


class _ExistsPatch(object):
    def __init__(self, world):
        self.world = world

    def __enter__(self):
        self.saved = []

        def swap(module, name, fn):
            self.saved.append((module, name, getattr(module, name)))
            setattr(module, name, fn)

        swap(grammar, '_PREDICATE_KINDS', frozenset(
            set(grammar._PREDICATE_KINDS) | {'exists'}
        ))
        orig_neg = grammar._negatable

        def negatable(node):
            if getattr(node, 'kind', None) == 'exists':
                return True
            return orig_neg(node)

        swap(grammar, '_negatable', negatable)
        orig_validate = standards.validate_user_rule

        def validate(model, expr, name):
            if expr.kind == 'exists':
                _check_exists_path(model, expr.item.path)
                return
            if expr.kind in ('and', 'or'):
                validate(model, expr.left, name)
                validate(model, expr.right, name)
                return
            if expr.kind == 'not':
                validate(model, expr.item, name)
                return
            return orig_validate(model, expr, name)

        swap(standards, 'validate_user_rule', validate)
        swap(compilers, 'validate_user_rule', validate)
        orig_compile = standards._compile

        def compile_expr(path, expr, scope):
            if expr.kind == 'exists':
                return _exists_q(self.world, expr.item.path)
            if expr.kind == 'not' and getattr(expr.item, 'kind', None) == 'exists':
                return ~_exists_q(self.world, expr.item.item.path)
            return orig_compile(path, expr, scope)

        swap(standards, '_compile', compile_expr)
        orig_walk = via._walk_node

        def walk(node, user_model, content_model, content, carriers, name, qn, force):
            if getattr(node, 'kind', None) == 'exists':
                return _exists_sql(user_model, node.item.path, qn)
            return orig_walk(
                node, user_model, content_model, content, carriers, name, qn, force,
            )

        swap(via, '_walk_node', walk)
        return self

    def __exit__(self, *exc):
        for module, name, fn in self.saved:
            setattr(module, name, fn)


_NOT_DEPTH = {'n': 0}
_SAVED_VIA = {}


def _walk_spike(node, user_model, content_model, content, carriers, name, qn, force):
    if getattr(node, 'kind', None) == 'not':
        _NOT_DEPTH['n'] += 1
        try:
            return _SAVED_VIA['walk'](
                node, user_model, content_model, content, carriers, name, qn, force,
            )
        finally:
            _NOT_DEPTH['n'] -= 1
    return _SAVED_VIA['walk'](
        node, user_model, content_model, content, carriers, name, qn, force,
    )


def _field_spike(node, user_model, content_model, content, carriers, name, qn, force):
    if _NOT_DEPTH['n'] and getattr(node, 'root', None) == 'user':
        field = via._local_field(user_model, node.path, name)
        if field.get_internal_type() == 'BooleanField':
            return '{alias}.%s' % qn(field.column)
    return _SAVED_VIA['field'](
        node, user_model, content_model, content, carriers, name, qn, force,
    )


def _compare_spike(node, user_model, content_model, content, carriers, name, qn, force):
    sql = _SAVED_VIA['compare'](
        node, user_model, content_model, content, carriers, name, qn, force,
    )
    if not sql or getattr(node, 'kind', None) != 'ne':
        return sql
    match = re.match(r'^\((.+) IS NULL OR \1 <> (.+)\)$', sql)
    if match:
        return '%s <> %s' % (match.group(1), match.group(2))
    return sql


class _WriterPatch(object):
    def __enter__(self):
        self.saved = []
        adapters = {
            'column_q': _column_unknown,
            'columns_q': _columns_unknown,
            'negate_q': _negate_unknown,
        }
        for module in (writers, standards, users):
            for name, fn in adapters.items():
                self.saved.append((module, name, getattr(module, name)))
                setattr(module, name, fn)
        _SAVED_VIA['walk'] = via._walk_node
        _SAVED_VIA['field'] = via._field_sql
        _SAVED_VIA['compare'] = via._compare_sql
        via._walk_node = _walk_spike
        via._field_sql = _field_spike
        via._compare_sql = _compare_spike
        return self

    def __exit__(self, *exc):
        for module, name, fn in self.saved:
            setattr(module, name, fn)
        via._walk_node = _SAVED_VIA['walk']
        via._field_sql = _SAVED_VIA['field']
        via._compare_sql = _SAVED_VIA['compare']
        _NOT_DEPTH['n'] = 0


@isolate_apps('tests', 'django.contrib.auth', 'django.contrib.contenttypes')
class UnknownPreservingSpike(TransactionTestCase):
    """Candidate rule through the real inquiries. Pins stay untouched."""

    def setUp(self):
        super().setUp()
        Field.register_lookup(SpikeNotEqual)
        Field.register_lookup(SpikeNotTrue)
        self.addCleanup(Field._unregister_lookup, SpikeNotEqual)
        self.addCleanup(Field._unregister_lookup, SpikeNotTrue)

    def test_candidate_through_inquiries(self):
        self._guard_tree()
        world = self._world()
        self.assertEqual(world['Grant'].objects.filter(user=world['people']['hop_true']).count(), 0)
        self.assertEqual(world['Grant'].objects.filter(user=world['people']['seed']).count(), 1)
        self.assertEqual(world['people']['hop_true'].probe_manager_id, world['people']['seed'].pk)
        baseline, base_walk = self._inquiries(world, candidate=False)
        candidate, cand_walk = self._inquiries(world, candidate=True)
        projected = self._project(world)
        exists = self._exists(world)
        artifact = {
            'production': _PRODUCTION,
            'pin_commit': _PIN_COMMIT,
            'vendor': connection.vendor,
            'baseline': baseline,
            'candidate': candidate,
            'walk': {'baseline': base_walk, 'candidate': cand_walk},
            'projected': projected['values'],
            'exists': exists['answers'],
            'sql': {
                'baseline': baseline.pop('_sql'),
                'candidate': candidate.pop('_sql'),
                'projected': projected['sql'],
                'filter_params': projected['filter_params'],
                'exists': exists['sql'],
            },
        }
        with open(
            '/tmp/issue365_spike_%s.json' % connection.vendor, 'w', encoding='utf-8',
        ) as handle:
            json.dump(artifact, handle, indent=2, sort_keys=True, default=str)
        self._assert_mode(baseline, candidate=False)
        self._assert_mode(candidate, candidate=True)
        self._assert_walk(base_walk, candidate=False)
        self._assert_walk(cand_walk, candidate=True)
        self.assertEqual(projected['values'], _CLASSIFY)
        self._assert_classify_sql(projected)
        for name, marks in _CANDIDATE.items():
            for label, mark in marks.items():
                for inquiry in _INQUIRIES:
                    got = candidate[name][label][inquiry]
                    want = 'hold' if mark == 'true' else 'fail'
                    self.assertEqual(got, want, '%s %s %s' % (name, label, inquiry))
                # Seed coverage of a direct grantee. Not a recursive hop.
                self.assertEqual(
                    candidate[name][label]['via_seed'],
                    'hold' if mark == 'true' else 'fail',
                    '%s %s via_seed' % (name, label),
                )
        self._assert_exists(exists)

    def _guard_tree(self):
        diff = subprocess.check_output(
            ['git', 'diff', '--stat', _PRODUCTION, '--', 'trusts'],
            cwd=_ROOT, text=True,
        )
        self.assertEqual(diff, '')
        for path in _PINS:
            pin_diff = subprocess.check_output(
                ['git', 'diff', '--stat', _PIN_COMMIT, '--', path],
                cwd=_ROOT, text=True,
            )
            self.assertEqual(pin_diff, '')

    def _assert_mode(self, found, *, candidate):
        for name, labels in _SUBJECTS.items():
            if candidate:
                holds = {
                    label for label, mark in _CANDIDATE[name].items()
                    if mark == 'true'
                }
            else:
                holds = _BASELINE_HOLD[name]
            for label in labels:
                row = found[name][label]
                for inquiry in _INQUIRIES:
                    want = 'hold' if label in holds else 'fail'
                    self.assertEqual(
                        row[inquiry], want, '%s %s %s candidate=%s' % (
                            name, label, inquiry, candidate,
                        ),
                    )

    def _assert_walk(self, walk, *, candidate):
        expect = _WALK_EXPECT[candidate]
        for name, labels in expect.items():
            for label, (direct, hopped) in labels.items():
                row = walk[name][label]
                for inquiry in _INQUIRIES:
                    self.assertEqual(
                        row['direct'][inquiry], direct,
                        'direct %s %s %s' % (name, label, inquiry),
                    )
                    self.assertEqual(
                        row['via'][inquiry], hopped,
                        'via %s %s %s' % (name, label, inquiry),
                    )
                if label != 'seed' and hopped == 'hold':
                    sql = walk['_sql']['%s-%s-via' % ('c' if candidate else 'b', name)]
                    blob = ' '.join(item['sql'] for item in sql)
                    self.assertIn('RECURSIVE', blob.upper())

    def _assert_classify_sql(self, projected):
        for name, payload in projected['filter_params'].items():
            sql = payload['sql'].upper()
            self.assertNotIn('THEN NULL WHEN', sql)
            if name == 'ne-lit':
                self.assertIn('<>', payload['sql'])
                self.assertIn('east', payload['params'])
                self.assertGreaterEqual(projected['sql'][name]['params'].count('east'), 2)
                self.assertIn('LEFT OUTER JOIN', projected['sql'][name]['sql'].upper())
            if name == 'ne-rhs':
                self.assertIn('<>', payload['sql'])
            classify = projected['sql'][name]['sql'].upper()
            self.assertIn('WHEN NOT', classify)
            self.assertIn('ELSE NULL', classify)
            self.assertNotIn('THEN NULL WHEN', classify)

    def _inquiries(self, world, *, candidate):
        patch = _WriterPatch() if candidate else _nullctx()
        found = {name: {} for name in _SUBJECTS}
        walk = {name: {} for name in _WALK_EXPECT[True]}
        sqls = {}
        specs = _expressions()
        with patch:
            for name, expr in specs:
                for hop in (False, True):
                    handle = compiler(
                        path='tests.core.issue365.spike.%s.%s.%s' % (
                            'c' if candidate else 'b', name, 'via' if hop else 'direct',
                        ),
                    )
                    try:
                        handle.set_user_condition('probe', expr)
                        kwargs = {'via': ('user__probe_manager', 4)} if hop else {}
                        handle.register(
                            trust=world['Grant'], user='user',
                            permission='permission', content='sheet', **kwargs,
                        )
                    except Exception as exc:
                        token = 'unsupported:%s' % type(exc).__name__
                        for label in _SUBJECTS[name]:
                            found[name].setdefault(label, {})[
                                'via_seed' if hop else 'direct'
                            ] = token
                        continue
                    self._fill(
                        world, handle, name, hop, found, walk, sqls, candidate,
                    )
        found['_sql'] = sqls
        walk['_sql'] = sqls
        return found, walk

    def _fill(self, world, handle, name, hop, found, walk, sqls, candidate):
        code = world['code']
        perm = world['perm']
        sheet = world['sheet']
        people = world['people']
        with _listed(handle):
            try:
                with CaptureQueriesContext(connection) as captured:
                    reached = set(
                        sheet.get_permitted_users(perm).values_list('pk', flat=True)
                    )
                reverse_error = None
                sqls['%s-%s-%s' % (
                    'c' if candidate else 'b', name, 'via' if hop else 'direct',
                )] = _snippets(captured.captured_queries)
            except Exception as exc:
                reached = set()
                reverse_error = 'error:%s' % type(exc).__name__
            for label in _SUBJECTS[name]:
                self._record(
                    world, found[name].setdefault(label, {}), label,
                    reached, reverse_error, hop, seed_key=True,
                )
            if name in walk:
                side = 'via' if hop else 'direct'
                for label in _WALK:
                    bucket = walk[name].setdefault(label, {})
                    bucket[side] = self._record(
                        world, {}, label, reached, reverse_error, False, seed_key=False,
                    )

    def _record(self, world, slot, label, reached, reverse_error, hop, *, seed_key):
        user = world['people'][label]
        code = world['code']
        sheet = world['sheet']
        try:
            has = _yn(user.has_perm(code, sheet))
        except Exception as exc:
            has = 'error:%s' % type(exc).__name__
        try:
            permitted = _yn(
                sheet.pk in set(
                    world['Sheet'].objects.permitted(code, user).values_list('pk', flat=True)
                )
            )
        except Exception as exc:
            permitted = 'error:%s' % type(exc).__name__
        if reverse_error:
            reverse = reverse_error
        else:
            reverse = _yn(user.pk in reached)
        recorded = {
            'has_perm': has,
            'permitted': permitted,
            'get_permitted_users': reverse,
        }
        if seed_key and hop:
            slot['via_seed'] = reverse
            return recorded
        slot.update(recorded)
        return recorded

    def _project(self, world):
        User = world['User']
        people = world['people']
        predicates = _predicate_q()
        ids = [user.pk for user in people.values()]
        filter_params = {}
        compiled = {}
        values = {name: {} for name in predicates}
        executed = []
        for name, q in predicates.items():
            sql, params = User.objects.filter(q).query.sql_with_params()
            filter_params[name] = {
                'sql': ' '.join(sql.split()),
                'params': _freeze(params),
            }
            alone = User.objects.filter(pk__in=ids).annotate(
                pred=ClassifyPredicate(q),
            )
            text, text_params = alone.query.sql_with_params()
            compiled[name] = {
                'sql': ' '.join(text.split())[:2000],
                'params': _freeze(text_params),
            }
            with CaptureQueriesContext(connection) as captured:
                rows = dict(alone.values_list('pk', 'pred'))
            executed.extend(_snippets(captured.captured_queries))
            for label, user in people.items():
                if label not in _CLASSIFY[name]:
                    continue
                if user.pk not in rows:
                    values[name][label] = 'dropped'
                else:
                    values[name][label] = _mark(rows[user.pk])
        return {
            'values': values,
            'sql': compiled,
            'filter_params': filter_params,
            'executed': executed,
        }

    def _world(self):
        from django.db import models

        User = get_user_model()

        class Unit(models.Model):
            note = models.CharField(max_length=20, null=True)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365s_unit'

        class Dept(models.Model):
            region = models.CharField(max_length=20, null=True)
            unit = models.ForeignKey(
                Unit, null=True, related_name='depts', on_delete=models.CASCADE,
            )

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365s_dept'

        from trusts.models import AuthorizedQuerySet, PermittedQuerySetMixin, PermittedUsersMixin

        class SheetQuery(PermittedQuerySetMixin, AuthorizedQuerySet):
            pass

        class Sheet(PermittedUsersMixin, models.Model):
            title = models.CharField(max_length=20)
            objects = models.Manager.from_queryset(SheetQuery)()

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365s_sheet'

        class Grant(models.Model):
            user = models.ForeignKey(User, related_name='+', on_delete=models.CASCADE)
            permission = models.ForeignKey(
                Permission, related_name='+', on_delete=models.CASCADE,
            )
            sheet = models.ForeignKey(Sheet, on_delete=models.CASCADE)

            class Meta:
                app_label = 'trusts_tests'
                db_table = 'p365s_grant'

        cm = _tables(Unit, Dept, Sheet, Grant)
        cm.__enter__()
        self.addCleanup(lambda: cm.__exit__(None, None, None))
        for name, field in (
            ('probe_east', models.CharField(max_length=20, null=True)),
            ('probe_dept', models.ForeignKey(
                Dept, null=True, blank=True, related_name='+',
                on_delete=models.DO_NOTHING, db_constraint=False, db_index=False,
            )),
            ('probe_manager', models.ForeignKey(
                'self', null=True, blank=True, related_name='spike_reports',
                on_delete=models.DO_NOTHING, db_constraint=False, db_index=False,
            )),
            ('is_banned', models.BooleanField(null=True)),
            ('is_owner', models.BooleanField(null=True)),
        ):
            _add_column(self, User, name, field)
        blank = Unit.objects.create(note=None)
        no_region = Dept.objects.create(region=None, unit=None)
        east = Dept.objects.create(region='east', unit=blank)
        west = Dept.objects.create(region='west', unit=blank)
        perm = _permission(Sheet, 'change_probe365_spike')
        sheet = Sheet.objects.create(title='spike')
        people = {}

        def person(label, dept, owner=False, banned=None, manager=None, grant=True):
            user = User.objects.create_user('p365s-%s' % label, password='x')
            user.probe_east = 'east'
            user.probe_dept = dept
            user.is_owner = owner
            user.is_banned = banned
            user.probe_manager = manager
            user.save()
            if grant:
                Grant.objects.create(user=user, permission=perm, sheet=sheet)
            people[label] = user
            return user

        person('miss', None)
        person('miss_own', None, owner=True)
        person('nullreg', no_region)
        person('west', west)
        person('east', east)
        person('ban_true', None, banned=True)
        person('ban_false', None, banned=False)
        seed = person('seed', west, owner=True, banned=False)
        person('hop_true', west, owner=True, banned=False, manager=seed, grant=False)
        person('hop_unknown', None, owner=False, banned=None, manager=seed, grant=False)
        person('hop_east', east, owner=False, banned=True, manager=seed, grant=False)
        person('unlinked', west, owner=True, banned=False, grant=False)
        return {
            'User': User,
            'Dept': Dept,
            'Unit': Unit,
            'Sheet': Sheet,
            'Grant': Grant,
            'people': people,
            'perm': perm,
            'code': 'trusts_tests.change_probe365_spike',
            'sheet': sheet,
        }

    def _exists(self, world):
        answers = {}
        sql = {}
        specs = (
            ('exists-dept', lambda user: exists(user.probe_dept)),
            ('not-exists-dept', lambda user: ~exists(user.probe_dept)),
            ('leaf-none', lambda user: user.probe_dept.region == None),  # noqa: E711
            ('exists-and-leaf', lambda user: (
                exists(user.probe_dept) & (user.probe_dept.region == None)  # noqa: E711
            )),
            ('exists-unit', lambda user: exists(user.probe_dept.unit)),
            ('dept-ne-none', lambda user: user.probe_dept != None),  # noqa: E711
            ('unit-ne-none', lambda user: user.probe_dept.unit != None),  # noqa: E711
            ('ne-none-and-leaf', lambda user: (
                (user.probe_dept != None) & (user.probe_dept.region == None)  # noqa: E711
            )),
        )
        labels = ('miss', 'nullreg', 'east', 'hop_unknown', 'hop_true', 'seed')
        with _ExistsPatch(world):
            for bad, expr in (
                ('scalar', lambda user: exists(user.probe_east)),
                ('collection', lambda user: exists(user.groups)),
            ):
                handle = compiler(path='tests.core.issue365.exists.%s' % bad)
                try:
                    handle.set_user_condition('probe', expr)
                    answers[bad] = {'unexpected': 'accepted'}
                except Exception as exc:
                    answers[bad] = {'unsupported': _one(exc)}
            for name, expr in specs:
                for hop in (False, True):
                    handle = compiler(
                        path='tests.core.issue365.exists.%s.%s' % (
                            name, 'via' if hop else 'direct',
                        ),
                    )
                    key = '%s-%s' % (name, 'via' if hop else 'direct')
                    try:
                        handle.set_user_condition('probe', expr)
                        kwargs = {'via': ('user__probe_manager', 4)} if hop else {}
                        handle.register(
                            trust=world['Grant'], user='user',
                            permission='permission', content='sheet', **kwargs,
                        )
                    except Exception as exc:
                        answers[key] = {'unsupported': _one(exc)}
                        continue
                    answers[key], sql[key] = self._exists_fill(world, handle, labels)
        return {'answers': answers, 'sql': sql}

    def _exists_fill(self, world, handle, labels):
        found = {}
        with _listed(handle):
            with CaptureQueriesContext(connection) as captured:
                try:
                    reached = set(
                        world['sheet'].get_permitted_users(
                            world['perm'],
                        ).values_list('pk', flat=True)
                    )
                    reverse_error = None
                except Exception as exc:
                    reached = set()
                    reverse_error = 'error:%s' % type(exc).__name__
            for label in labels:
                user = world['people'][label]
                try:
                    has = _yn(user.has_perm(world['code'], world['sheet']))
                except Exception as exc:
                    has = 'error:%s' % type(exc).__name__
                try:
                    permitted = _yn(
                        world['sheet'].pk in set(
                            world['Sheet'].objects.permitted(
                                world['code'], user,
                            ).values_list('pk', flat=True)
                        )
                    )
                except Exception as exc:
                    permitted = 'error:%s' % type(exc).__name__
                reverse = reverse_error or _yn(user.pk in reached)
                found[label] = {
                    'has_perm': has,
                    'permitted': permitted,
                    'get_permitted_users': reverse,
                }
        return found, _snippets(captured.captured_queries)

    def _assert_exists(self, exists):
        # direct grantees: miss, nullreg, east. Three inquiries agree.
        table = {
            'exists-dept': {'miss': 'fail', 'nullreg': 'hold', 'east': 'hold'},
            'not-exists-dept': {'miss': 'hold', 'nullreg': 'fail', 'east': 'fail'},
            'leaf-none': {'miss': 'hold', 'nullreg': 'hold', 'east': 'fail'},
            'exists-and-leaf': {'miss': 'fail', 'nullreg': 'hold', 'east': 'fail'},
            'exists-unit': {'miss': 'fail', 'nullreg': 'fail', 'east': 'hold'},
            'dept-ne-none': {'miss': 'fail', 'nullreg': 'hold', 'east': 'hold'},
            'unit-ne-none': {'miss': 'fail', 'nullreg': 'fail', 'east': 'hold'},
            'ne-none-and-leaf': {'miss': 'fail', 'nullreg': 'hold', 'east': 'fail'},
        }
        for name, labels in table.items():
            got = exists['answers']['%s-direct' % name]
            self.assertNotIn('unsupported', got, name)
            for label, want in labels.items():
                for inquiry in _INQUIRIES:
                    self.assertEqual(
                        got[label][inquiry], want,
                        '%s %s %s' % (name, label, inquiry),
                    )
        # Same rows through the walk. seed has a department and a unit, so
        # Exists(dept) and Exists(unit) reach hop_true and not hop_unknown.
        via = {
            'exists-dept': {'seed': 'hold', 'hop_true': 'hold', 'hop_unknown': 'fail'},
            'not-exists-dept': {
                'seed': 'fail', 'hop_true': 'fail', 'hop_unknown': 'fail',
            },
            'exists-unit': {'seed': 'hold', 'hop_true': 'hold', 'hop_unknown': 'fail'},
        }
        for name, labels in via.items():
            got = exists['answers']['%s-via' % name]
            for label, want in labels.items():
                for inquiry in _INQUIRIES:
                    self.assertEqual(
                        got[label][inquiry], want,
                        'via %s %s %s' % (name, label, inquiry),
                    )
        direct_hop = exists['answers']['exists-dept-direct']['hop_true']
        for inquiry in _INQUIRIES:
            self.assertEqual(direct_hop[inquiry], 'fail')
        for bad in ('scalar', 'collection'):
            self.assertIn('unsupported', exists['answers'][bad])


class _nullctx(object):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def _snippets(queries):
    kept = []
    for item in queries:
        sql = ' '.join(item.get('sql', '').split())
        if 'p365s_' not in sql and 'auth_user' not in sql:
            continue
        kept.append({
            'sql': sql[:2500],
            'params': _params(item),
        })
    return kept


def _params(item):
    if 'params' in item:
        return repr(item['params'])[:500]
    return None
