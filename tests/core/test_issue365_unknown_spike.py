"""Test-local feasibility spike for an unknown-preserving comparison.

Production code and the #366 behavior pins stay as they are. This does
not adopt the rule. The candidate run points ``column_q``, ``columns_q``,
and ``negate_q`` at two lookups (``<>`` and ``NOT (column = TRUE)``).
The via walker does not use those lookups. Its candidate run only drops
the ``IS NULL OR`` wrapper on a constant inequality and negates the
boolean column instead of ``column IS TRUE``.

The projection is a nullable CASE selected before filtering. ``hold`` is
the filtered inquiry. Unknown and false both fail that filter.
"""
import json
import os
import re
import subprocess

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.db import connection
from django.db.models import BooleanField, Case, F, Field, Q, Value, When
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
from trusts.plan import standards, users, via, writers


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


def _three(isnull, when_true):
    return Case(
        When(isnull, then=Value(None)),
        When(when_true, then=Value(True)),
        default=Value(False),
        output_field=BooleanField(null=True),
    )


def _mark(value):
    if value is None:
        return 'unknown'
    if value in (True, 1):
        return 'true'
    if value in (False, 0):
        return 'false'
    return 'other:%r' % (value,)


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
        baseline = self._inquiries(world, candidate=False)
        candidate = self._inquiries(world, candidate=True)
        projected = self._project(world)
        artifact = {
            'production': _PRODUCTION,
            'pin_commit': _PIN_COMMIT,
            'vendor': connection.vendor,
            'baseline': baseline,
            'candidate': candidate,
            'projected': projected['values'],
            'sql': {
                'baseline': baseline.pop('_sql'),
                'candidate': candidate.pop('_sql'),
                'projected': projected['sql'],
            },
        }
        with open(
            '/tmp/issue365_spike_%s.json' % connection.vendor, 'w', encoding='utf-8',
        ) as handle:
            json.dump(artifact, handle, indent=2, sort_keys=True)
        self._assert_mode(baseline, candidate=False)
        self._assert_mode(candidate, candidate=True)
        self.assertEqual(projected['values'], _CANDIDATE)
        for name, marks in _CANDIDATE.items():
            for label, mark in marks.items():
                for inquiry in ('has_perm', 'permitted', 'get_permitted_users', 'via'):
                    got = candidate[name][label][inquiry]
                    want = 'hold' if mark == 'true' else 'fail'
                    self.assertEqual(
                        got, want,
                        '%s %s %s projected %s' % (name, label, inquiry, mark),
                    )

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
                for inquiry, got in row.items():
                    want = 'hold' if label in holds else 'fail'
                    self.assertEqual(
                        got, want, '%s %s %s candidate=%s' % (
                            name, label, inquiry, candidate,
                        ),
                    )

    def _inquiries(self, world, *, candidate):
        patch = _WriterPatch() if candidate else _nullctx()
        found = {name: {} for name in _SUBJECTS}
        sqls = {}
        specs = (
            ('ne-lit', lambda user: user.probe_dept.region != 'east'),
            ('ne-rhs', lambda user: user.probe_dept.region != user.probe_east),
            ('not-ban', lambda user: ~user.is_banned),
            ('or-own', lambda user: (
                (user.probe_dept.region == 'east') | user.is_owner
            )),
            ('rel-none', lambda user: user.probe_dept == None),  # noqa: E711
            ('leaf-none', lambda user: user.probe_dept.region == None),  # noqa: E711
        )
        with patch:
            for name, expr in specs:
                for hop in (False, True):
                    key = name
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
                            slot = found[name].setdefault(label, {})
                            slot['via' if hop else 'direct'] = token
                        continue
                    self._fill(
                        world, handle, name, hop, found, sqls, candidate,
                    )
        found['_sql'] = sqls
        return found

    def _fill(self, world, handle, name, hop, found, sqls, candidate):
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
                if hop or name in ('ne-lit', 'not-ban', 'or-own'):
                    sqls['%s-%s-%s' % (
                        'c' if candidate else 'b', name, 'via' if hop else 'direct',
                    )] = _snippets(captured.captured_queries)
            except Exception as exc:
                reached = set()
                reverse_error = 'error:%s' % type(exc).__name__
            for label in _SUBJECTS[name]:
                user = people[label]
                slot = found[name].setdefault(label, {})
                if hop:
                    if reverse_error:
                        slot['via'] = reverse_error
                    else:
                        slot['via'] = _yn(user.pk in reached)
                    continue
                try:
                    has = _yn(user.has_perm(code, sheet))
                except Exception as exc:
                    has = 'error:%s' % type(exc).__name__
                try:
                    permitted = _yn(
                        sheet.pk in set(
                            world['Sheet'].objects.permitted(
                                code, user,
                            ).values_list('pk', flat=True)
                        )
                    )
                except Exception as exc:
                    permitted = 'error:%s' % type(exc).__name__
                if reverse_error:
                    reverse = reverse_error
                else:
                    reverse = _yn(user.pk in reached)
                slot['has_perm'] = has
                slot['permitted'] = permitted
                slot['get_permitted_users'] = reverse

    def _project(self, world):
        User = world['User']
        people = world['people']
        region_missing = Q(probe_dept__region__isnull=True)
        qs = User.objects.filter(pk__in=[user.pk for user in people.values()])
        qs = qs.annotate(
            ne_lit=_three(region_missing, Q(probe_dept__region__spike_ne='east')),
            ne_rhs=_three(
                region_missing | Q(probe_east__isnull=True),
                Q(probe_dept__region__spike_ne=F('probe_east')),
            ),
            not_ban=_three(
                Q(is_banned__isnull=True),
                Q(is_banned__spike_not_true=True),
            ),
            or_own=Case(
                When(
                    Q(probe_dept__region='east') | Q(is_owner=True),
                    then=Value(True),
                ),
                When(
                    region_missing | Q(is_owner__isnull=True),
                    then=Value(None),
                ),
                default=Value(False),
                output_field=BooleanField(null=True),
            ),
            rel_none=Case(
                When(probe_dept__isnull=True, then=Value(True)),
                default=Value(False),
                output_field=BooleanField(null=True),
            ),
            leaf_none=Case(
                When(region_missing, then=Value(True)),
                default=Value(False),
                output_field=BooleanField(null=True),
            ),
        )
        columns = (
            'ne_lit', 'ne_rhs', 'not_ban', 'or_own', 'rel_none', 'leaf_none',
        )
        names = {
            'ne_lit': 'ne-lit', 'ne_rhs': 'ne-rhs', 'not_ban': 'not-ban',
            'or_own': 'or-own', 'rel_none': 'rel-none', 'leaf_none': 'leaf-none',
        }
        with CaptureQueriesContext(connection) as captured:
            rows = list(qs.values_list('pk', *columns))
        by_pk = {row[0]: row[1:] for row in rows}
        values = {name: {} for name in _SUBJECTS}
        for label, user in people.items():
            marks = by_pk[user.pk]
            for index, column in enumerate(columns):
                name = names[column]
                if label in _CANDIDATE[name]:
                    values[name][label] = _mark(marks[index])
        return {'values': values, 'sql': _snippets(captured.captured_queries)}

    def _world(self):
        from django.db import models

        User = get_user_model()

        class Dept(models.Model):
            region = models.CharField(max_length=20, null=True)

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

        cm = _tables(Dept, Sheet, Grant)
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
        no_region = Dept.objects.create(region=None)
        east = Dept.objects.create(region='east')
        west = Dept.objects.create(region='west')
        perm = _permission(Sheet, 'change_probe365_spike')
        sheet = Sheet.objects.create(title='spike')
        people = {}

        def person(label, dept, owner=False, banned=None):
            user = User.objects.create_user('p365s-%s' % label, password='x')
            user.probe_east = 'east'
            user.probe_dept = dept
            user.is_owner = owner
            user.is_banned = banned
            user.save()
            Grant.objects.create(user=user, permission=perm, sheet=sheet)
            people[label] = user

        person('miss', None)
        person('miss_own', None, owner=True)
        person('nullreg', no_region)
        person('west', west)
        person('east', east)
        person('ban_true', None, banned=True)
        person('ban_false', None, banned=False)
        return {
            'User': User,
            'Sheet': Sheet,
            'Grant': Grant,
            'people': people,
            'perm': perm,
            'code': 'trusts_tests.change_probe365_spike',
            'sheet': sheet,
        }


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
