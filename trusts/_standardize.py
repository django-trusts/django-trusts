"""Private rewrite of a finished policy queryset.

Policy code builds ordinary querysets with ``filter``, ``Q``, ``Value``,
``Exists``, and ``OuterRef``. ``standardize`` is the only pass that
folds repeated values onto one ``trusts_bind`` row. The flag in this
module is private: it is not a Django setting and not a public contract.
Off, ``standardize`` returns the queryset unchanged.

On, values that occur more than once (lookup constants, ``Value`` nodes,
and ``along=`` depth caps, including those inside ``EXISTS`` and other
subqueries) become columns of one outer row. That queryset is what runs
and what the lockfile compiles.
"""

import copy
import re
from contextlib import contextmanager

from django.db.models import IntegerField, QuerySet
from django.db.models.expressions import Expression, Value
from django.db.models.lookups import Lookup
from django.db.models.query_utils import Q
from django.db.models.sql.query import Query
from django.db.models.sql.where import WhereNode

from trusts.core import TrustsConfigurationError


BIND_ALIAS = 'trusts_bind'

_ENABLED = False
_SKIP = object()
_DEPTH_CAP = re.compile(r'["`]depth["`]\s*<\s*%s')
_INTEGER = IntegerField()


def enabled():
    return _ENABLED


@contextmanager
def scope(active=True):
    """Temporarily set the private flag. Not a public setting."""
    global _ENABLED
    previous = _ENABLED
    _ENABLED = bool(active)
    try:
        yield
    finally:
        _ENABLED = previous


def standardize(qs, *also):
    """Return the queryset to execute and to record.

    Extra trees (a grant ``Q`` that is not yet on ``qs``) are rewritten
    against the same row and returned after the queryset. Off, every
    argument is returned unchanged.
    """
    if not _ENABLED:
        return (qs, *also) if also else qs
    query = getattr(qs, 'query', None)
    if isinstance(query, Query) and BIND_ALIAS in query.alias_map:
        return (qs, *also) if also else qs
    prepared, extras = _prepare(qs, also)
    connection = _connection_for(prepared)
    hits = []
    _collect(_query_of(prepared), hits, connection)
    for extra in extras:
        _collect(extra, hits, connection)
    groups = _repeated(hits)
    if not groups:
        return (qs, *also) if also else qs
    columns = []
    names = set()
    for group in groups:
        column = _column_for(group, names)
        columns.append(column)
        ref = BindRef(BIND_ALIAS, column.sql_name, column.output_field)
        for hit in group:
            hit.apply(ref)
    _install(_query_of(prepared), columns)
    if also:
        return (prepared, *extras)
    return prepared


def execute_exists(queryset):
    """``queryset.exists()`` on the standardized statement."""
    if not _ENABLED:
        return queryset.exists()
    holder = _QueryHolder(queryset.query.exists())
    standardize(holder)
    compiler = holder.query.get_compiler(using=queryset.db)
    return compiler.has_results()


class _QueryHolder(object):
    def __init__(self, query):
        self.query = query


class _Hit(object):
    __slots__ = ('token', 'kind', 'label', 'value', 'output_field', 'apply')

    def __init__(self, value, kind, label, output_field, apply):
        self.token = _value_token(value)
        self.kind = kind
        self.label = label
        self.value = value
        self.output_field = output_field
        self.apply = apply


class BindColumn(object):
    __slots__ = ('kind', 'label', 'value', 'output_field', 'sql_name')

    def __init__(self, kind, label, value, output_field, sql_name):
        self.kind = kind
        self.label = label
        self.value = value
        self.output_field = output_field
        self.sql_name = sql_name


class BindRef(Expression):
    """One column of the outer bind row. It adds no placeholder."""

    def __init__(self, alias, column, output_field):
        super().__init__(output_field=output_field)
        self.alias = alias
        self.column = column

    def as_sql(self, compiler, connection):
        quote = compiler.quote_name
        return '%s.%s' % (quote(self.alias), quote(self.column)), ()

    def resolve_expression(
        self, query=None, allow_joins=True, reuse=None,
        summarize=False, for_save=False,
    ):
        return copy.copy(self)

    def relabeled_clone(self, change_map):
        alias = change_map.get(self.alias, self.alias)
        if alias == self.alias:
            return self
        clone = copy.copy(self)
        clone.alias = alias
        return clone

    def get_source_expressions(self):
        return []

    def set_source_expressions(self, exprs):
        if exprs:
            raise TypeError('BindRef has no source expressions.')


class BindTable(object):
    """``CROSS JOIN (SELECT %s AS col, ...) trusts_bind``.

    ``join_type`` stays unset so ``Query.promote_joins`` treats the row
    like a base table and leaves it alone. ``as_sql`` still emits
    ``CROSS JOIN``. The row is installed after the real base table.
    """

    join_type = None
    parent_alias = None
    filtered_relation = None
    nullable = False

    def __init__(self, columns):
        self.table_name = BIND_ALIAS
        self.table_alias = BIND_ALIAS
        self.columns = tuple(columns)
        self._symbols = []

    def as_sql(self, compiler, connection):
        quote = compiler.quote_name
        parts = []
        params = []
        self._symbols = []
        for column in self.columns:
            placeholder, value = _placeholder(column, compiler, connection)
            parts.append('%s AS %s' % (placeholder, quote(column.sql_name)))
            if value:
                params.extend(value)
                self._symbols.append(column)
        sql = 'CROSS JOIN (SELECT %s) %s' % (
            ', '.join(parts), quote(self.table_alias),
        )
        return sql, tuple(params)

    def next_column(self):
        if not self._symbols:
            raise IndexError('bind table has no placeholder left to classify')
        return self._symbols.pop(0)

    def relabeled_clone(self, change_map):
        clone = copy.copy(self)
        clone.table_alias = change_map.get(self.table_alias, self.table_alias)
        clone._symbols = []
        return clone

    def promote(self):
        return self

    def demote(self):
        return self


class _StandardWalk(Expression):
    """Retarget one ``along=`` depth cap at the bind row.

    The walk SQL is produced by the inner expression. The cap is the
    ``depth < %s`` placeholder in that SQL, not a node in the tree.
    """

    filterable = True
    subquery = True

    def __init__(self, inner, ref):
        super().__init__(output_field=inner.output_field)
        self.inner = inner
        self.ref = ref

    def get_source_expressions(self):
        return [self.inner, self.ref]

    def set_source_expressions(self, exprs):
        self.inner, self.ref = exprs

    def resolve_expression(
        self, query=None, allow_joins=True, reuse=None,
        summarize=False, for_save=False,
    ):
        clone = copy.copy(self)
        clone.inner = self.inner.resolve_expression(
            query, allow_joins=allow_joins, reuse=reuse,
            summarize=summarize, for_save=for_save,
        )
        clone.ref = self.ref.resolve_expression(
            query, allow_joins=allow_joins, reuse=reuse,
            summarize=summarize, for_save=for_save,
        )
        return clone

    def relabeled_clone(self, change_map):
        clone = copy.copy(self)
        clone.inner = self.inner.relabeled_clone(change_map)
        clone.ref = self.ref.relabeled_clone(change_map)
        return clone

    def as_sql(self, compiler, connection):
        sql, params = compiler.compile(self.inner)
        ref_sql, ref_params = compiler.compile(self.ref)
        if ref_params:
            raise TrustsConfigurationError(
                'standardize bind reference emitted a placeholder.'
            )
        return _retarget_depth(sql, params, ref_sql)


def _retarget_depth(sql, params, ref_sql):
    matches = list(_DEPTH_CAP.finditer(sql))
    if len(matches) != 1:
        raise TrustsConfigurationError(
            'standardize could not retarget the along depth cap.'
        )
    match = matches[0]
    index = sql[:match.start()].count('%s')
    params = list(params)
    if index >= len(params):
        raise TrustsConfigurationError(
            'standardize could not retarget the along depth cap.'
        )
    del params[index]
    head = match.group(0)[:-2].rstrip()
    sql = '%s%s %s%s' % (sql[:match.start()], head, ref_sql, sql[match.end():])
    return sql, tuple(params)


def _prepare(qs, also):
    if isinstance(qs, QuerySet):
        prepared = qs._chain()
        prepared.query = _own_query(prepared.query)
    elif isinstance(getattr(qs, 'query', None), Query):
        prepared = qs
        prepared.query = _own_query(qs.query)
    else:
        raise TrustsConfigurationError(
            'standardize expected a queryset, not %r.' % (qs,)
        )
    return prepared, tuple(_own_expr(item) for item in also)


def _query_of(qs):
    return qs.query


def _own_query(query):
    clone = query.clone()
    clone.where = _own_expr(query.where)
    clone.annotations = {
        key: _own_expr(value) for key, value in query.annotations.items()
    }
    if query.combined_queries:
        clone.combined_queries = tuple(
            _own_query(part) for part in query.combined_queries
        )
    return clone


def _own_expr(expr):
    if expr is None or isinstance(expr, Query):
        return _own_query(expr) if isinstance(expr, Query) else expr
    if isinstance(expr, (list, tuple)):
        return type(expr)(_own_expr(item) for item in expr)
    if isinstance(expr, Lookup):
        clone = copy.copy(expr)
        clone.lhs = _own_expr(expr.lhs)
        if not expr.rhs_is_direct_value():
            clone.rhs = _own_expr(expr.rhs)
        return clone
    if isinstance(expr, (WhereNode, Q)):
        clone = expr.create(connector=expr.connector, negated=expr.negated)
        clone.children = [_own_expr(child) for child in expr.children]
        if hasattr(expr, 'resolved'):
            clone.resolved = expr.resolved
        return clone
    if not hasattr(expr, 'get_source_expressions'):
        return expr
    clone = expr.copy() if hasattr(expr, 'copy') else copy.copy(expr)
    sources = expr.get_source_expressions()
    if sources:
        clone.set_source_expressions([
            None if source is None else _own_expr(source)
            for source in sources
        ])
    return clone


def _collect(node, hits, connection):
    if node is None or isinstance(node, (BindRef, str, bytes, int, float, bool)):
        return
    if isinstance(node, _StandardWalk):
        _collect(node.inner, hits, connection)
        return
    if isinstance(node, Query):
        _collect(node.where, hits, connection)
        for key, annotation in node.annotations.items():
            if isinstance(annotation, Value):
                _note_value(
                    hits, annotation,
                    lambda ref, store=node.annotations, key=key: store.__setitem__(key, ref),
                )
            else:
                _collect(annotation, hits, connection)
        for part in node.combined_queries or ():
            _collect(part, hits, connection)
        return
    if isinstance(node, Lookup):
        if _is_along(node.lhs):
            lhs = node.lhs
            _note_along(
                hits, lhs,
                lambda ref, node=node, lhs=lhs: setattr(
                    node, 'lhs', _StandardWalk(lhs, ref),
                ),
            )
            _collect_sources(lhs, hits, connection)
        else:
            _collect(node.lhs, hits, connection)
        if getattr(node, 'lookup_name', None) == 'isnull':
            return
        if node.rhs_is_direct_value():
            plain = _plain_value(node.rhs)
            if plain is _SKIP or not _rhs_is_emitted(node, plain, connection):
                return
            kind, label = _describe_lookup(node, plain)
            hits.append(_Hit(
                plain, kind, label, _lookup_output(node),
                lambda ref, node=node: setattr(node, 'rhs', ref),
            ))
            return
        if isinstance(node.rhs, Value):
            _note_value(
                hits, node.rhs,
                lambda ref, node=node: setattr(node, 'rhs', ref),
            )
            return
        _collect(node.rhs, hits, connection)
        return
    if isinstance(node, (WhereNode, Q)):
        for index, child in enumerate(node.children):
            if _is_along(child):
                _note_along(
                    hits, child,
                    lambda ref, parent=node, index=index, child=child: (
                        parent.children.__setitem__(index, _StandardWalk(child, ref))
                    ),
                )
                _collect_sources(child, hits, connection)
            elif _unresolved_lookup(child):
                _note_unresolved(hits, node, index, child)
            else:
                _collect(child, hits, connection)
        return
    if isinstance(node, Value):
        return
    _collect_sources(node, hits, connection)


def _collect_sources(node, hits, connection):
    if not hasattr(node, 'get_source_expressions'):
        return
    for index, source in enumerate(node.get_source_expressions()):
        if isinstance(source, Value):
            _note_value(
                hits, source,
                lambda ref, node=node, index=index: _replace_source(node, index, ref),
            )
        elif _is_along(source):
            _note_along(
                hits, source,
                lambda ref, node=node, index=index, source=source: _replace_source(
                    node, index, _StandardWalk(source, ref),
                ),
            )
            _collect_sources(source, hits, connection)
        else:
            _collect(source, hits, connection)


def _rhs_is_emitted(lookup, value, connection):
    """False when Exact drops a bool because the left side is already a predicate.

    ``Exists`` and other conditional expressions are stored as
    ``Exact(expr, True)``. Django emits the expression alone, so that
    ``True`` is not a placeholder and must stay put.
    """
    if not isinstance(value, bool):
        return True
    if getattr(lookup, 'lookup_name', None) != 'exact':
        return True
    if not getattr(lookup.lhs, 'conditional', False):
        return True
    return not connection.ops.conditional_expression_supported_in_where_clause(
        lookup.lhs,
    )


def _connection_for(obj):
    from django.db import connections

    alias = getattr(obj, 'db', None) or 'default'
    return connections[alias]


def _note_value(hits, node, apply):
    value = node.value
    if isinstance(value, bool):
        label = 'literal'
    elif value == 1:
        label = 'exists marker'
    else:
        label = 'literal'
    hits.append(_Hit(value, 'const', label, node.output_field, apply))


def _note_along(hits, node, apply):
    bound = _along_bound(node)
    hits.append(_Hit(bound, 'const', 'along bound', _INTEGER, apply))


def _replace_source(node, index, replacement):
    sources = list(node.get_source_expressions())
    sources[index] = replacement
    node.set_source_expressions(sources)


def _is_along(node):
    from trusts.core import (
        GrantReach, _AnchorInInverseReach, _KeyedReach, _PrefixInForwardWalk,
    )

    return isinstance(node, (
        GrantReach, _PrefixInForwardWalk, _KeyedReach, _AnchorInInverseReach,
    ))


def _along_bound(node):
    from trusts.core import _KeyedReach

    if isinstance(node, _KeyedReach):
        return node.walk.bound
    return node.record.along.bound


def _repeated(hits):
    order = []
    buckets = {}
    for hit in hits:
        bucket = buckets.get(hit.token)
        if bucket is None:
            bucket = []
            buckets[hit.token] = bucket
            order.append(bucket)
        bucket.append(hit)
    return [bucket for bucket in order if len(bucket) > 1]


def _column_for(group, names):
    chosen = group[0]
    for hit in group:
        if hit.kind == 'bind':
            chosen = hit
            break
    output = chosen.output_field
    if output is None:
        for hit in group:
            if hit.output_field is not None:
                output = hit.output_field
                break
    return BindColumn(
        chosen.kind, chosen.label, chosen.value, output,
        _unique_name(_column_base(chosen.kind, chosen.label), names),
    )


def _install(query, columns):
    if not query.alias_map and getattr(query, 'model', None) is not None:
        query.get_initial_alias()
    query.alias_map[BIND_ALIAS] = BindTable(columns)
    query.alias_refcount[BIND_ALIAS] = 1
    aliases = query.table_map.setdefault(BIND_ALIAS, [])
    if BIND_ALIAS not in aliases:
        aliases.append(BIND_ALIAS)


def _placeholder(column, compiler, connection):
    del compiler
    value = column.value
    field = column.output_field
    if field is not None:
        value = field.get_db_prep_value(value, connection=connection)
    if value is None:
        return 'NULL', ()
    return '%s', (value,)


def _unresolved_lookup(child):
    return (
        isinstance(child, tuple)
        and len(child) == 2
        and isinstance(child[0], str)
        and not child[0].endswith('__isnull')
    )


def _note_unresolved(hits, parent, index, child):
    key, value = child
    plain = _plain_value(value)
    if plain is _SKIP:
        return
    hits.append(_Hit(
        plain, 'const', key.rsplit('__', 1)[-1] or 'literal', None,
        lambda ref, parent=parent, index=index, key=key: parent.children.__setitem__(
            index, (key, ref),
        ),
    ))


def _plain_value(value):
    if isinstance(value, (list, tuple, set, dict, QuerySet)):
        return _SKIP
    if hasattr(value, 'resolve_expression') or hasattr(value, 'as_sql'):
        return _SKIP
    if hasattr(value, '_meta') and hasattr(value, 'pk'):
        return value.pk
    return value


def _lookup_output(lookup):
    lhs = lookup.lhs
    field = getattr(lhs, 'output_field', None)
    if field is not None:
        return field
    return getattr(lhs, 'target', None)


def _describe_lookup(lookup, value):
    from trusts.policy_lock import _bind_name, _const_hint, _ctx

    record = getattr(_ctx, 'record', None)
    if record is not None:
        bind = _bind_name(lookup, record)
        if bind is not None:
            return 'bind', bind
    return 'const', _const_hint(lookup, value)


def _value_token(value):
    if isinstance(value, bool):
        return ('bool', value)
    if isinstance(value, int):
        return ('int', value)
    if isinstance(value, str):
        return ('str', value)
    if isinstance(value, float):
        return ('float', repr(value))
    if value is None:
        return ('none', None)
    return (type(value).__name__, repr(value))


def _column_base(kind, label):
    if kind == 'bind':
        base = (label or 'value').replace('.', '_')
    else:
        base = {
            'content type app': 'app_label',
            'content type model': 'model',
            'along bound': 'along_bound',
            'content pk': 'content_pk',
            'exists marker': 'exists_marker',
            'active': 'is_active',
            'along match': 'along_match',
        }.get(label, (label or 'value').replace(' ', '_'))
    cleaned = []
    for char in base:
        cleaned.append(char if char.isalnum() or char == '_' else '_')
    name = ''.join(cleaned) or 'value'
    if name[0].isdigit():
        name = 'v_' + name
    return name


def _unique_name(base, names):
    name = base
    number = 2
    while name in names:
        name = '%s_%s' % (base, number)
        number += 1
    names.add(name)
    return name
