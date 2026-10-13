"""Turn one plain policy queryset into a bound-once statement.

Policy code builds ordinary querysets (``filter``, ``Q``, ``Exists``,
``OuterRef``). ``bind_once`` is the only pass that folds inquiry values
onto one ``trusts_bind`` row. That queryset is what runs and what the
lockfile records.

``TRUSTS_SQL_BIND_ONCE`` defaults to true. Set it to false and ``bind_once``
returns the queryset unchanged, so the lockfile shows the plain SQL.
"""

import copy
import re

from django.db.models import BooleanField, Exists, IntegerField, QuerySet, Value
from django.db.models.expressions import Expression
from django.db.models.lookups import Lookup
from django.db.models.query_utils import Q
from django.db.models.sql.query import Query
from django.db.models.sql.where import WhereNode


BIND_ALIAS = 'trusts_bind'

_SKIP = object()
_INTEGER = IntegerField()
_DEPTH_CAP = re.compile(r'["`]depth["`]\s*<\s*%s')
_EXISTS_MARKER = re.compile(r'SELECT %s AS (["`])a\1')
_ELIGIBILITY = {
    'is_active': 'active',
    'is_anonymous': 'is_anonymous',
    'is_authenticated': 'is_authenticated',
}
_USER_FIELDS = frozenset((
    'user', 'user_id', 'delegate', 'delegate_id', 'sponsor', 'sponsor_id',
))
_PERMISSION_FIELDS = frozenset(('permission', 'permission_id'))


def trusts_bind_once():
    """Whether statements bind each distinct inquiry value once.

    Missing ``TRUSTS_SQL_BIND_ONCE`` means on. ``False`` leaves the queryset
    exactly as policy code built it.
    """
    from django.conf import settings

    return bool(getattr(settings, 'TRUSTS_SQL_BIND_ONCE', True))


def bind_once(queryset, *also):
    """Return the queryset to execute and to record.

    Extra trees (a grant ``Q`` that is not yet on ``queryset``) are
    rewritten against the same row and returned after the queryset.
    When the setting is off, every argument is returned unchanged.
    """
    if not trusts_bind_once():
        return (queryset, *also) if also else queryset
    query = getattr(queryset, 'query', None)
    if isinstance(query, Query) and BIND_ALIAS in getattr(query, 'alias_map', {}):
        return (queryset, *also) if also else queryset
    prepared, extras = _prepare(queryset, also)
    root = getattr(getattr(prepared, 'query', None), 'model', None)
    walk = _Walk(root, _connection_for(prepared))
    walk.visit(_query_of(prepared))
    for extra in extras:
        walk.visit(extra)
    walk.finish(_query_of(prepared))
    if also:
        return (prepared, *extras)
    return prepared


def execute_exists(queryset):
    """``EXISTS`` on the bound-once statement, or the plain one when off."""
    if not trusts_bind_once():
        return queryset.exists()
    return query_exists(bind_once(queryset))


def bound_exists_query(queryset):
    """The ``EXISTS`` query the lockfile compiles for ``queryset``."""
    if not trusts_bind_once():
        return queryset.query.exists()
    return strip_exists_marker(bind_once(queryset).query.exists())


def _prepare(queryset, also):
    if isinstance(queryset, QuerySet):
        prepared = queryset._chain()
        prepared.query = _own_query(prepared.query)
    elif isinstance(getattr(queryset, 'query', None), Query):
        prepared = queryset
        prepared.query = _own_query(queryset.query)
    else:
        from trusts.core import TrustsConfigurationError

        raise TrustsConfigurationError(
            'bind_once expected a queryset, not %r.' % (queryset,)
        )
    return prepared, tuple(_own_expr(item) for item in also)


def _query_of(queryset):
    return queryset.query


def _connection_for(queryset):
    from django.db import connections

    alias = getattr(queryset, 'db', None) or 'default'
    return connections[alias]


class _Walk(object):
    def __init__(self, root_model, connection):
        self.root_model = root_model
        self.connection = connection
        self.hits = []
        self.seen_queries = set()
        self.seen_along = set()
        self._query_stack = []
        self._along_parents = []
        self._inside_along = 0

    def finish(self, query):
        if not self.hits:
            return
        inner_parents = []
        if getattr(self.connection, 'vendor', None) == 'mysql':
            # A recursive CTE inside EXISTS cannot see a derived table
            # joined above that EXISTS. Repeat the row there, but only
            # with the columns that CTE (or that EXISTS) actually reads.
            # Everything else stays on the outer row.
            for item in self._along_parents:
                if item is not query and item not in inner_parents:
                    inner_parents.append(item)
        inner_ids = {id(item) for item in inner_parents}
        buckets = {id(query): []}
        for item in inner_parents:
            buckets[id(item)] = []
        for hit in self.hits:
            if hit.forced_along is not None and id(hit.forced_along) in inner_ids:
                buckets[id(hit.forced_along)].append(hit)
            elif hit.query is not None and id(hit.query) in inner_ids:
                buckets[id(hit.query)].append(hit)
            else:
                buckets[id(query)].append(hit)
        for target in [query] + inner_parents:
            owned = buckets[id(target)]
            if not owned:
                continue
            names = set()
            columns = []
            for group in _group(owned):
                column = _column_for(group, names)
                columns.append(column)
                ref = BindRef(BIND_ALIAS, column.sql_name, column.output_field)
                for hit in group:
                    hit.apply(ref)
            _install(target, columns)

    def visit(self, node):
        if node is None or isinstance(node, (
            BindRef, BoundBool, SqlInt, str, bytes, int, float, bool,
        )):
            return
        if isinstance(node, _AlongOnce):
            self.visit(node.inner)
            return
        if isinstance(node, Query):
            if id(node) in self.seen_queries:
                return
            self.seen_queries.add(id(node))
            self._query_stack.append(node)
            try:
                self.visit(node.where)
                for key, annotation in list(node.annotations.items()):
                    if (
                        key == 'a'
                        and isinstance(annotation, Value)
                        and annotation.value == 1
                        and not isinstance(annotation.value, bool)
                    ):
                        node.annotations[key] = SqlInt(1)
                        node._annotation_select_cache = None
                        continue
                    self.visit(annotation)
                for part in node.combined_queries or ():
                    self.visit(part)
            finally:
                self._query_stack.pop()
            return
        if isinstance(node, Lookup):
            self._visit_lookup(node)
            return
        if isinstance(node, (WhereNode, Q)):
            for index, child in enumerate(list(node.children)):
                if _is_along(child):
                    self._note_along(child, _child_apply(node, index, child))
                elif _unresolved_pair(child):
                    self._note_unresolved(node, index, child)
                else:
                    self.visit(child)
            return
        self._visit_sources(node)

    def _visit_lookup(self, node):
        if _is_along(node.lhs):
            self._note_along(node.lhs, _lhs_apply(node, node.lhs))
            if not node.rhs_is_direct_value():
                self.visit(node.rhs)
            return
        self.visit(node.lhs)
        if getattr(node, 'lookup_name', None) == 'isnull':
            return
        if node.rhs_is_direct_value():
            self._note_lookup_value(node, node.rhs)
            return
        if isinstance(node.rhs, Value):
            self._note_lookup_value(node, node.rhs.value)
            return
        self.visit(node.rhs)

    def _note_lookup_value(self, node, raw):
        plain = _plain_value(raw)
        if plain is _SKIP or not _rhs_is_emitted(node, plain, self.connection):
            return
        kind, label = _classify_lookup(node, plain, self.root_model)
        if kind == 'eligibility':
            node.rhs = BoundBool(plain, label)
            return
        if kind != 'bind' and kind != 'const':
            return
        output = _lookup_output(node)
        query, forced_along = self._hit_scope()
        self.hits.append(_Hit(
            plain, kind, label, output,
            lambda ref, lookup=node: setattr(lookup, 'rhs', ref),
            query, forced_along,
        ))

    def _note_unresolved(self, parent, index, child):
        key, raw = child
        if key.endswith('__isnull') or key.endswith('__in'):
            return
        plain = _plain_value(raw)
        if plain is _SKIP:
            self.visit(raw)
            return
        kind, label = _classify_key(key, plain, self.root_model)
        if kind == 'eligibility':
            parent.children[index] = (key, BoundBool(plain, label))
            return
        if kind != 'bind' and kind != 'const':
            return
        query, forced_along = self._hit_scope()
        self.hits.append(_Hit(
            plain, kind, label, None,
            lambda ref, parent=parent, index=index, key=key: (
                parent.children.__setitem__(index, (key, ref))
            ),
            query, forced_along,
        ))

    def _note_along(self, node, apply):
        if id(node) in self.seen_along:
            return
        self.seen_along.add(id(node))
        if self._inside_along == 0 and self._query_stack:
            parent = self._query_stack[-1]
            if parent not in self._along_parents:
                self._along_parents.append(parent)
        bound = _along_bound(node)
        parent = self._query_stack[-1] if self._query_stack else None
        self.hits.append(_Hit(
            bound, 'const', 'along bound', _INTEGER, apply, parent, parent,
        ))
        self._inside_along += 1
        try:
            self._visit_sources(node)
        finally:
            self._inside_along -= 1

    def _visit_sources(self, node):
        if not hasattr(node, 'get_source_expressions'):
            return
        for source in node.get_source_expressions():
            self.visit(source)

    def _hit_scope(self):
        query = self._query_stack[-1] if self._query_stack else None
        forced = None
        if self._inside_along and self._along_parents:
            forced = self._along_parents[-1]
        return query, forced


class _Hit(object):
    __slots__ = (
        'token', 'kind', 'label', 'value', 'output_field', 'apply',
        'query', 'forced_along',
    )

    def __init__(self, value, kind, label, output_field, apply, query, forced_along):
        self.token = _value_token(value)
        self.kind = kind
        self.label = label
        self.value = value
        self.output_field = output_field
        self.apply = apply
        self.query = query
        self.forced_along = forced_along


def _group(hits):
    order = []
    buckets = {}
    for hit in hits:
        key = (hit.kind, hit.label, hit.token)
        bucket = buckets.get(key)
        if bucket is None:
            bucket = []
            buckets[key] = bucket
            order.append(bucket)
        bucket.append(hit)
    return order


def _column_for(group, names):
    chosen = group[0]
    output = chosen.output_field
    if output is None:
        for hit in group:
            if hit.output_field is not None:
                output = hit.output_field
                break
    if output is None:
        output = _INTEGER
    return BindColumn(
        chosen.kind, chosen.label, chosen.value, output,
        _unique_name(_column_base(chosen.kind, chosen.label), names),
    )


def _child_apply(parent, index, child):
    def apply(ref, parent=parent, index=index, child=child):
        parent.children[index] = _AlongOnce(child, ref)
    return apply


def _lhs_apply(lookup, child):
    def apply(ref, lookup=lookup, child=child):
        lookup.lhs = _AlongOnce(child, ref)
    return apply


def _classify_lookup(lookup, value, root_model):
    name = _lookup_field_name(lookup)
    model_label = _lookup_model_label(lookup)
    if isinstance(value, bool) and name in _ELIGIBILITY:
        return 'eligibility', _ELIGIBILITY[name]
    if name == 'app_label' and model_label == 'contenttypes.ContentType':
        return 'const', 'content type app'
    if name == 'model' and model_label == 'contenttypes.ContentType':
        return 'const', 'content type model'
    bind = _infer_bind(lookup, root_model)
    if bind is not None:
        return 'bind', bind
    if _is_content_pk(lookup):
        return 'const', 'content pk'
    return 'leave', None


def _classify_key(key, value, root_model):
    field = key.rsplit('__', 1)[-1]
    if isinstance(value, bool) and field in _ELIGIBILITY:
        return 'eligibility', _ELIGIBILITY[field]
    if field == 'app_label' and 'content_type' in key:
        return 'const', 'content type app'
    if field == 'model' and 'content_type' in key:
        return 'const', 'content type model'
    if field in _USER_FIELDS:
        return 'bind', 'user.id'
    if field in _PERMISSION_FIELDS:
        return 'bind', 'permission.id'
    if field in ('pk', 'id') and _model_is_content(root_model):
        return 'const', 'content pk'
    return 'leave', None


def _infer_bind(lookup, root_model):
    target = getattr(getattr(lookup, 'lhs', None), 'target', None)
    if getattr(lookup, 'trusts_content_bind', False):
        attname = getattr(target, 'attname', None) or 'id'
        return 'content.%s' % attname
    if target is None:
        return None
    remote = getattr(target, 'remote_field', None)
    if remote is not None and getattr(remote, 'model', None) is not None:
        concrete = remote.model._meta.concrete_model
        attname = target.target_field.attname
        if concrete is _user_concrete() or _lookup_field_name(lookup) in _USER_FIELDS:
            return 'user.%s' % attname
        if (
            concrete is _permission_concrete()
            or _lookup_field_name(lookup) in _PERMISSION_FIELDS
        ):
            return 'permission.%s' % attname
        if _model_is_user(root_model):
            return 'content.%s' % attname
        return None
    if getattr(target, 'primary_key', False):
        concrete = target.model._meta.concrete_model
        if concrete is _user_concrete():
            return 'user.%s' % target.attname
        if concrete is _permission_concrete():
            return 'permission.%s' % target.attname
    return None


def _is_content_pk(lookup):
    target = getattr(getattr(lookup, 'lhs', None), 'target', None)
    if target is None or not getattr(target, 'primary_key', False):
        return False
    concrete = target.model._meta.concrete_model
    if concrete is _user_concrete() or concrete is _permission_concrete():
        return False
    return True


def _model_is_user(model):
    if model is None:
        return False
    return model._meta.concrete_model is _user_concrete()


def _model_is_content(model):
    if model is None:
        return False
    concrete = model._meta.concrete_model
    return concrete is not _user_concrete() and concrete is not _permission_concrete()


def _user_concrete():
    from django.contrib.auth import get_user_model

    return get_user_model()._meta.concrete_model


def _permission_concrete():
    from django.contrib.auth.models import Permission

    return Permission._meta.concrete_model


def _lookup_field_name(lookup):
    lhs = getattr(lookup, 'lhs', None)
    for attr in ('output_field', 'target'):
        field = getattr(lhs, attr, None)
        name = getattr(field, 'name', None)
        if isinstance(name, str) and name != '':
            return name
    return None


def _lookup_model_label(lookup):
    lhs = getattr(lookup, 'lhs', None)
    target = getattr(lhs, 'target', None)
    model = getattr(target, 'model', None)
    meta = getattr(model, '_meta', None)
    return getattr(meta, 'label', None)


def _lookup_output(lookup):
    lhs = lookup.lhs
    for attr in ('output_field', 'target'):
        field = getattr(lhs, attr, None)
        prepared = _preparable_field(field)
        if prepared is not None:
            return prepared
    return None


def _preparable_field(field):
    if hasattr(field, 'get_db_prep_value'):
        return field
    for attr in ('target_field', 'field'):
        inner = getattr(field, attr, None)
        if hasattr(inner, 'get_db_prep_value'):
            return inner
    return None


def _rhs_is_emitted(lookup, value, connection):
    """False when ``Exact`` drops a bool that is not a placeholder.

    ``Exists(...)`` is stored as ``Exact(expr, True)``. On backends that
    accept that expression in ``WHERE``, the ``True`` is not sent.
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


def _plain_value(value):
    if isinstance(value, (list, tuple, set, dict, QuerySet)):
        return _SKIP
    if isinstance(value, (BindRef, BoundBool, SqlInt, Expression)):
        return _SKIP
    if hasattr(value, 'resolve_expression') or hasattr(value, 'as_sql'):
        return _SKIP
    if hasattr(value, '_meta') and hasattr(value, 'pk'):
        return value.pk
    if value is None:
        return _SKIP
    return value


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
        return int(node.walk.bound)
    return int(node.record.along.bound)


def _unresolved_pair(child):
    return (
        isinstance(child, tuple)
        and len(child) == 2
        and isinstance(child[0], str)
    )


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
    if expr is None or isinstance(expr, (str, bytes, int, float, bool)):
        return expr
    if isinstance(expr, Query):
        return _own_query(expr)
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
    field = _preparable_field(column.output_field)
    if field is not None:
        value = field.get_db_prep_value(value, connection=connection)
    if value is None:
        return 'NULL', ()
    return '%s', (value,)


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

    def get_group_by_cols(self):
        return []


class BindTable(object):
    """``CROSS JOIN (SELECT %s AS col, ...) trusts_bind``.

    ``join_type`` stays unset so ``Query.promote_joins`` leaves the row
    alone. ``as_sql`` still emits ``CROSS JOIN``. The row is installed
    after the statement's real base table.
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

    @property
    def identity(self):
        return (
            self.__class__,
            tuple(
                (column.kind, column.label, _value_token(column.value), column.sql_name)
                for column in self.columns
            ),
        )

    def __eq__(self, other):
        if not isinstance(other, BindTable):
            return NotImplemented
        return self.identity == other.identity

    def __hash__(self):
        return hash(self.identity)


class BoundBool(Value):
    """Boolean parameter that stays ``= %s`` on PostgreSQL.

    A plain ``True`` is not a ``bool`` here, so ``Exact`` does not turn
    the comparison into a bare column. ``as_sql`` still emits one
    placeholder. The hint is the lockfile label (``active``).
    """

    def __init__(self, value, hint):
        super().__init__(bool(value), output_field=BooleanField())
        self.hint = hint

    def as_sql(self, compiler, connection):
        return '%s', (self.value,)

    def resolve_expression(
        self, query=None, allow_joins=True, reuse=None,
        summarize=False, for_save=False,
    ):
        return copy.copy(self)


class SqlInt(Expression):
    """Integer literal such as the ``SELECT 1`` of ``EXISTS``. No placeholder."""

    def __init__(self, number):
        super().__init__(output_field=IntegerField())
        self.number = int(number)

    def as_sql(self, compiler, connection):
        return str(self.number), ()

    def resolve_expression(
        self, query=None, allow_joins=True, reuse=None,
        summarize=False, for_save=False,
    ):
        return copy.copy(self)

    def get_source_expressions(self):
        return []

    def set_source_expressions(self, exprs):
        if exprs:
            raise TypeError('SqlInt has no source expressions.')


class _AlongOnce(Expression):
    """Retarget one ``along=`` depth cap at the bind row.

    The cap is the ``depth < %s`` placeholder in the walk SQL, not a
    node in the tree. An ``EXISTS`` marker compiled inside that SQL
    becomes the literal ``1``.
    """

    filterable = True

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
            from trusts.core import TrustsConfigurationError

            raise TrustsConfigurationError(
                'bind_once reference emitted a placeholder.'
            )
        sql, params = _literalize_exists(sql, params)
        return _retarget_depth(sql, params, ref_sql)


def _retarget_depth(sql, params, ref_sql):
    from trusts.core import TrustsConfigurationError

    matches = list(_DEPTH_CAP.finditer(sql))
    if len(matches) != 1:
        raise TrustsConfigurationError(
            'bind_once could not retarget the along depth cap.'
        )
    match = matches[0]
    index = sql[:match.start()].count('%s')
    params = list(params)
    if index >= len(params):
        raise TrustsConfigurationError(
            'bind_once could not retarget the along depth cap.'
        )
    del params[index]
    head = match.group(0)[:-2].rstrip()
    sql = '%s%s %s%s' % (sql[:match.start()], head, ref_sql, sql[match.end():])
    return sql, tuple(params)


def _literalize_exists(sql, params):
    matches = list(_EXISTS_MARKER.finditer(sql))
    if not matches:
        return sql, params
    params = list(params)
    for match in reversed(matches):
        index = sql[:match.start()].count('%s')
        if index >= len(params) or not _param_is_exists_one(params[index]):
            continue
        del params[index]
        quote = match.group(1)
        literal = 'SELECT 1 AS %sa%s' % (quote, quote)
        sql = sql[:match.start()] + literal + sql[match.end():]
    return sql, tuple(params)


def _param_is_exists_one(param):
    if param == 1 and not isinstance(param, bool):
        return True
    payload = getattr(param, 'payload', None)
    return (
        isinstance(payload, dict)
        and payload.get('hint') == 'exists marker'
        and payload.get('const') == 1
    )


def strip_exists_marker(query):
    """Replace Django's ``SELECT %s`` exists sentinel with the literal ``1``."""
    annotation = query.annotations.get('a')
    if isinstance(annotation, Value) and annotation.value == 1:
        query.annotations['a'] = SqlInt(1)
        query._annotation_select_cache = None
    return query


def query_exists(queryset):
    """Evaluate ``queryset.exists()`` with a literal exists marker."""
    query = strip_exists_marker(queryset.query.exists())
    compiler = query.get_compiler(using=queryset.db)
    return compiler.has_results()


class LiteralExists(Exists):
    """``EXISTS (SELECT 1 ...)``. The marker is SQL, not a placeholder."""

    def __init__(self, queryset, **kwargs):
        super().__init__(queryset, **kwargs)
        strip_exists_marker(self.query)
