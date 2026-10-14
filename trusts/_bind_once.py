"""Turn one plain policy queryset into a bound-once statement.

Policy code builds ordinary querysets (``filter``, ``Q``, ``Exists``,
``OuterRef``). ``bind_once`` is the only pass that folds inquiry values
onto one ``trusts_bind`` row. That queryset is what runs and what the
lockfile records.

``TRUSTS_SQL_BIND_ONCE`` defaults to true. Set it to false and ``bind_once``
returns the queryset unchanged, so the lockfile shows the plain SQL.

If the queryset does not have the Django query structure this pass reads,
or the rewrite fails, the original queryset is returned unchanged and one
warning is logged. The lockfile then records that plain SQL.
"""

import copy
import logging
import re
import weakref

from django.db.models import BooleanField, Exists, IntegerField, QuerySet, Value
from django.db.models.expressions import BaseExpression, Expression, F
from django.db.models.lookups import Lookup
from django.db.models.query_utils import Q
from django.db.models.sql.query import Query
from django.db.models.sql.where import ExtraWhere, NothingNode, WhereNode


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
_TERMINALS = (NothingNode, ExtraWhere)
_BOUND_QUERY_CLASSES = {}
_fallbacks = weakref.WeakSet()
_warned = False


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
    ``exists()`` on the queryset this returns keeps the bound statement,
    including the literal ``SELECT 1`` marker.

    A queryset whose Django query structure does not match, or a rewrite
    that fails, is returned unchanged. The warning is logged once.
    An ``along=`` depth cap is checked here too, while the original
    queryset is still intact. A cap the rewrite cannot retarget returns
    that original queryset, not a mix of bound and plain SQL.
    """
    if not trusts_bind_once():
        return _pack(queryset, also)
    query = getattr(queryset, 'query', None)
    alias_map = getattr(query, 'alias_map', None)
    if (
        isinstance(query, Query)
        and isinstance(alias_map, dict)
        and BIND_ALIAS in alias_map
    ):
        return _pack(queryset, also)
    try:
        problem = _shape_problem(queryset, also)
        if problem is not None:
            return _fallback(queryset, also, problem)
        prepared, extras = _rewrite(queryset, also)
    except Exception as exc:
        return _fallback(queryset, also, _exception_detail(exc))
    return _pack(prepared, extras)


def bound_exists_query(queryset):
    """The ``EXISTS`` query the lockfile compiles for ``queryset``."""
    if not trusts_bind_once():
        return queryset.query.exists()
    bound = bind_once(queryset)
    if bound in _fallbacks:
        return bound.query.exists()
    return strip_exists_marker(bound.query.exists())


def _pack(queryset, extras):
    if extras:
        return (queryset, *extras)
    return queryset


def _fallback(queryset, also, detail):
    _warn_once(detail)
    for obj in (queryset, *also):
        try:
            _fallbacks.add(obj)
        except TypeError:
            pass
    return _pack(queryset, also)


def _warn_once(detail):
    global _warned
    if _warned:
        return
    _warned = True
    import django

    logging.getLogger('trusts').warning(
        'bind_once left the queryset unchanged: %s (Django %s).',
        detail,
        django.get_version(),
    )


def _exception_detail(exc):
    message = str(exc).strip()
    name = type(exc).__name__
    if message:
        return '%s: %s' % (name, message)
    return name


def _bound_has_results(self, using):
    exists_query = strip_exists_marker(self.exists())
    compiler = exists_query.get_compiler(using=using)
    return compiler.has_results()


def _arm_exists(queryset):
    query = queryset.query
    cls = query.__class__
    if getattr(cls, '_trusts_bound_has_results', False):
        return
    bound = _BOUND_QUERY_CLASSES.get(cls)
    if bound is None:
        bound = type(cls.__name__, (cls,), {
            'has_results': _bound_has_results,
            '_trusts_bound_has_results': True,
        })
        _BOUND_QUERY_CLASSES[cls] = bound
    query.__class__ = bound


def _shape_problem(queryset, also):
    """Describe the first Django query structure this pass does not know.

    ``None`` means the tree matches the attributes, classes, and node
    types the rewrite reads.
    """
    query = getattr(queryset, 'query', None)
    if not isinstance(query, Query):
        return 'queryset.query is %s, not a Query' % type(query).__name__
    problem = _compiler_shape(queryset, query)
    if problem is not None:
        return problem
    seen = set()
    problem = _walk_shape(query, seen)
    if problem is not None:
        return problem
    for extra in also:
        problem = _walk_shape(extra, seen)
        if problem is not None:
            return problem
    return None


def _compiler_shape(queryset, query):
    alias = getattr(queryset, 'db', None) or 'default'
    compiler = query.get_compiler(using=alias)
    if not callable(getattr(compiler, 'quote_name', None)):
        return 'SQLCompiler.quote_name is missing'
    if not callable(getattr(compiler, 'compile', None)):
        return 'SQLCompiler.compile is missing'
    ops = getattr(compiler.connection, 'ops', None)
    method = getattr(
        ops, 'conditional_expression_supported_in_where_clause', None,
    )
    if not callable(method):
        return (
            'DatabaseOperations.conditional_expression_supported_in_where_clause '
            'is missing'
        )
    return None


def _walk_shape(node, seen):
    if node is None or isinstance(node, (str, bytes, int, float, bool)):
        return None
    if isinstance(node, _TERMINALS) or isinstance(node, F):
        if isinstance(node, F) and not isinstance(getattr(node, 'name', None), (str, F)):
            return 'F.name is %s, not a string or an F reference' % type(
                getattr(node, 'name', None)
            ).__name__
        return None
    if id(node) in seen:
        return None
    seen.add(id(node))
    if isinstance(node, Query):
        return _query_shape(node, seen)
    if isinstance(node, Lookup):
        return _lookup_shape(node, seen)
    if isinstance(node, (WhereNode, Q)):
        return _node_shape(node, seen)
    if isinstance(node, tuple):
        if len(node) == 2 and isinstance(node[0], str):
            return _walk_value(node[1], seen)
        return 'query child is a %s-tuple, not a lookup pair' % len(node)
    get_source = getattr(node, 'get_source_expressions', None)
    if not callable(get_source):
        return (
            '%s has no get_source_expressions' % type(node).__name__
        )
    sources = get_source()
    if not isinstance(sources, (list, tuple)):
        return (
            '%s.get_source_expressions returned %s, not a list'
            % (type(node).__name__, type(sources).__name__)
        )
    if sources and not callable(getattr(node, 'set_source_expressions', None)):
        return '%s.set_source_expressions is missing' % type(node).__name__
    for source in sources:
        problem = _walk_shape(source, seen)
        if problem is not None:
            return problem
    return None


def _query_shape(query, seen):
    if not isinstance(getattr(query, 'alias_map', None), dict):
        return 'Query.alias_map is %s, not a dict' % type(
            getattr(query, 'alias_map', None)
        ).__name__
    if not isinstance(getattr(query, 'alias_refcount', None), dict):
        return 'Query.alias_refcount is %s, not a dict' % type(
            getattr(query, 'alias_refcount', None)
        ).__name__
    for alias, count in query.alias_refcount.items():
        if not isinstance(alias, str) or not isinstance(count, int):
            return 'Query.alias_refcount entry %r is not a string and an int' % (
                alias,
            )
    if not isinstance(getattr(query, 'table_map', None), dict):
        return 'Query.table_map is %s, not a dict' % type(
            getattr(query, 'table_map', None)
        ).__name__
    for table, aliases in query.table_map.items():
        if not isinstance(table, str) or not isinstance(aliases, list):
            return 'Query.table_map entry %r is not a string and a list' % (
                table,
            )
    where = getattr(query, 'where', None)
    if not isinstance(where, WhereNode):
        return 'Query.where is %s, not a WhereNode' % type(where).__name__
    annotations = getattr(query, 'annotations', None)
    if not isinstance(annotations, dict):
        return 'Query.annotations is %s, not a dict' % type(annotations).__name__
    for key, annotation in annotations.items():
        if not isinstance(key, str):
            return 'annotation alias is %s, not a str' % type(key).__name__
        if annotation is not None and not isinstance(annotation, BaseExpression):
            return 'annotation %r is %s, not an expression' % (
                key, type(annotation).__name__,
            )
    combined = getattr(query, 'combined_queries', None)
    if not isinstance(combined, tuple):
        return 'Query.combined_queries is %s, not a tuple' % type(combined).__name__
    if not hasattr(query, 'model'):
        return 'Query.model is missing'
    for name in ('clone', 'exists', 'get_initial_alias'):
        if not callable(getattr(query, name, None)):
            return 'Query.%s is missing' % name
    problem = _walk_shape(where, seen)
    if problem is not None:
        return problem
    for annotation in annotations.values():
        problem = _walk_shape(annotation, seen)
        if problem is not None:
            return problem
    for part in combined:
        if not isinstance(part, Query):
            return 'combined query is %s, not a Query' % type(part).__name__
        problem = _walk_shape(part, seen)
        if problem is not None:
            return problem
    return None


def _node_shape(node, seen):
    children = getattr(node, 'children', None)
    if not isinstance(children, list):
        return '%s.children is %s, not a list' % (
            type(node).__name__, type(children).__name__,
        )
    connector = getattr(node, 'connector', None)
    if not isinstance(connector, str):
        return '%s.connector is %s, not a str' % (
            type(node).__name__, type(connector).__name__,
        )
    if not isinstance(getattr(node, 'negated', None), bool):
        return '%s.negated is not a bool' % type(node).__name__
    if not callable(getattr(type(node), 'create', None)):
        return '%s.create is missing' % type(node).__name__
    for child in children:
        problem = _walk_shape(child, seen)
        if problem is not None:
            return problem
    return None


def _walk_value(value, seen):
    """A ``Q`` pair's value. Plain values stay. Expressions are walked."""
    if value is None or isinstance(value, (
        str, bytes, int, float, bool, list, tuple, set, dict, QuerySet,
    )):
        return None
    if isinstance(value, (Query, Lookup, WhereNode, Q, BaseExpression)):
        return _walk_shape(value, seen)
    if (
        hasattr(value, 'resolve_expression')
        or hasattr(value, 'as_sql')
        or hasattr(value, 'get_source_expressions')
    ):
        return _walk_shape(value, seen)
    return None


def _lookup_shape(node, seen):
    if not hasattr(node, 'lhs') or not hasattr(node, 'rhs'):
        return 'Lookup is missing lhs or rhs'
    if not callable(getattr(node, 'rhs_is_direct_value', None)):
        return 'Lookup.rhs_is_direct_value is missing'
    lookup_name = getattr(node, 'lookup_name', None)
    if lookup_name is not None and not isinstance(lookup_name, str):
        return 'Lookup.lookup_name is %s, not a str' % type(lookup_name).__name__
    problem = _walk_shape(node.lhs, seen)
    if problem is not None:
        return problem
    if node.rhs_is_direct_value():
        if isinstance(node.rhs, Value) and not hasattr(node.rhs, 'value'):
            return 'Value is missing value'
        return None
    return _walk_shape(node.rhs, seen)


class _QueryHolder(object):
    """Owns a cloned query without touching the caller's object."""

    def __init__(self, db, query):
        self.db = db
        self.query = query


def _rewrite(queryset, also):
    prepared, extras = _prepare(queryset, also)
    root = getattr(prepared.query, 'model', None)
    walk = _Walk(root, _connection_for(prepared))
    walk.visit(prepared.query)
    for extra in extras:
        walk.visit(extra)
    walk.finish(prepared.query)
    # Compile along retargets before this clone is published. A failure
    # raises into bind_once, which still holds the untouched original.
    _validate_along_retarget(prepared, extras)
    _arm_exists(prepared)
    if isinstance(queryset, QuerySet):
        return prepared, extras
    queryset.query = prepared.query
    return queryset, extras


def _validate_along_retarget(prepared, extras):
    """Compile each along retarget on copies before the clone is returned.

    ``_retarget_depth`` otherwise runs when the caller compiles SQL, after
    ``bind_once`` has already returned the rewritten queryset. A miss then
    raises, and the original statement is no longer available to fall back
    to. Compiling here makes that miss a rewrite failure. Copies keep the
    compiler from writing aliases onto the queryset this pass returns.
    """
    nodes = []
    seen = set()
    _collect_along_once(prepared.query, nodes, seen)
    for extra in extras:
        _collect_along_once(extra, nodes, seen)
    if not nodes:
        return
    probe = prepared.query.clone()
    probe.alias_map = {
        alias: table if table is None else copy.copy(table)
        for alias, table in probe.alias_map.items()
    }
    probe.table_map = {
        name: list(aliases) for name, aliases in probe.table_map.items()
    }
    compiler = probe.get_compiler(
        using=getattr(prepared, 'db', None) or 'default',
    )
    for node in nodes:
        # The statement compiler resolves F() before as_sql. Do the same
        # on the probe, or an unresolved F is reported as a rewrite failure.
        standalone = _own_expr(node)
        if hasattr(standalone, 'resolve_expression'):
            standalone = standalone.resolve_expression(
                probe, allow_joins=True, reuse=None, summarize=False,
            )
        standalone.as_sql(compiler, compiler.connection)


def _collect_along_once(node, found, seen):
    if node is None or isinstance(node, (str, bytes, int, float, bool)):
        return
    marker = id(node)
    if marker in seen:
        return
    if isinstance(node, _AlongOnce):
        seen.add(marker)
        found.append(node)
        return
    if isinstance(node, Query):
        seen.add(marker)
        _collect_along_once(node.where, found, seen)
        for annotation in node.annotations.values():
            _collect_along_once(annotation, found, seen)
        for part in node.combined_queries or ():
            _collect_along_once(part, found, seen)
        return
    if isinstance(node, (list, tuple)):
        seen.add(marker)
        for item in node:
            _collect_along_once(item, found, seen)
        return
    if isinstance(node, Lookup):
        seen.add(marker)
        _collect_along_once(node.lhs, found, seen)
        if not node.rhs_is_direct_value():
            _collect_along_once(node.rhs, found, seen)
        return
    if isinstance(node, (WhereNode, Q)):
        seen.add(marker)
        for child in node.children:
            _collect_along_once(child, found, seen)
        return
    if not hasattr(node, 'get_source_expressions'):
        return
    seen.add(marker)
    for source in node.get_source_expressions():
        _collect_along_once(source, found, seen)


def _prepare(queryset, also):
    extras = tuple(_own_expr(item) for item in also)
    if isinstance(queryset, QuerySet):
        prepared = queryset._chain()
        prepared.query = _own_query(prepared.query)
        return prepared, extras
    query = getattr(queryset, 'query', None)
    if isinstance(query, Query):
        return _QueryHolder(
            getattr(queryset, 'db', None), _own_query(query),
        ), extras
    from trusts.core import TrustsConfigurationError

    raise TrustsConfigurationError(
        'bind_once expected a queryset, not %r.' % (queryset,)
    )


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

    def finish(self, query):
        if not self.hits:
            return
        # One row on the outer statement. A trusts_bind column is visible
        # inside WITH RECURSIVE, including a walk nested in EXISTS, so
        # MySQL uses that same column instead of binding the value again.
        names = set()
        columns = []
        for group in _group(self.hits):
            column = _column_for(group, names)
            columns.append(column)
            ref = BindRef(BIND_ALIAS, column.sql_name, column.output_field)
            for hit in group:
                hit.apply(ref)
        _install(query, columns)

    def visit(self, node, exists_context=False):
        if node is None or isinstance(node, (
            BindRef, BoundBool, SqlInt, str, bytes, int, float, bool,
        )):
            return
        if isinstance(node, _AlongOnce):
            self.visit(node.inner)
            return
        if isinstance(node, Exists):
            # Exists.__init__ already ran query.exists(), which put the
            # sentinel on this query. Do not walk sources again.
            self.visit(node.query, exists_context=True)
            return
        if isinstance(node, Query):
            if id(node) in self.seen_queries:
                return
            self.seen_queries.add(id(node))
            self.visit(node.where)
            for key, annotation in list(node.annotations.items()):
                # Django's EXISTS sentinel is the annotation named "a" on
                # the existence subquery. A caller annotation of that name
                # on the outer query keeps its value and output field.
                if (
                    exists_context
                    and key == 'a'
                    and isinstance(annotation, Value)
                    and annotation.value == 1
                    and not isinstance(annotation.value, bool)
                ):
                    node.annotations[key] = SqlInt(1)
                    node._annotation_select_cache = None
                    continue
                self.visit(annotation)
            for part in node.combined_queries or ():
                self.visit(part, exists_context=exists_context)
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
            if (
                node.rhs_is_direct_value()
                and node.rhs is True
                and _rhs_is_emitted(node, True, self.connection)
            ):
                # Every walk's match flag is the same True. One column,
                # referenced from each comparison.
                self.hits.append(_Hit(
                    True, 'const', 'along match', BooleanField(),
                    lambda ref, lookup=node: setattr(lookup, 'rhs', ref),
                ))
                return
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
        # A JSON primary key sentinel is a dict. It is still the content
        # call input, so it has to join the bind row instead of being
        # recorded as a constant. An ``__in`` list stays on the lookup.
        candidate = raw.value if isinstance(raw, Value) else raw
        if (
            isinstance(candidate, dict)
            and getattr(node, 'lookup_name', None) == 'exact'
            and _is_content_pk(node)
        ):
            self.hits.append(_Hit(
                candidate, 'const', 'content pk', _lookup_output(node),
                lambda ref, lookup=node: setattr(lookup, 'rhs', ref),
            ))
            return
        plain = _plain_value(raw)
        if plain is _SKIP or not _rhs_is_emitted(node, plain, self.connection):
            return
        kind, label = _classify_lookup(node, plain, self.root_model)
        if kind == 'eligibility':
            # One column for every copy of this boolean. The comparison is
            # ``column = trusts_bind.<name>``, so PostgreSQL still emits an
            # equality instead of a bare boolean column.
            self.hits.append(_Hit(
                plain, kind, label, _lookup_output(node) or BooleanField(),
                lambda ref, lookup=node: setattr(lookup, 'rhs', ref),
            ))
            return
        if kind != 'bind' and kind != 'const':
            return
        output = _lookup_output(node)
        self.hits.append(_Hit(
            plain, kind, label, output,
            lambda ref, lookup=node: setattr(lookup, 'rhs', ref),
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
            self.hits.append(_Hit(
                plain, kind, label, BooleanField(),
                lambda ref, parent=parent, index=index, key=key: (
                    parent.children.__setitem__(index, (key, ref))
                ),
            ))
            return
        if kind != 'bind' and kind != 'const':
            return
        self.hits.append(_Hit(
            plain, kind, label, None,
            lambda ref, parent=parent, index=index, key=key: (
                parent.children.__setitem__(index, (key, ref))
            ),
        ))

    def _note_along(self, node, apply):
        if id(node) in self.seen_along:
            return
        self.seen_along.add(id(node))
        bound = _along_bound(node)
        self.hits.append(_Hit(bound, 'const', 'along bound', _INTEGER, apply))
        self._visit_sources(node)

    def _visit_sources(self, node):
        if not hasattr(node, 'get_source_expressions'):
            return
        for source in node.get_source_expressions():
            self.visit(source)


class _Hit(object):
    __slots__ = ('token', 'kind', 'label', 'value', 'output_field', 'apply')

    def __init__(self, value, kind, label, output_field, apply):
        self.token = _value_token(value)
        self.kind = kind
        self.label = label
        self.value = value
        self.output_field = output_field
        self.apply = apply


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
        self.columns = _role_first(columns)
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


def _role_first(columns):
    """User, permission, then content. Skip a role that is not used.

    Other columns keep the order they were registered. A content primary
    key constant is the content call input, so it sorts with content.
    """
    def key(item):
        index, column = item
        if column.kind == 'bind':
            role = column.label.split('.', 1)[0]
            rank = {'user': 0, 'permission': 1, 'content': 2}.get(role)
            if rank is not None:
                return (rank, index)
        if column.kind == 'const' and column.label == 'content pk':
            return (2, index)
        return (3, index)

    return tuple(
        column for _, column in sorted(enumerate(columns), key=key)
    )


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
    """True when this placeholder is the ``SELECT %s AS "a"`` sentinel.

    The match is the constant ``1`` at that SQL position. A caller
    annotation such as ``review_annotation=Value(1)`` is a different
    placeholder and is not stripped.
    """
    if param == 1 and not isinstance(param, bool):
        return True
    payload = getattr(param, 'payload', None)
    if not isinstance(payload, dict):
        return False
    const = payload.get('const')
    return const == 1 and not isinstance(const, bool)


def strip_exists_marker(query):
    """Replace Django's ``SELECT %s`` exists sentinel with the literal ``1``."""
    annotation = query.annotations.get('a')
    if isinstance(annotation, Value) and annotation.value == 1:
        query.annotations['a'] = SqlInt(1)
        query._annotation_select_cache = None
    return query


class LiteralExists(Exists):
    """``EXISTS (SELECT 1 ...)``. The marker is SQL, not a placeholder."""

    def __init__(self, queryset, **kwargs):
        super().__init__(queryset, **kwargs)
        strip_exists_marker(self.query)
