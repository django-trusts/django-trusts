"""Three-valued SQL for a condition tree.

Path resolution stays separate from the truth value. A missing row, including
a dangling foreign key whose target was not joined, is not a stored NULL.
Ordinary comparisons and ``== None`` are NULL (Unknown) until the owning row
is joined. ``Exists`` is true or false: the owning row was joined, even when
the named column is NULL. Only a final true grants. Negation and ``&`` / ``|``
are Kleene. ``!= None`` is the negation of ``== None``.

Collection membership is not lowered here. ``.contains()`` and a
permission many-to-many ``EXISTS`` keep today's join: one matching member
is enough, an empty collection does not match, and a NULL stored on a
member row is not a quantifier. There is no ``Any()`` or ``All()``.
This module does not choose which content row a ``via=`` carrier reads.
"""

import copy
from datetime import datetime
from decimal import Decimal

from django.db.models import BooleanField, Model, Q
from django.db.models.expressions import Expression
from django.db.models.lookups import Lookup

from trusts.errors import PermissionConditionError
from trusts.plan.conditions import ModelIdentity
from trusts.plan.grammar import walk


class _Marked(object):
    """One placeholder plus the lockfile label the exporter expects."""

    __slots__ = ('value', 'const_hint', 'bind', 'runtime')

    def __init__(self, value, const_hint=None, bind=None, runtime=None):
        self.value = value
        self.const_hint = const_hint
        self.bind = bind
        self.runtime = runtime


class Operand(object):
    """A value plus whether the row that holds it was joined.

    ``literal_none`` is a constant ``None``, the explicit null test.
    A field whose value is NULL is not ``literal_none``. ``export_hint``
    is the lockfile name of this field when a constant is compared to it.
    """

    __slots__ = (
        'value_sql', 'value_params', 'reached_sql', 'reached_params',
        'literal_none', 'output_field', 'export_hint',
    )

    def __init__(self, value_sql, value_params, reached_sql, reached_params,
                 literal_none=False, output_field=None, export_hint=None):
        self.value_sql = value_sql
        self.value_params = tuple(value_params)
        self.reached_sql = reached_sql
        self.reached_params = tuple(reached_params)
        self.literal_none = literal_none
        self.output_field = output_field
        self.export_hint = export_hint


class Expr(object):
    """Boolean SQL that may be true, false, or NULL."""

    __slots__ = ('sql', 'params')

    def __init__(self, sql, params=()):
        self.sql = sql
        self.params = tuple(params)


_COMPARE = {
    'eq': '=',
    'lt': '<',
    'le': '<=',
    'gt': '>',
    'ge': '>=',
}


def _unwrap(value):
    if isinstance(value, _Marked):
        return value.value
    return value


def _runtime_param(param, connection):
    """Value sent to the database. Export keeps the original constant."""
    if isinstance(param, _Marked) and param.runtime is not None:
        value = param.runtime
    else:
        value = _unwrap(param)
    if connection.vendor == 'sqlite' and isinstance(value, Decimal):
        # SQLite stores a decimal column as a real. ``str(Decimal('2.50'))``
        # is ``2.50``, which is not equal to that real; ``2.5`` is.
        text = format(value, 'f')
        if '.' in text:
            text = text.rstrip('0').rstrip('.')
        return text or '0'
    return value


def _prepare_const(operand, field, connection):
    """Adapt a ``%s`` constant to the column it is compared with."""
    if (
        field is None or connection is None or operand.literal_none
        or operand.value_sql not in ('%s', 'CAST(%s AS DATETIME(6))')
        or len(operand.value_params) != 1
    ):
        return operand
    marked = operand.value_params[0]
    if isinstance(marked, _Marked) and marked.runtime is not None:
        raw = marked.runtime
    else:
        raw = _unwrap(marked)
    try:
        prepared = field.get_db_prep_value(raw, connection)
    except Exception:
        prepared = raw
    if isinstance(prepared, memoryview):
        prepared = prepared.tobytes()
    sql = '%s'
    if connection.vendor == 'mysql' and isinstance(raw, datetime):
        sql = 'CAST(%s AS DATETIME(6))'
    if isinstance(marked, _Marked):
        stored = _Marked(
            marked.value, const_hint=marked.const_hint, bind=marked.bind,
            runtime=prepared,
        )
    else:
        stored = _Marked(raw, runtime=prepared)
    return Operand(
        sql, (stored,), operand.reached_sql, operand.reached_params,
        False, field, operand.export_hint,
    )


def _mark_const(operand, hint):
    if (
        operand.value_sql == '%s'
        and len(operand.value_params) == 1
        and not isinstance(operand.value_params[0], _Marked)
    ):
        operand.value_params = (
            _Marked(_unwrap(operand.value_params[0]), const_hint=hint),
        )
    operand.export_hint = hint
    return operand


def _tag_const(operand, hint):
    if (
        not hint
        or operand.export_hint
        or operand.value_sql not in ('%s', 'CAST(%s AS DATETIME(6))')
        or len(operand.value_params) != 1
    ):
        return operand
    param = operand.value_params[0]
    if isinstance(param, _Marked):
        if param.const_hint or param.bind:
            return operand
        param = _Marked(
            param.value, const_hint=hint, runtime=param.runtime,
        )
    else:
        param = _Marked(param, const_hint=hint)
    return Operand(
        operand.value_sql, (param,),
        operand.reached_sql, operand.reached_params,
        operand.literal_none, operand.output_field, operand.export_hint,
    )


def _align(left, right, connection):
    field = left.output_field or right.output_field
    left = _prepare_const(left, field, connection)
    right = _prepare_const(right, field, connection)
    if left.export_hint and not right.export_hint:
        right = _tag_const(right, left.export_hint)
    elif right.export_hint and not left.export_hint:
        left = _tag_const(left, right.export_hint)
    return left, right


def compare(kind, left, right, connection=None):
    """One comparison. ``== None`` / ``!= None`` test a stored NULL only."""
    if kind in ('eq', 'ne') and left.literal_none != right.literal_none:
        field = right if left.literal_none else left
        eq = Expr(
            'CASE WHEN (%s) THEN (%s IS NULL) ELSE NULL END' % (
                field.reached_sql, field.value_sql,
            ),
            field.reached_params + field.value_params,
        )
        if kind == 'eq':
            return eq
        # Derived: unreachable stays Unknown, a reached value is true.
        return Expr('(NOT (%s))' % eq.sql, eq.params)
    left, right = _align(left, right, connection)
    if kind == 'ne':
        # The policy formatter accepts ``=`` and ``NOT``. ``<>`` is not
        # emitted.
        return Expr(
            '(NOT (%s = %s))' % (left.value_sql, right.value_sql),
            left.value_params + right.value_params,
        )
    return Expr(
        '(%s %s %s)' % (left.value_sql, _COMPARE[kind], right.value_sql),
        left.value_params + right.value_params,
    )


def lower(node, scope):
    """Lower ``node`` to three-valued SQL. The caller demands true."""
    kind = node.kind
    if kind == 'and':
        left, right = lower(node.left, scope), lower(node.right, scope)
        return Expr(
            '((%s) AND (%s))' % (left.sql, right.sql),
            left.params + right.params,
        )
    if kind == 'or':
        left, right = lower(node.left, scope), lower(node.right, scope)
        return Expr(
            '((%s) OR (%s))' % (left.sql, right.sql),
            left.params + right.params,
        )
    if kind == 'not':
        inner = lower(node.item, scope)
        return Expr('(NOT (%s))' % inner.sql, inner.params)
    if kind == 'bare':
        operand = scope.operand(node.item)
        field = operand.output_field
        if (
            field is not None
            and field.get_internal_type() == 'BooleanField'
        ):
            prepared = True
            if scope.connection is not None:
                try:
                    prepared = field.get_db_prep_value(True, scope.connection)
                except Exception:
                    prepared = True
            return Expr(
                '(' + operand.value_sql + ' = %s)',
                operand.value_params + (
                    _Marked(prepared, const_hint=operand.export_hint or 'literal'),
                ),
            )
    if kind == 'exists':
        operand = scope.exists_operand(node.item)
        return Expr('(%s)' % operand.reached_sql, operand.reached_params)
    if kind == 'ne' or kind in _COMPARE:
        return compare(
            kind, scope.operand(node.left), scope.operand(node.right),
            scope.connection,
        )
    raise PermissionConditionError(
        'Cannot lower condition node %r to SQL.' % (node,)
    )


def has_contains(node):
    return any(item.kind == 'contains' for item in walk(node))


def prepare_value(value):
    if isinstance(value, ModelIdentity):
        return value.pk
    return value


def now_sql(connection):
    vendor = connection.vendor
    if vendor == 'postgresql':
        return 'STATEMENT_TIMESTAMP()'
    if vendor == 'mysql':
        return 'CURRENT_TIMESTAMP(6)'
    return "STRFTIME('%%Y-%%m-%%d %%H:%%M:%%f', 'NOW')"


def _const_operand(value, connection):
    runtime = prepare_value(value)
    sql = '%s'
    if (
        connection is not None
        and connection.vendor == 'mysql'
        and isinstance(runtime, datetime)
    ):
        sql = 'CAST(%s AS DATETIME(6))'
    if isinstance(value, ModelIdentity):
        param = _Marked(value, runtime=runtime)
    else:
        param = runtime
    return Operand(sql, (param,), '(1=1)', (), runtime is None)


def _forward_fk(field):
    """A concrete foreign key or one-to-one, including ``to_field``."""
    return bool(
        getattr(field, 'concrete', False)
        and (
            getattr(field, 'many_to_one', False)
            or getattr(field, 'one_to_one', False)
        )
    )


def _reverse_one_to_one(field):
    return bool(
        getattr(field, 'one_to_one', False)
        and not getattr(field, 'concrete', False)
    )


def _value_column(field):
    return bool(
        getattr(field, 'concrete', False)
        and not getattr(field, 'many_to_many', False)
        and not _forward_fk(field)
    )


def _reject_path(field, name):
    raise PermissionConditionError(
        'Cannot push condition path %r down to SQL.' % (name,)
    )


def split_value_path(model, path):
    """Hops to the row that holds the leaf column, and that column."""
    hops = []
    current = model
    for index, name in enumerate(path):
        try:
            field = current._meta.get_field(name)
        except Exception as exc:
            raise PermissionConditionError(
                'Cannot push condition path %r down to SQL.' % (name,)
            ) from exc
        last = index == len(path) - 1
        if last and (_value_column(field) or _forward_fk(field)):
            return hops, field
        if not last and _forward_fk(field):
            hops.append(('fk', field))
            current = field.remote_field.model
            continue
        if not last and _reverse_one_to_one(field):
            hops.append(('rev', field))
            current = field.related_model
            continue
        _reject_path(field, name)
    raise PermissionConditionError(
        'Cannot push condition path down to SQL.'
    )


def relation_hops(model, path):
    """Joins that reach the row ``Exists(path)`` asks about."""
    hops = []
    current = model
    for index, name in enumerate(path):
        try:
            field = current._meta.get_field(name)
        except Exception as exc:
            raise PermissionConditionError(
                'Cannot push condition path %r down to SQL.' % (name,)
            ) from exc
        last = index == len(path) - 1
        if _forward_fk(field):
            hops.append(('fk', field))
            current = field.remote_field.model
            if last:
                return hops
            continue
        if _reverse_one_to_one(field):
            hops.append(('rev', field))
            current = field.related_model
            if last:
                return hops
            continue
        if last and _value_column(field):
            return hops
        _reject_path(field, name)
    return hops


def _join_cond(kind, field, left, right, qn):
    if kind == 'fk':
        return '%s.%s = %s.%s' % (
            right, qn(field.target_field.column),
            left, qn(field.column),
        )
    forward = field.field
    return '%s.%s = %s.%s' % (
        right, qn(forward.column),
        left, qn(forward.target_field.column),
    )


def _related(kind, field):
    if kind == 'fk':
        return field.remote_field.model
    return field.related_model


def correlated(model, hops, leaf_column, source, qn, *, exists):
    """Scalar value or ``EXISTS`` from ``source``.

    ``source`` is ``('alias', sql)`` or ``('pk', pk, model)``. A join that
    misses, including a dangling foreign key, yields no row.
    """
    if source[0] == 'alias':
        prev = source[1]
        parts = []
        where = None
        for index, (kind, field) in enumerate(hops):
            dest = qn('h%d' % index)
            related = _related(kind, field)
            cond = _join_cond(kind, field, prev, dest, qn)
            table = qn(related._meta.db_table)
            if not parts:
                parts.append('%s AS %s' % (table, dest))
                where = cond
            else:
                parts.append('JOIN %s AS %s ON %s' % (table, dest, cond))
            prev = dest
        if not hops:
            if exists:
                return '(1=1)', ()
            return '%s.%s' % (source[1], qn(leaf_column)), ()
        selected = '1' if exists else '%s.%s' % (prev, qn(leaf_column))
        body = 'SELECT %s FROM %s WHERE %s' % (
            selected, ' '.join(parts), where,
        )
        if exists:
            return 'EXISTS (%s)' % body, ()
        return '(%s)' % body, ()
    pk, row_model = source[1], source[2]
    src = qn('src')
    table = qn(row_model._meta.db_table)
    pk_column = qn(row_model._meta.pk.column)
    parts = ['%s AS %s' % (table, src)]
    prev = src
    for index, (kind, field) in enumerate(hops):
        dest = qn('h%d' % index)
        related = _related(kind, field)
        cond = _join_cond(kind, field, prev, dest, qn)
        parts.append(
            'JOIN %s AS %s ON %s' % (qn(related._meta.db_table), dest, cond)
        )
        prev = dest
    where = '%s.%s = %%s' % (src, pk_column)
    if exists:
        body = 'SELECT 1 FROM %s WHERE %s' % (' '.join(parts), where)
        return 'EXISTS (%s)' % body, (pk,)
    column = qn(leaf_column) if leaf_column else qn(row_model._meta.pk.column)
    holder = prev
    body = 'SELECT %s.%s FROM %s WHERE %s' % (
        holder, column, ' '.join(parts), where,
    )
    return '(%s)' % body, (pk,)


def field_operand(model, path, source, qn):
    """Value of ``path`` and whether its owning row was joined."""
    if not path:
        if source[0] == 'alias':
            column = model._meta.pk.column
            sql = '%s.%s' % (source[1], qn(column))
            return Operand(sql, (), '(1=1)', (), False)
        sql, params = correlated(
            model, (), model._meta.pk.column, source, qn, exists=False,
        )
        reached, reached_params = correlated(
            model, (), None, source, qn, exists=True,
        )
        return Operand(sql, params, reached, reached_params, False)
    hops, leaf = split_value_path(model, path)
    value_sql, value_params = correlated(
        model, hops, leaf.column, source, qn, exists=False,
    )
    reached_sql, reached_params = correlated(
        model, hops, leaf.column, source, qn, exists=True,
    )
    return Operand(
        value_sql, value_params, reached_sql, reached_params, False, leaf,
    )


def exists_operand(model, path, source, qn):
    hops = relation_hops(model, path)
    reached_sql, reached_params = correlated(
        model, hops, None, source, qn, exists=True,
    )
    return Operand('(1=0)', (), reached_sql, reached_params, False)


class Scope(object):
    """How a root becomes a row. Bindings name alias, pk, or permission."""

    def __init__(self, bindings, qn, connection, alias_sql):
        self.bindings = bindings
        self.qn = qn
        self.connection = connection
        self.alias_sql = alias_sql

    def operand(self, node):
        if node.kind == 'const':
            return _const_operand(node.value, self.connection)
        if node.kind == 'call':
            return self._call(node)
        if node.kind == 'field':
            return self._field(node)
        raise PermissionConditionError(
            'Cannot lower condition node %r.' % (node,)
        )

    def exists_operand(self, node):
        if node.kind != 'field':
            raise PermissionConditionError(
                'Exists() needs a field path.'
            )
        model, source = self._source(node)
        path = self._path(node)
        operand = exists_operand(model, path, source, self.qn)
        operand.export_hint = self._export_hint(node)
        return self._mark_binds(operand, node)

    def _field(self, node):
        if node.root == 'permission':
            return self._permission(node)
        model, source = self._source(node)
        operand = field_operand(model, self._path(node), source, self.qn)
        operand.export_hint = self._export_hint(node)
        return self._mark_binds(operand, node)

    def _export_hint(self, node):
        path = '__'.join(self._path(node))
        if node.root == 'user':
            if path == 'is_active':
                return 'active'
            if path:
                return 'user.' + path
            return 'user.id'
        if path:
            return path
        return None

    def _mark_binds(self, operand, node):
        binding = self.bindings.get(node.root)
        if binding is None or binding[0] != 'pk':
            return operand
        attname = binding[1]._meta.pk.attname
        if node.root == 'user':
            bind = 'user.' + attname
        elif node.root == 'object':
            bind = 'content.' + attname
        else:
            bind = attname

        def mark(params):
            marked = []
            for param in params:
                if isinstance(param, _Marked):
                    marked.append(param)
                else:
                    marked.append(_Marked(param, bind=bind))
            return tuple(marked)

        operand.value_params = mark(operand.value_params)
        operand.reached_params = mark(operand.reached_params)
        return operand

    def _path(self, node):
        binding = self.bindings.get(node.root)
        prefix = ()
        if binding is not None and binding[0] == 'alias':
            prefix = binding[2]
        return tuple(prefix) + tuple(node.path)

    def _source(self, node):
        binding = self.bindings.get(node.root)
        if binding is None:
            raise PermissionConditionError(
                'Cannot lower field rooted at %r.' % (node.root,)
            )
        if binding[0] == 'alias':
            return binding[1], ('alias', self.alias_sql)
        if binding[0] == 'pk':
            return binding[1], ('pk', binding[2], binding[1])
        raise PermissionConditionError(
            'Cannot lower field rooted at %r.' % (node.root,)
        )

    def _permission(self, node):
        binding = self.bindings.get('permission')
        perm = None if binding is None else binding[1]
        if not node.path:
            if isinstance(perm, Model):
                operand = _const_operand(perm.pk, self.connection)
            elif perm is None:
                raise PermissionConditionError(
                    'Permission references cannot traverse attributes in V1.'
                )
            else:
                operand = _const_operand(perm, self.connection)
            return _mark_const(operand, 'permission.codename')
        if len(node.path) != 1:
            raise PermissionConditionError(
                'Permission references cannot traverse attributes in V1.'
            )
        attr = node.path[0]
        if isinstance(perm, str):
            app_label, dot, rest = perm.partition('.')
            codename = rest.split(':', 1)[0] if dot else ''
            if attr == 'app_label' and dot:
                return _mark_const(
                    _const_operand(app_label, self.connection),
                    'permission.app_label',
                )
            if attr == 'codename' and dot:
                return _mark_const(
                    _const_operand(codename, self.connection),
                    'permission.codename',
                )
        if isinstance(perm, Model):
            return field_operand(
                perm.__class__, (attr,),
                ('pk', perm.pk, perm.__class__), self.qn,
            )
        raise PermissionConditionError(
            'Permission references cannot traverse attributes in V1.'
        )

    def _call(self, node):
        name = node.value
        if name == 'now':
            return Operand(now_sql(self.connection), (), '(1=1)', (), False)
        if name == 'lower':
            inner = self.operand(node.item[0])
            return Operand(
                'LOWER(%s)' % inner.value_sql, inner.value_params,
                '(1=1)', (), False,
            )
        if name == 'coalesce':
            parts = [self.operand(arg) for arg in node.item]
            field = next(
                (part.output_field for part in parts if part.output_field is not None),
                None,
            )
            hint = next(
                (part.export_hint for part in parts if part.export_hint),
                None,
            )
            prepared = []
            params = []
            for part in parts:
                part = _prepare_const(part, field, self.connection)
                if part.export_hint is None and hint:
                    part = _tag_const(part, hint)
                prepared.append(part.value_sql)
                params.extend(part.value_params)
            # An unreachable argument is NULL here, so a later argument can
            # replace it. Exists() is how a caller rejects that path.
            sql = 'COALESCE(%s)' % ', '.join(prepared)
            if (
                field is not None
                and self.connection is not None
                and self.connection.vendor == 'sqlite'
                and field.get_internal_type() in ('DecimalField', 'FloatField')
            ):
                db_type = field.db_type(self.connection)
                if db_type:
                    # SQLite gives COALESCE a different type than the column,
                    # so ``2.5 = '2.50'`` fails. The column type puts it back.
                    sql = 'CAST(%s AS %s)' % (sql, db_type)
            return Operand(
                sql, tuple(params), '(1=1)', (), False, field, hint,
            )
        raise PermissionConditionError(
            'Cannot lower function %r.' % (name,)
        )


def _freeze(value):
    if isinstance(value, tuple):
        return tuple(_freeze(item) for item in value)
    if isinstance(value, Model):
        return ('model', value._meta.label, value.pk)
    try:
        hash(value)
    except TypeError:
        return ('repr', repr(value))
    return value


def _tree_key(node):
    if node is None:
        return None
    if isinstance(node, tuple):
        return tuple(_tree_key(item) for item in node)
    item = node.item
    if isinstance(item, tuple):
        item_key = tuple(_tree_key(child) for child in item)
    else:
        item_key = _tree_key(item)
    return (
        node.kind, node.root, tuple(node.path), _freeze(node.value),
        _tree_key(node.left), _tree_key(node.right), item_key,
    )


def _binding_key(bindings):
    frozen = []
    for key in sorted(bindings):
        frozen.append((key, _freeze(bindings[key])))
    return tuple(frozen)


def _export_param(param):
    from trusts.inspect.snapshot import _Symbol, _json_const, _with_hint
    if not isinstance(param, _Marked):
        return _Symbol(_with_hint(
            {'const': _json_const(param)}, 'literal',
        ))
    if param.bind:
        return _Symbol(_with_hint({'bind': param.bind}, '$' + param.bind))
    return _Symbol(_with_hint(
        {'const': _json_const(param.value)}, param.const_hint or 'literal',
    ))


def _exporting():
    from trusts.inspect.snapshot import _export_scope
    return _export_scope.get() is not None


class GrantLookup(Lookup):
    """The three-valued expression itself. True is the only grant.

    Django would otherwise compare the expression to ``True``. On SQLite
    that adds a placeholder the policy renderer cannot name, and it is
    the same grant as the expression alone.
    """

    lookup_name = 'exact'

    def __init__(self, predicate):
        self.predicate = predicate
        super().__init__(predicate, True)

    def as_sql(self, compiler, connection):
        return self.predicate.as_sql(compiler, connection)

    def get_source_expressions(self):
        return [self.predicate]


class GrantPredicate(Expression):
    """One condition as a conditional expression. True is the only grant."""

    conditional = True

    def __init__(self, node, bindings):
        super().__init__(output_field=BooleanField())
        self.node = node
        self.bindings = bindings

    def resolve_expression(
        self, query=None, allow_joins=True, reuse=None,
        summarize=False, for_save=False,
    ):
        return GrantLookup(copy.copy(self))

    def as_sql(self, compiler, connection):
        qn = connection.ops.quote_name
        alias = qn(compiler.query.get_initial_alias())
        expr = lower(self.node, Scope(
            self.bindings, qn, connection, alias,
        ))
        if _exporting():
            return expr.sql, tuple(_export_param(param) for param in expr.params)
        return expr.sql, tuple(
            _runtime_param(param, connection) for param in expr.params
        )

    def get_source_expressions(self):
        return []

    def set_source_expressions(self, exprs):
        if exprs:
            raise TypeError('GrantPredicate has no source expressions.')

    @property
    def identity(self):
        return (GrantPredicate, _tree_key(self.node), _binding_key(self.bindings))

    def __eq__(self, other):
        if not isinstance(other, GrantPredicate):
            return NotImplemented
        return self.identity == other.identity

    def __hash__(self):
        return hash(self.identity)


def grant_q(node, bindings):
    return Q(GrantPredicate(node, bindings))
