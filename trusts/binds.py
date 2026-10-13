"""One SQL placeholder per inquiry value.

Each distinct user, permission, content, content-type, and flag value used
by one statement is placed in a one-row derived table on the outer query.
Inner predicates compare against that row's columns. The lockfile lists
those placeholders once because that is the statement that runs.

The join alias is chosen by this module. It does not follow Django's
lookup compilation order, and it is not renamed when a subquery bumps
its own aliases.
"""

import copy
from contextlib import contextmanager
from contextvars import ContextVar

from django.db.models import BooleanField, Exists, IntegerField, Value
from django.db.models.expressions import Expression
from django.db.models.lookups import Lookup


BIND_ALIAS = 'trusts_bind'

_sheet = ContextVar('trusts_bind_sheet', default=None)


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
        base = label.replace('.', '_')
    else:
        base = {
            'content type app': 'app_label',
            'content type model': 'model',
            'allow inactive': 'allow_inactive',
            'along bound': 'along_bound',
            'content pk': 'content_pk',
            'exists marker': 'exists_marker',
        }.get(label, label.replace(' ', '_'))
    cleaned = []
    for char in base:
        cleaned.append(char if char.isalnum() or char == '_' else '_')
    name = ''.join(cleaned) or 'value'
    if name[0].isdigit():
        name = 'v_' + name
    return name


class BindColumn(object):
    __slots__ = ('kind', 'label', 'value', 'output_field', 'sql_name')

    def __init__(self, kind, label, value, output_field, sql_name):
        self.kind = kind
        self.label = label
        self.value = value
        self.output_field = output_field
        self.sql_name = sql_name


class BindSheet(object):
    def __init__(self):
        self.columns = []
        self._index = {}
        self._names = set()
        self.sealed = False

    def reference(self, kind, label, value, output_field):
        key = (kind, label, _value_token(value))
        column = self._index.get(key)
        if column is None:
            base = _column_base(kind, label)
            sql_name = base
            number = 2
            while sql_name in self._names:
                sql_name = '%s_%s' % (base, number)
                number += 1
            self._names.add(sql_name)
            column = BindColumn(kind, label, value, output_field, sql_name)
            self._index[key] = column
            self.columns.append(column)
        return BindRef(BIND_ALIAS, column.sql_name, output_field)


class BindRef(Expression):
    """Column of the outer one-row bind table. No placeholder of its own."""

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

    ``join_type`` stays unset. Django treats a join type as a join from
    ``parent_alias``, and this row is not joined from another table.
    ``as_sql`` still emits ``CROSS JOIN``. Queryset ``&`` / ``|`` can then
    attach a second row when the two inquiries carry different values,
    and reuse one row when the values are the same.
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
            params.extend(value)
            self._symbols.append(column)
        sql = 'CROSS JOIN (SELECT %s) %s' % (
            ', '.join(parts),
            quote(self.table_alias),
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


def _placeholder(column, compiler, connection):
    value = column.value
    field = column.output_field
    if field is not None:
        value = field.get_db_prep_value(value, connection=connection)
    if value is None:
        return 'NULL', ()
    return '%s', (value,)


def current_sheet():
    return _sheet.get()


def hoist(value, output_field, *, bind=None, hint=None):
    """Return ``value`` unchanged, or a column reference when a sheet is open.

    ``bind`` is a request-time name such as ``user.id``. ``hint`` labels a
    constant such as ``content type app``. An expression is returned as-is
    so an ``OuterRef`` stays correlated to its own outer column.
    """
    if hasattr(value, 'resolve_expression') and not hasattr(value, '_meta'):
        return value
    sheet = current_sheet()
    if sheet is None:
        return value
    if bind is not None:
        return sheet.reference('bind', bind, value, output_field)
    if hint is None:
        hint = 'literal'
    return sheet.reference('const', hint, value, output_field)


@contextmanager
def bind_scope():
    """Reuse an open sheet so nested inquiry builders share one row."""
    existing = _sheet.get()
    if existing is not None:
        yield existing
        return
    sheet = BindSheet()
    token = _sheet.set(sheet)
    try:
        yield sheet
    finally:
        _sheet.reset(token)


def seal(queryset):
    """Attach the bind row to the outermost statement, once."""
    sheet = current_sheet()
    if sheet is None or not sheet.columns or sheet.sealed:
        return queryset
    query = getattr(queryset, 'query', queryset)
    columns = tuple(sheet.columns)
    existing = query.alias_map.get(BIND_ALIAS)
    if isinstance(existing, BindTable) and existing.columns == columns:
        sheet.sealed = True
        return queryset
    # The first alias is the statement's base table. Installing the bind
    # row first would make Django treat ``trusts_bind`` as that table.
    if not query.alias_map and getattr(query, 'model', None) is not None:
        query.get_initial_alias()
    query.alias_map[BIND_ALIAS] = BindTable(columns)
    query.alias_refcount[BIND_ALIAS] = 1
    table_map = query.table_map.setdefault(BIND_ALIAS, [])
    if BIND_ALIAS not in table_map:
        table_map.append(BIND_ALIAS)
    sheet.sealed = True
    return queryset


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
    """``EXISTS (SELECT 1 ...)``. The marker is SQL, not a repeated bind."""

    def __init__(self, queryset, **kwargs):
        super().__init__(queryset, **kwargs)
        strip_exists_marker(self.query)


class BooleanPredicate(Lookup):
    """A boolean expression used directly in ``WHERE``.

    Django wraps a non-lookup conditional expression as ``expr = True``,
    which binds ``true`` once per use. The comparison is not part of the
    predicate. Emitting the expression itself keeps that value out of the
    parameter list.
    """

    lookup_name = 'trusts_predicate'
    prepare_rhs = False

    def __init__(self, expression):
        self.expression = expression
        Expression.__init__(self, output_field=BooleanField())
        self.rhs = True
        self.bilateral_transforms = []

    @property
    def lhs(self):
        # WhereNode assigns the outer-query resolution onto ``lhs``. That
        # assignment has to replace the expression ``as_sql`` compiles.
        # A separate attribute would keep the inner ``ResolvedOuterRef``
        # and ``compiler.compile`` would refuse to render it.
        return self.expression

    @lhs.setter
    def lhs(self, value):
        self.expression = value

    def get_prep_lookup(self):
        return True

    def as_sql(self, compiler, connection):
        return compiler.compile(self.expression)

    def get_source_expressions(self):
        return [self.expression]

    def set_source_expressions(self, exprs):
        self.expression = exprs[0]

    def resolve_expression(
        self, query=None, allow_joins=True, reuse=None,
        summarize=False, for_save=False,
    ):
        clone = copy.copy(self)
        clone.expression = self.expression.resolve_expression(
            query, allow_joins, reuse, summarize, for_save,
        )
        return clone


class AllowOr(Lookup):
    """``(flag OR column)`` so both ``allow_inactive`` values share one statement."""

    lookup_name = 'allow_inactive_or'
    prepare_rhs = False

    def __init__(self, column, flag):
        self.column = column
        self.flag = flag
        Expression.__init__(self, output_field=BooleanField())
        self.lhs = column
        self.rhs = flag
        self.bilateral_transforms = []

    def get_prep_lookup(self):
        return self.flag

    def as_sql(self, compiler, connection):
        column_sql, column_params = compiler.compile(self.column)
        if hasattr(self.flag, 'as_sql'):
            flag_sql, flag_params = compiler.compile(self.flag)
        else:
            flag_sql, flag_params = '%s', (self.flag,)
        return (
            '(%s OR %s)' % (flag_sql, column_sql),
            tuple(flag_params) + tuple(column_params),
        )

    def get_source_expressions(self):
        if hasattr(self.flag, 'resolve_expression'):
            return [self.column, self.flag]
        return [self.column]

    def set_source_expressions(self, exprs):
        self.column = exprs[0]
        self.lhs = self.column
        if len(exprs) > 1:
            self.flag = exprs[1]
            self.rhs = self.flag

    def resolve_expression(
        self, query=None, allow_joins=True, reuse=None,
        summarize=False, for_save=False,
    ):
        clone = copy.copy(self)
        clone.column = self.column.resolve_expression(
            query, allow_joins, reuse, summarize, for_save,
        )
        flag = self.flag
        if hasattr(flag, 'resolve_expression'):
            flag = flag.resolve_expression(
                query, allow_joins, reuse, summarize, for_save,
            )
        clone.flag = flag
        clone.lhs = clone.column
        clone.rhs = clone.flag
        return clone


class SqlTrue(Lookup):
    """Boolean literal ``TRUE``. No column and no placeholder.

    ``TRUE`` is the standard boolean literal on SQLite, PostgreSQL, and
    MySQL, which are the engines that render policy SQL.
    """

    lookup_name = 'sql_true'
    prepare_rhs = False

    def __init__(self):
        Expression.__init__(self, output_field=BooleanField())
        self.lhs = Value(True, output_field=BooleanField())
        self.rhs = True
        self.bilateral_transforms = []

    def get_prep_lookup(self):
        return True

    def as_sql(self, compiler, connection):
        return 'TRUE', ()

    def get_source_expressions(self):
        return []

    def set_source_expressions(self, exprs):
        if exprs:
            raise TypeError('SqlTrue has no source expressions.')

    def resolve_expression(
        self, query=None, allow_joins=True, reuse=None,
        summarize=False, for_save=False,
    ):
        return copy.copy(self)
