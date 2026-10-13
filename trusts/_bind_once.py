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

from django.db.models import Exists, IntegerField, Value
from django.db.models.expressions import Expression


BIND_ALIAS = 'trusts_bind'

_sheet = ContextVar('trusts_bind_sheet', default=None)


def sql_bind_once():
    """Return whether one statement binds each distinct value once.

    ``TRUSTS_SQL_BIND_ONCE`` defaults to true. Set it to false to leave
    every placeholder where the compiler emitted it and to skip the
    one-row ``trusts_bind`` table. The ``EXISTS`` marker stays the
    literal ``1`` either way.
    """
    from django.conf import settings

    return getattr(settings, 'TRUSTS_SQL_BIND_ONCE', True)


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
    if not sql_bind_once():
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
    if not sql_bind_once():
        return queryset
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
