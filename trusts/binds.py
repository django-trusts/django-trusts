"""Inquiry values as ordinary SQL placeholders.

Columns that already belong to the outer statement stay correlated with
``OuterRef`` at the call site. A user id, permission id, content-type
name, or ``allow_inactive`` flag is not one of those columns, so each
use is its own ``Value``. Django compiles each ``Value`` to its own
placeholder. This module does not add a row to ``FROM`` and does not
write ``alias_map``, ``table_map``, or ``alias_refcount``.
"""

import copy
from contextlib import contextmanager

from django.db.models import BooleanField, Exists, IntegerField, Value
from django.db.models.expressions import Expression
from django.db.models.lookups import Lookup


class LabeledValue(Value):
    """One ``Value`` whose lockfile label is the inquiry role.

    The SQL is still a single placeholder. Repeating the value repeats
    the placeholder. ``trusts_bind`` and ``trusts_hint`` are labels for
    the policy lock, not query aliases.
    """

    def __init__(self, value, output_field=None, *, bind=None, hint=None):
        super().__init__(value, output_field=output_field)
        self.trusts_bind = bind
        self.trusts_hint = hint

    def as_sql(self, compiler, connection):
        # ``Value`` casts some fields (``CAST(%s AS REAL)``). The policy
        # formatter accepts a bare placeholder, which is what the statement
        # binds. ``NULL`` stays SQL, not a placeholder.
        value = self.value
        field = self._output_field_or_none
        if field is not None:
            value = field.get_db_prep_value(value, connection=connection)
        if value is None:
            return 'NULL', ()
        return '%s', (value,)

    def as_sqlite(self, compiler, connection, **extra_context):
        # ``Value.as_sqlite`` wraps decimals in ``CAST(... AS REAL)``.
        # The policy formatter records a bare placeholder.
        return self.as_sql(compiler, connection)


def hoist(value, output_field, *, bind=None, hint=None):
    """Return an ``OuterRef`` unchanged, or a labeled ``Value``.

    An expression is already correlated to whatever query owns it.
    A concrete inquiry value becomes a placeholder at every use.
    """
    if hasattr(value, 'resolve_expression') and not hasattr(value, '_meta'):
        return value
    if bind is None and hint is None:
        return value
    return LabeledValue(value, output_field, bind=bind, hint=hint)


@contextmanager
def bind_scope():
    """Inquiry scope. Nested builders share no bind row, because there is none."""
    yield None


def seal(queryset):
    """Return ``queryset``. There is no bind row to attach."""
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
