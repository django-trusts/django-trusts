"""SQL functions for condition builders.

``Now``, ``Lower``, and ``Coalesce`` are Django's functions plus
``ComparableMixin``. The mixin compares by returning a condition node.
``Exists`` asks whether the row that owns a field was joined. The
objects last only while the builder runs. Registration lowers them to
stored nodes, and the compiler emits SQL.
"""

from django.db.models import functions

from trusts.plan.grammar import Tree, unsupported


def _comparison(kind):
    def compare(self, other):
        if isinstance(other, Tree):
            raise unsupported('Comparing a condition')
        return Tree(
            kind, left=Tree('const', value=self),
            right=Tree('const', value=other),
        )

    return compare


class ComparableMixin(object):
    """Comparisons that record a condition node instead of a bool."""

    __eq__ = _comparison('eq')
    __ne__ = _comparison('ne')
    __lt__ = _comparison('lt')
    __le__ = _comparison('le')
    __gt__ = _comparison('gt')
    __ge__ = _comparison('ge')

    def __hash__(self):
        return super().__hash__()


class Now(ComparableMixin, functions.Now):
    pass


class Lower(ComparableMixin, functions.Lower):
    pass


class Coalesce(ComparableMixin, functions.Coalesce):
    pass


class Exists(object):
    """Whether the row that owns a field was joined.

    ``Exists(dept.unit)`` is true when ``dept`` was joined and false when
    it was not, including a dangling foreign key. ``unit`` may be NULL.
    The result is true or false, never unknown. ``~Exists(path)`` is the
    no-row test.
    """

    def __new__(cls, arg):
        from trusts.plan.grammar import (
            Symbol,
            Tree,
            symbol_path,
            symbol_root,
            unsupported,
        )
        if not isinstance(arg, Symbol) or not symbol_path(arg):
            raise unsupported(
                'Exists() on a value that is not a field path',
                hint='Name a field, for example Exists(o.dept.unit).',
            )
        return Tree(
            'exists',
            item=Tree(
                'field', root=symbol_root(arg), path=symbol_path(arg),
            ),
        )
