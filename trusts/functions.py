"""SQL functions for condition builders.

``Now``, ``Lower``, and ``Coalesce`` are Django's functions plus
``ComparableMixin``. The mixin compares by returning a condition node.
``Exists`` asks whether the row that owns a field was joined. The
objects last only while the builder runs. Registration lowers them to
stored nodes, and the compiler emits SQL.
"""

from django.db.models import functions

from trusts.plan.grammar import EXISTS_KIND, EXISTS_NAME, Tree, unsupported


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

    ``Exists(dept.unit)`` is true when ``dept`` was joined, even when
    ``unit`` is NULL, and false when ``dept`` was not joined. The same
    rule makes ``Exists(room.desk)`` true when the room row was reached
    even if ``room.desk`` is NULL. A dangling key is still that column's
    value: ``Exists`` does not follow it.
    ``Exists(dept.unit.code)`` is false when the unit row cannot be
    joined. The result is true or false, never unknown.
    ``~Exists(path)`` is the no-row test.

    The public name is ``EXISTS_NAME``. A later rename changes that
    constant and this class together.
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
                '%s() on a value that is not a field path' % EXISTS_NAME,
                hint='Name a field, for example %s(o.dept.unit).' % EXISTS_NAME,
            )
        return Tree(
            EXISTS_KIND,
            item=Tree(
                'field', root=symbol_root(arg), path=symbol_path(arg),
            ),
        )
