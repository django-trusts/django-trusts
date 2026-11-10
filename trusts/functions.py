"""SQL functions for condition builders.

``Now``, ``Lower``, and ``Coalesce`` are Django's functions plus
``ComparableMixin``. The mixin compares by returning a condition node.
``Reachable`` asks whether the join reached the row named by the last
relation. It is neither SQL ``EXISTS`` nor a NULL check. The objects
last only while the builder runs. Registration lowers them to stored
nodes, and the compiler emits SQL.
"""

from django.db.models import functions

from trusts.plan.grammar import REACHABLE_KIND, REACHABLE_NAME, Tree, unsupported


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


class Reachable(object):
    """Whether the join reached the row named by the last relation.

    This is neither SQL ``EXISTS`` nor a NULL check. ``Reachable(a.b)``
    is true when the row named by ``b`` was joined, and false when that
    join missed. A terminal forward foreign key is followed:
    ``Reachable(c.dept.unit)`` is false when ``unit`` is NULL or the key
    does not match a row. ``~Reachable(path)`` is that test negated.
    The result is true or false, never unknown.

    Registration accepts a path that ends in a forward foreign key or a
    reverse one-to-one, for example ``Reachable(c.dept)`` and
    ``Reachable(c.dept.unit)``. A root alone (``Reachable(c)``,
    ``Reachable(u)``, ``Reachable(t)``) and a path that ends in a column
    (``c.name``, ``c.dept.name``, ``c.dept.unit_id``, ``c.dept.id``)
    raise ``PermissionConditionError``. An attname in the middle of a
    path (``c.dept_id.unit``) is rejected, as are a reverse foreign key
    and a many-to-many.

    The public name is ``REACHABLE_NAME``. The stored node kind is
    ``reachable``.
    """

    def __new__(cls, arg):
        from trusts.plan.grammar import (
            Symbol,
            Tree,
            symbol_path,
            symbol_root,
            unsupported,
        )
        if isinstance(arg, Symbol) and not symbol_path(arg):
            from trusts.errors import PermissionConditionError
            if symbol_root(arg) == 'permission':
                raise PermissionConditionError(
                    '%s() does not apply to a permission field.' % REACHABLE_NAME
                )
            raise PermissionConditionError(
                '%s() needs a relation. A root alone is not a path.'
                % REACHABLE_NAME
            )
        if not isinstance(arg, Symbol):
            raise unsupported(
                '%s() on a value that is not a field path' % REACHABLE_NAME,
                hint='Name a relation, for example %s(o.dept).' % REACHABLE_NAME,
            )
        return Tree(
            REACHABLE_KIND,
            item=Tree(
                'field', root=symbol_root(arg), path=symbol_path(arg),
            ),
        )
