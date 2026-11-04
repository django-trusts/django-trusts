"""SQL functions for condition builders.

Each public class is Django's function plus ``ComparableMixin``.
The mixin compares by returning a condition node, so the function may
sit on either side. The objects last only while the builder runs.
Registration lowers them to stored nodes, and the compiler emits
Django's own functions.
"""

from django.db.models import functions

from trusts.plan.grammar import Symbol, Tree, symbol_path, unsupported


class ComparableMixin(object):
    """Comparisons that record a condition node instead of a bool."""

    def __eq__(self, other):
        return _comparison('eq', self, other)

    def __ne__(self, other):
        return _comparison('ne', self, other)

    def __lt__(self, other):
        return _comparison('lt', self, other)

    def __le__(self, other):
        return _comparison('le', self, other)

    def __gt__(self, other):
        return _comparison('gt', self, other)

    def __ge__(self, other):
        return _comparison('ge', self, other)

    def __hash__(self):
        return super().__hash__()


def _comparison(kind, left, right):
    return Tree(kind, left=_side(left), right=_side(right))


def _side(value):
    """One comparison operand. Symbols stay wrapped until lowering."""
    if isinstance(value, Tree):
        raise unsupported('Comparing a condition')
    if isinstance(value, Symbol) and not symbol_path(value):
        raise unsupported(
            'A root without a field', hint='Name a field, for example o.owner.',
        )
    return Tree('const', value=value)


class Now(ComparableMixin, functions.Now):
    pass


class Lower(ComparableMixin, functions.Lower):
    pass


class Coalesce(ComparableMixin, functions.Coalesce):
    pass
