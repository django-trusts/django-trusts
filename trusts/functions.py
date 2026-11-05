"""SQL functions for condition builders.

Each public class is Django's function plus ``ComparableMixin``.
The mixin compares by returning a condition node, so the function may
sit on either side. The objects last only while the builder runs.
Registration lowers them to stored nodes, and the compiler emits
Django's own functions.
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
