"""Public alias for django-trusts declarative condition builders.

The Django app package remains ``trusts``. Import ``Query``, ``TQ``, and
``condition_refs`` from here or from ``trusts.conditions``.
"""

from trusts.conditions import Expr, Query, TQ, condition_refs

__all__ = ['Expr', 'Query', 'TQ', 'condition_refs']
