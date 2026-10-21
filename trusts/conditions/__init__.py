"""Public permission-condition API.

Register named filters as builders on the configured backend
(``add_named_filter``). The application-facing surface is the condition
error and the permission-code helpers.

``from trusts.conditions import Expr`` raises ``ImportError``.
"""

from trusts.plan.conditions import (
    permission_condition_code,
    permission_has_condition,
)
from trusts.errors import PermissionConditionError

__all__ = [
    'PermissionConditionError',
    'permission_condition_code',
    'permission_has_condition',
]
