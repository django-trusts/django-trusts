"""Public permission-condition API (issue #142 Stage B).

Register named filters as builders on the configured backend
(``add_named_filter``). The application-facing surface is only the
condition exceptions and permission-code helpers.

Construction nodes, ref factories, reserved ``Query`` / ``TQ``, and
registry/compiler store types live in ``trusts.conditions._ir``.
``from trusts.conditions import Expr`` and
``from trusts.conditions import ConditionRegistry`` raise
``ImportError``.
"""

from trusts.conditions._ir import (
    PermissionConditionBooleanError,
    PermissionConditionError,
    PermissionConditionNotQueryable,
    PermissionConditionUnsupported,
    permission_condition_code,
    permission_has_condition,
)

__all__ = [
    'PermissionConditionBooleanError',
    'PermissionConditionError',
    'PermissionConditionNotQueryable',
    'PermissionConditionUnsupported',
    'permission_condition_code',
    'permission_has_condition',
]
