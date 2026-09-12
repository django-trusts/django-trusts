"""Public permission-condition API (issue #142 Stage B).

Register named conditions as builders on
``BackendHandle.register_permission_condition``. Construction nodes
(``Expr``, refs, constants, comparison/boolean nodes, ``Query`` /
``TQ``, and ref factories) live in ``trusts.conditions._ir`` and are
not part of this surface.

``from trusts.conditions import Expr`` and
``from django_trusts import condition_refs`` raise ``ImportError``.
"""

from trusts.conditions._ir import (
    ConditionLookup,
    ConditionRecord,
    ConditionRegistry,
    ModelIdentity,
    PermissionConditionBooleanError,
    PermissionConditionError,
    PermissionConditionNotQueryable,
    PermissionConditionUnsupported,
    RegistryConditionLookup,
    compile_expression_q,
    evaluate_registered_expression,
    obsolete_legacy_callback_setting_enabled,
    permission_condition_code,
    permission_has_condition,
    validate_expression,
    _ensure_permission_conditions_option,
)

__all__ = [
    'ConditionLookup',
    'ConditionRecord',
    'ConditionRegistry',
    'ModelIdentity',
    'PermissionConditionBooleanError',
    'PermissionConditionError',
    'PermissionConditionNotQueryable',
    'PermissionConditionUnsupported',
    'RegistryConditionLookup',
    'compile_expression_q',
    'evaluate_registered_expression',
    'obsolete_legacy_callback_setting_enabled',
    'permission_condition_code',
    'permission_has_condition',
    'validate_expression',
]
