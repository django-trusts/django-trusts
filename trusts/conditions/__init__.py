"""Public permission-condition API (issue #142 Stage B).

Application code registers named conditions as builders::

    handle.register_permission_condition(
        Document, "non_confidential", lambda u, p, o: o.confidential != True,
    )

Construction nodes (``Expr``, refs, constants, comparison/boolean
trees, ``condition_refs``, reserved ``Query`` / ``TQ``) live in the
private compiler module ``trusts.conditions._ir``. They are not part of
this public surface.
"""

from trusts.conditions._ir import (
    ConditionLookup,
    ConditionRecord,
    ConditionRegistry,
    PermissionConditionBooleanError,
    PermissionConditionError,
    PermissionConditionNotQueryable,
    PermissionConditionUnsupported,
    RegistryConditionLookup,
    _ensure_permission_conditions_option,
    obsolete_legacy_callback_setting_enabled,
    permission_condition_code,
    permission_has_condition,
)

__all__ = [
    'ConditionLookup',
    'ConditionRecord',
    'ConditionRegistry',
    'PermissionConditionBooleanError',
    'PermissionConditionError',
    'PermissionConditionNotQueryable',
    'PermissionConditionUnsupported',
    'RegistryConditionLookup',
    'obsolete_legacy_callback_setting_enabled',
    'permission_condition_code',
    'permission_has_condition',
]

_REMOVED_CONSTRUCTION_NAMES = frozenset((
    'And',
    'Const',
    'Eq',
    'Expr',
    'ModelIdentity',
    'Ne',
    'Or',
    'Query',
    'Ref',
    'TQ',
    '_Ordering',
    'as_node',
    'condition_refs',
    'is_predicate',
    'object_ref',
    'permission_ref',
    'principal_ref',
))


def __getattr__(name):
    if name in _REMOVED_CONSTRUCTION_NAMES:
        raise AttributeError(
            'cannot import name %r from %r (construction nodes are private; '
            'register a builder on BackendHandle.register_permission_condition)'
            % (name, __name__)
        )
    raise AttributeError('module %r has no attribute %r' % (__name__, name))
