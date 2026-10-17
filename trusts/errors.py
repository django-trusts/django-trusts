"""Configuration and permission-condition errors.

``TrustsConfigurationError`` and ``TrustsCompilerError`` are re-exported
from ``trusts.core``. ``trusts.conditions`` re-exports the
permission-condition errors as Core's own public surface. That package
is not a compatibility shim for django-trusts-zero: Zero imports
``PermissionConditionNotQueryable`` from here and carries its own
``permission_has_condition``.
"""


class TrustsConfigurationError(Exception):
    """Malformed or unsupported ``TrustsRegistry`` registration."""


class TrustsCompilerError(TrustsConfigurationError):
    """Configured Trusts backend is missing or has a malformed query compiler."""


class PermissionConditionError(Exception):
    """Unsupported or malformed declarative permission condition.

    Fail closed: never ignore the condition and return the underlying grant.
    """


class PermissionConditionBooleanError(PermissionConditionError):
    """Raised when a symbolic condition is truth-tested (``and`` / ``or`` / ``not``)."""


class PermissionConditionUnsupported(PermissionConditionError):
    """Raised for operations outside the V1 grammar (calls, indexing, arithmetic)."""


class PermissionConditionNotQueryable(ValueError):
    """Raised when a SQL list/create filter cannot compile a ``:condition``.

    Generic core exception. Import this name from ``trusts.errors``.
    """
