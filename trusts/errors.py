"""Configuration and permission-condition errors."""

from django.core.exceptions import ImproperlyConfigured


class TrustsConfigurationError(Exception):
    """Malformed or unsupported registration."""


class TrustsCompilerError(TrustsConfigurationError):
    """Configured Trusts backend is missing or has a malformed query compiler."""


class TrustsMixinRequired(ImproperlyConfigured):
    """The backend's app config does not extend TrustsConfigMixin."""


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
