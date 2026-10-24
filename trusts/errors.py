"""Configuration and permission-condition errors."""

from django.core.exceptions import ImproperlyConfigured


class TrustsConfigurationError(Exception):
    """Malformed or unsupported registration."""


class TrustsMixinRequired(ImproperlyConfigured):
    """The backend's app config does not extend TrustsConfigMixin."""


class PermissionConditionError(TrustsConfigurationError):
    """Malformed condition grammar on every registration surface.

    Fail closed: never ignore the condition and return the underlying grant.
    """
