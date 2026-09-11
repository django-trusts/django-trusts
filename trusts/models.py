# trusts/models.py — 1.x compatibility shim. Not a Django model module.
# AppConfig.import_models() imports this file. It must not define Model
# subclasses and must not import Zero at import time. Zero is imported
# only when a name in ``__all__`` is accessed (#54 r9).

__all__ = (
    'Content', 'Junction', 'Trust', 'TrustUserPermission', 'TrustGroup',
    'TrustGroupPermission', 'Role', 'RolePermission', 'ReadonlyFieldsMixin',
    'PermissionConditionNotQueryable',
)

# Explicit names that load Zero. ``__all__`` is the r9 documented set;
# the extras are C1 public names still owned by Zero (managers, queryset,
# junction hook). Unknown names raise AttributeError without importing Zero.
_COMPAT_NAMES = frozenset(__all__) | frozenset((
    'TrustManager',
    'ContentManager',
    'ContentQuerySet',
    'register_content_junction',
    'legacy_permission_callbacks_allowed',
    'permission_has_condition',
))

_ZERO_MODELS = None
_ZERO_ERR = (
    "django-trusts kernel no longer ships the 0.x schema. Install "
    "django-trusts-zero and add 'trusts.zero.apps.ZeroConfig' to "
    "INSTALLED_APPS, or import from trusts.zero.models."
)


def _zero_models():
    global _ZERO_MODELS
    if _ZERO_MODELS is None:
        try:
            from trusts.zero import models as zero_models
        except ImportError as e:
            raise ImportError(_ZERO_ERR) from e
        _ZERO_MODELS = zero_models
    return _ZERO_MODELS


def __getattr__(name):
    # populate does not walk attributes. Non-legacy names must not load Zero.
    if name not in _COMPAT_NAMES:
        raise AttributeError(
            'module %r has no attribute %r' % (__name__, name)
        )
    return getattr(_zero_models(), name)


def __dir__():
    return sorted(set(globals()) | _COMPAT_NAMES)
