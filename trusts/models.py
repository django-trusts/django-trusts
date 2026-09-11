# trusts/models.py — 1.x compatibility shim. Not a Django model module.
# AppConfig.import_models() imports this file. It must not define Model
# subclasses and must not import Zero at import time.

__all__ = (
    'Content', 'Junction', 'Trust', 'TrustUserPermission', 'TrustGroup',
    'TrustGroupPermission', 'Role', 'RolePermission', 'ReadonlyFieldsMixin',
    'PermissionConditionNotQueryable',
)

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
    # populate does not walk attributes; GH-only never calls this for Trust.
    return getattr(_zero_models(), name)


def __dir__():
    names = set(globals()) | set(__all__)
    try:
        names.update(dir(_zero_models()))
    except ImportError:
        pass
    return sorted(names)
