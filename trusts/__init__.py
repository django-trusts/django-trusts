from django.conf import settings
from django.apps import apps as django_apps
from django.core.exceptions import ImproperlyConfigured


ENTITY_MODEL_NAME = getattr(settings, 'TRUSTS_ENTITY_MODEL',
        getattr(settings, 'AUTH_USER_MODEL', 'auth.User')
    )

DEFAULT_SETTLOR = getattr(settings, 'TRUSTS_DEFAULT_SETTLOR', None)

ALLOW_NULL_SETTLOR = getattr(settings, 'TRUSTS_ALLOW_NULL_SETTLOR', DEFAULT_SETTLOR is None)

ROOT_PK = getattr(settings, 'TRUSTS_ROOT_PK', 1)

AUTH_GROUP_MODEL = 'auth.Group'
AUTH_PERMISSION_MODEL = 'auth.Permission'

# Historical 0001_initial / 0002_trustgroup import these names. They are
# pinned to Django's auth models. TRUSTS_GROUP_MODEL / TRUSTS_PERMISSION_MODEL
# no longer select a field target (deprecated in 1.0; removed in 1.1.0).
GROUP_MODEL_NAME = AUTH_GROUP_MODEL
PERMISSION_MODEL_NAME = AUTH_PERMISSION_MODEL


def _live_entity_model_name():
    return getattr(
        settings,
        'TRUSTS_ENTITY_MODEL',
        getattr(settings, 'AUTH_USER_MODEL', 'auth.User'),
    )


def _live_group_model_name():
    """Live ``TRUSTS_GROUP_MODEL`` if present, else ``auth.Group``.

    Diagnostics and fail-closed only. Field targets stay on
    ``GROUP_MODEL_NAME`` (``auth.Group``).
    """
    return getattr(settings, 'TRUSTS_GROUP_MODEL', AUTH_GROUP_MODEL)


def _live_permission_model_name():
    """Live ``TRUSTS_PERMISSION_MODEL`` if present, else ``auth.Permission``.

    Diagnostics and fail-closed only. Field targets stay on
    ``PERMISSION_MODEL_NAME`` (``auth.Permission``).
    """
    return getattr(settings, 'TRUSTS_PERMISSION_MODEL', AUTH_PERMISSION_MODEL)


def group_model_setting_overridden():
    """True when ``TRUSTS_GROUP_MODEL`` is explicitly configured."""
    return settings.is_overridden('TRUSTS_GROUP_MODEL')


def permission_model_setting_overridden():
    """True when ``TRUSTS_PERMISSION_MODEL`` is explicitly configured."""
    return settings.is_overridden('TRUSTS_PERMISSION_MODEL')


def _get_configured_model(name, value_error, lookup_error):
    try:
        return django_apps.get_model(name)
    except ValueError:
        raise ImproperlyConfigured(value_error)
    except LookupError:
        raise ImproperlyConfigured(lookup_error % name)


def get_entity_model():
    """Return the model named by live ``TRUSTS_ENTITY_MODEL`` / ``AUTH_USER_MODEL``.

    Field ``to=`` targets stay on the import-time ``ENTITY_MODEL_NAME`` snapshot.
    Runtime grants and queries must call ``supported_entity_contract()`` and
    use ``AUTH_USER_MODEL``; a silenced ``trusts.E003`` does not authorize a
    non-user entity.
    """
    name = _live_entity_model_name()
    return _get_configured_model(
        name,
        "TRUSTS_ENTITY_MODEL or AUTH_USER_MODEL must be of the form 'app_label.model_name'",
        "TRUSTS_ENTITY_MODEL or AUTH_USER_MODEL refers to model '%s' that has not been installed",
    )


def get_group_model():
    """Return Django ``auth.Group``.

    ``TRUSTS_GROUP_MODEL`` is deprecated and does not select a model.
    Runtime still fail-closes when that setting names anything else.
    """
    from django.contrib.auth.models import Group

    return Group


def get_permission_model():
    """Return Django ``auth.Permission``.

    ``TRUSTS_PERMISSION_MODEL`` is deprecated and does not select a model.
    Runtime still fail-closes when that setting names anything else.
    """
    from django.contrib.auth.models import Permission

    return Permission


def lookup_group_model_setting():
    """Resolve the live ``TRUSTS_GROUP_MODEL`` string for diagnostics.

    Does not change runtime Group resolution. Used by ``trusts.E004``.
    """
    name = _live_group_model_name()
    return _get_configured_model(
        name,
        "TRUSTS_GROUP_MODEL must be of the form 'app_label.model_name'",
        "TRUSTS_GROUP_MODEL refers to model '%s' that has not been installed",
    )


def lookup_permission_model_setting():
    """Resolve the live ``TRUSTS_PERMISSION_MODEL`` string for diagnostics.

    Does not change runtime Permission resolution. Used by ``trusts.E005``.
    """
    name = _live_permission_model_name()
    return _get_configured_model(
        name,
        "TRUSTS_PERMISSION_MODEL must be of the form 'app_label.model_name'",
        "TRUSTS_PERMISSION_MODEL refers to model '%s' that has not been installed",
    )


def supported_entity_contract():
    """True when settlor/trustee settings and the User model are the same principal.

    Checks the import-time field target and the live setting. Either mismatch
    is fail-closed: silenced ``trusts.E003`` must not reach grants or queries.
    """
    from django.contrib.auth import get_user_model

    user_label = getattr(settings, 'AUTH_USER_MODEL', 'auth.User')
    if ENTITY_MODEL_NAME != user_label:
        return False
    try:
        return get_entity_model() is get_user_model()
    except ImproperlyConfigured:
        return False


def supported_group_contract():
    """True when no unsupported ``TRUSTS_GROUP_MODEL`` is configured.

    Field targets and ``get_group_model()`` are always ``auth.Group``.
    A leftover non-``auth.Group`` setting still fail-closes so a silenced
    ``trusts.E004`` cannot enable the discarded swap.
    """
    if GROUP_MODEL_NAME != AUTH_GROUP_MODEL:
        return False
    return _live_group_model_name() == AUTH_GROUP_MODEL


def supported_permission_contract():
    """True when no unsupported ``TRUSTS_PERMISSION_MODEL`` is configured.

    Field targets and ``get_permission_model()`` are always ``auth.Permission``.
    A leftover non-``auth.Permission`` setting still fail-closes so a
    silenced ``trusts.E005`` cannot enable the discarded swap.
    """
    if PERMISSION_MODEL_NAME != AUTH_PERMISSION_MODEL:
        return False
    return _live_permission_model_name() == AUTH_PERMISSION_MODEL
