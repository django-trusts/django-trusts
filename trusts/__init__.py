from django.conf import settings
from django.apps import apps as django_apps
from django.core.exceptions import ImproperlyConfigured


ENTITY_MODEL_NAME = getattr(settings, 'TRUSTS_ENTITY_MODEL',
        getattr(settings, 'AUTH_USER_MODEL', 'auth.User')
    )
GROUP_MODEL_NAME = getattr(settings, 'TRUSTS_GROUP_MODEL', 'auth.Group')

PERMISSION_MODEL_NAME = getattr(settings, 'TRUSTS_PERMISSION_MODEL', 'auth.Permission')

DEFAULT_SETTLOR = getattr(settings, 'TRUSTS_DEFAULT_SETTLOR', None)

ALLOW_NULL_SETTLOR = getattr(settings, 'TRUSTS_ALLOW_NULL_SETTLOR', DEFAULT_SETTLOR is None)

ROOT_PK = getattr(settings, 'TRUSTS_ROOT_PK', 1)

AUTH_GROUP_MODEL = 'auth.Group'
AUTH_PERMISSION_MODEL = 'auth.Permission'


def _live_entity_model_name():
    return getattr(
        settings,
        'TRUSTS_ENTITY_MODEL',
        getattr(settings, 'AUTH_USER_MODEL', 'auth.User'),
    )


def _live_group_model_name():
    return getattr(settings, 'TRUSTS_GROUP_MODEL', AUTH_GROUP_MODEL)


def _live_permission_model_name():
    return getattr(settings, 'TRUSTS_PERMISSION_MODEL', AUTH_PERMISSION_MODEL)


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
    """Return the model named by live ``TRUSTS_GROUP_MODEL``.

    Runtime must not grant or query through this model unless
    ``supported_group_contract()`` is true (``auth.Group``).
    """
    name = _live_group_model_name()
    return _get_configured_model(
        name,
        "TRUSTS_GROUP_MODEL must be of the form 'app_label.model_name'",
        "TRUSTS_GROUP_MODEL refers to model '%s' that has not been installed",
    )


def get_permission_model():
    """Return the model named by live ``TRUSTS_PERMISSION_MODEL``.

    Runtime must not grant or query through this model unless
    ``supported_permission_contract()`` is true (``auth.Permission``).
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
    """True when group settings and the field graph are ``auth.Group``.

    Silenced ``trusts.E004`` must not run ``group__user`` against another model.
    """
    from django.contrib.auth.models import Group

    if GROUP_MODEL_NAME != AUTH_GROUP_MODEL:
        return False
    try:
        return get_group_model() is Group
    except ImproperlyConfigured:
        return False


def supported_permission_contract():
    """True when permission settings and the field graph are ``auth.Permission``.

    Silenced ``trusts.E005`` must not resolve or grant through another model.
    """
    from django.contrib.auth.models import Permission

    if PERMISSION_MODEL_NAME != AUTH_PERMISSION_MODEL:
        return False
    try:
        return get_permission_model() is Permission
    except ImproperlyConfigured:
        return False
