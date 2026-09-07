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


def get_entity_model():
    """
    Returns the Entity model. By default it is
    """

    try:
        return django_apps.get_model(ENTITY_MODEL_NAME)
    except ValueError:
        raise ImproperlyConfigured("TRUSTS_ENTITY_MODEL or AUTH_USER_MODEL must be of the form 'app_label.model_name'")
    except LookupError:
        raise ImproperlyConfigured(
            "TRUSTS_ENTITY_MODEL or AUTH_USER_MODEL refers to model '%s' that has not been installed" % ENTITY_MODEL_NAME
        )


def get_group_model():
    """
    Returns the Group model
    """
    try:
        return django_apps.get_model(GROUP_MODEL_NAME)
    except ValueError:
        raise ImproperlyConfigured("TRUSTS_GROUP_MODEL must be of the form 'app_label.model_name'")
    except LookupError:
        raise ImproperlyConfigured(
            "TRUSTS_GROUP_MODEL refers to model '%s' that has not been installed" % GROUP_MODEL_NAME
        )


def get_permission_model():
    """
    Returns the Permission model
    """
    try:
        return django_apps.get_model(PERMISSION_MODEL_NAME)
    except ValueError:
        raise ImproperlyConfigured("TRUSTS_PERMISSION_MODEL must be of the form 'app_label.model_name'")
    except LookupError:
        raise ImproperlyConfigured(
            "TRUSTS_PERMISSION_MODEL refers to model '%s' that has not been installed" % PERMISSION_MODEL_NAME
        )
