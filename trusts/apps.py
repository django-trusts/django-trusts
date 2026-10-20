"""Recorder and catalog maps. ``TrustsImplementationConfig.ready`` builds once.

Core is not the ``trusts`` app label (Zero owns that). This config's
module name is ``trusts.apps`` and its label is ``trusts_lifecycle``.
The class exists so Django calls ``ready()``. That call freezes the
listed recorders and builds catalogs. It does not own backends, paths,
or families. The path label is the dotted ``AUTHENTICATION_BACKENDS``
string, read once in that sweep. Family is the backend class's
``family`` attribute.
"""

import django.apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import options as model_options


def _ensure_permission_conditions_option():
    """Register ``Meta.permission_conditions`` once, before host models load."""
    names = model_options.DEFAULT_NAMES
    if 'permission_conditions' in names:
        return
    if isinstance(names, tuple):
        model_options.DEFAULT_NAMES = names + ('permission_conditions',)
    else:
        names.append('permission_conditions')


_ensure_permission_conditions_option()

recorders = {}
catalogs = {}
_user_model = None
object_blind_backends = frozenset()


def user_model():
    """User model resolved once in ``TrustsImplementationConfig.ready``."""
    return _user_model


def store_user_model(model):
    global _user_model
    _user_model = model


def store_object_blind_backends(classes):
    global object_blind_backends
    object_blind_backends = frozenset(classes)


def installed_object_blind_backends():
    """Object-blind backend classes stored by ``TrustsImplementationConfig.ready``."""
    return object_blind_backends


class TrustsImplementationConfig(django.apps.AppConfig):
    """One sweep after other apps have registered on their recorders.

    List this config last. ``name`` is this module so the library is
    not installed under the ``trusts`` app label. Subclasses do not
    declare a backend path: the same application writes the backend
    class and lists it in ``AUTHENTICATION_BACKENDS``.
    """

    name = 'trusts.apps'
    label = 'trusts_lifecycle'
    default = False

    def ready(self):
        # ``django.contrib.auth.backends`` calls ``get_user_model()``
        # while it loads. Importing it at module level from any module
        # on the path ``trusts.query`` → ``trusts.plan.users`` →
        # ``trusts.apps`` cycles a custom user model that imports
        # ``trusts.query`` during its own import. ``ready()`` runs
        # after the user model is installed.
        from django.contrib.auth.backends import (
            AllowAllUsersModelBackend,
            AllowAllUsersRemoteUserBackend,
            ModelBackend,
            RemoteUserBackend,
        )
        from trusts.backends import TrustModelBackendMixin
        from trusts.compile.factory import build_configured_catalogs
        from trusts.inspect.commands import install_policy_commands
        import trusts.inspect.checks  # noqa: F401

        install_policy_commands()
        model = get_user_model()
        store_user_model(model)
        store_object_blind_backends((
            ModelBackend,
            AllowAllUsersModelBackend,
            RemoteUserBackend,
            AllowAllUsersRemoteUserBackend,
        ))
        build_configured_catalogs(
            tuple(settings.AUTHENTICATION_BACKENDS),
            model,
            TrustModelBackendMixin,
        )
