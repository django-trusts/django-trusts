"""``TrustsImplementationConfig.ready`` freezes recorders and builds catalogs."""

import django.apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import options as model_options

import trusts.plan.standards as standards


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


class TrustsImplementationConfig(django.apps.AppConfig):
    """One sweep after other apps have registered on their recorders.

    List this config last. ``name`` is this module so the library is
    not registered under the ``trusts`` app label.
    """

    name = 'trusts.apps'
    label = 'trusts_lifecycle'
    default = False

    def ready(self):
        # These imports construct Django models (``auth.Permission``,
        # ``get_user_model()``). ``Apps.populate`` phase 1 imports this
        # module before the registry is ready, so they cannot sit at
        # module level:
        from trusts.compile.factory import build_configured_catalogs
        from trusts.inspect.commands import install_policy_commands
        import trusts.inspect.checks  # noqa: F401

        install_policy_commands()
        model = get_user_model()
        standards.user_model = model
        build_configured_catalogs(
            tuple(settings.AUTHENTICATION_BACKENDS),
            model,
        )
