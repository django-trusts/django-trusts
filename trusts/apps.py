"""``TrustsImplementationConfig.ready`` freezes recorders and builds catalogs."""

import django.apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.db.models import options as model_options

import trusts.plan.standards as standards

# Populate imports this module before any models.
if 'permission_conditions' not in model_options.DEFAULT_NAMES:
    _names = model_options.DEFAULT_NAMES
    if isinstance(_names, tuple):
        model_options.DEFAULT_NAMES = _names + ('permission_conditions',)
    else:
        _names.append('permission_conditions')


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
