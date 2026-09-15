"""Import-time ``Meta.permission_conditions`` registration (zero SQL).

This module must not import ``trusts.core`` or ``trusts.conditions``.
``trusts.apps`` imports it so Django can construct models that declare
the option when a host loads ``TrustsImplementationConfig``. Applications
do not import this module.
"""

from django.db.models import options as model_options


def _ensure_permission_conditions_option():
    """Register generic ``Meta.permission_conditions`` idempotently.

    Must run at import, before Django constructs participating model
    classes. Repeated import/setup must not duplicate the name.
    """
    names = model_options.DEFAULT_NAMES
    if 'permission_conditions' in names:
        return
    if isinstance(names, tuple):
        model_options.DEFAULT_NAMES = names + ('permission_conditions',)
    else:
        names.append('permission_conditions')


_ensure_permission_conditions_option()
