"""Mixin app for modules under ``tests.core``.

The along jobs cannot install ``TestsConfig``. That label is
``trusts_tests``, and an unmigrated app with that label is synced before
``auth`` on PostgreSQL and MySQL. This config has no models. It exists
so a backend or model defined in ``tests.core`` still has an owning
``TrustsConfigMixin``.
"""

import trusts.apps as trusts_apps


class AlongCoreConfig(trusts_apps.TrustsConfigMixin):
    name = 'tests.core'
    label = 'along_core'
    default = False
    default_auto_field = 'django.db.models.AutoField'
