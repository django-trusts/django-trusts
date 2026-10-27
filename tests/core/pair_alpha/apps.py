import trusts.apps as trusts_apps


class PairAlphaConfig(trusts_apps.TrustsConfigMixin):
    """Content app A. Its backend reads this config's catalog."""

    name = 'tests.core.pair_alpha'
    label = 'pair_alpha'
    default = False
    default_auto_field = 'django.db.models.AutoField'

    def ready(self):
        from tests.core.pair_alpha.backends import PairAlphaBackend
        PairAlphaBackend().get_registry()
        super().ready()
