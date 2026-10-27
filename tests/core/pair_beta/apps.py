import trusts.apps as trusts_apps


class PairBetaConfig(trusts_apps.TrustsConfigMixin):
    """Content app B. Its backend reads this config's catalog."""

    name = 'tests.core.pair_beta'
    label = 'pair_beta'
    default = False
    default_auto_field = 'django.db.models.AutoField'

    def ready(self):
        from tests.core.pair_beta.backends import PairBetaBackend
        PairBetaBackend().get_registry()
        super().ready()
