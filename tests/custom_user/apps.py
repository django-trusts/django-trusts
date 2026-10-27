import trusts.apps as trusts_apps


class CustomUserConfig(trusts_apps.TrustsConfigMixin):
    name = 'tests.custom_user'
    label = 'custom_user'
    default_auto_field = 'django.db.models.AutoField'
