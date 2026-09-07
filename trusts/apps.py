from django.apps import AppConfig as DjangoAppConfig


class AppConfig(DjangoAppConfig):
    name = 'trusts'
    verbose_name = "Django Trusts Add-in"
    label = 'trusts'
    # Preserve the historical AutoField primary keys from 0001_initial.
    default_auto_field = 'django.db.models.AutoField'

    def ready(self):
        # admin.py registers core ModelAdmins at import. Only load it when
        # django.contrib.admin is installed so a wheel import without admin
        # (CI verify-wheel-install) still starts.
        from django.apps import apps as django_apps
        if django_apps.is_installed('django.contrib.admin'):
            from trusts.admin import register_auto_modeladmins
            register_auto_modeladmins()
