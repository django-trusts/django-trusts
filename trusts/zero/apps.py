from django.apps import AppConfig as DjangoAppConfig


class ZeroConfig(DjangoAppConfig):
    """Concrete Zero Django app: package ``trusts.zero``, historical label ``trusts``."""

    name = 'trusts.zero'
    label = 'trusts'
    verbose_name = 'Django Trusts Add-in'
    # Preserve the historical AutoField primary keys from 0001_initial.
    default_auto_field = 'django.db.models.AutoField'

    def ready(self):
        # admin.py registers core ModelAdmins at import. Only load it when
        # django.contrib.admin is installed so a kernel-only wheel import
        # without admin still starts.
        from django.apps import apps as django_apps
        if django_apps.is_installed('django.contrib.admin'):
            from trusts.zero.admin import register_auto_modeladmins
            register_auto_modeladmins()
        # Register Zero system checks. Do not validate conditions here:
        # raising from ready() would block shell, migrations, and recovery.
        from trusts.zero import checks as _trusts_zero_checks  # noqa: F401
