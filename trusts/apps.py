from django.apps import AppConfig as DjangoAppConfig
from django.apps import apps as django_apps


class AppConfig(DjangoAppConfig):
    name = 'trusts'
    verbose_name = "Django Trusts Add-in"
    label = 'trusts'
    # Preserve the historical AutoField primary keys from 0001_initial.
    default_auto_field = 'django.db.models.AutoField'

    def ready(self):
        self._register_auto_modeladmins()

    def _register_auto_modeladmins(self):
        """Opt-in admin registration for concrete Content/Junction subclasses.

        Set ``auto_modeladmin = True`` on the model's Meta. Core Trusts models
        stay explicitly registered in ``trusts.admin``.
        """
        if not django_apps.is_installed('django.contrib.admin'):
            return

        from django.contrib import admin
        from trusts.models import Content, Junction

        for model in django_apps.get_models():
            meta = getattr(model, '_meta', None)
            if meta is None or getattr(meta, 'abstract', False):
                continue
            if not getattr(meta, 'auto_modeladmin', False):
                continue
            if not issubclass(model, (Content, Junction)):
                continue
            if model not in admin.site._registry:
                admin.site.register(model)
