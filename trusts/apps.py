from django.apps import AppConfig as DjangoAppConfig


class AppConfig(DjangoAppConfig):
    name = 'trusts'
    verbose_name = "Django Trusts Add-in"
    label = 'trusts'
    # Preserve the historical AutoField primary keys from 0001_initial.
    default_auto_field = 'django.db.models.AutoField'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Import here: a module-level trusts.core import loads contenttypes
        # models before Apps.populate finishes.
        from trusts.core import TrustsRegistry

        # Package-owned live registry. Created here so every AppConfig exists
        # before any contributor ready(). ready() must not replace this object;
        # tests re-enter ready() and isolated core tests keep their own
        # TrustsRegistry() instances.
        self.registry = TrustsRegistry()

    def ready(self):
        # admin.py registers core ModelAdmins at import. Only load it when
        # django.contrib.admin is installed so a wheel import without admin
        # (CI verify-wheel-install) still starts.
        from django.apps import apps as django_apps
        if django_apps.is_installed('django.contrib.admin'):
            from trusts.admin import register_auto_modeladmins
            register_auto_modeladmins()
        # Register system checks. Do not validate conditions here: raising
        # from ready() would block shell, migrations, and recovery.
        from trusts import checks as _trusts_checks  # noqa: F401

        # S1: package-owned Trust-as-content. Donate TUP → parent Trust ←
        # child Trust onto *this* AppConfig's registry. One sentinel for
        # this contribution; compare registry identity; set only after
        # register() succeeds. ready() must not replace self.registry.
        donated = getattr(self, '_trusts_tup_trust_registry_id', None)
        if donated is self.registry:
            return

        from trusts.core import Ref
        from trusts.models import Trust, TrustUserPermission

        j = Ref(TrustUserPermission)
        rev = Trust._meta.get_field('trust').remote_field.get_accessor_name()
        self.registry.register(
            content=getattr(j.trust, rev),
            user=j.entity,
            permission=j.permission,
        )
        self._trusts_tup_trust_registry_id = self.registry
