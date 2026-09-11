from django.apps import AppConfig


class TestsConfig(AppConfig):
    name = 'tests'
    label = 'trusts_tests'
    default_auto_field = 'django.db.models.AutoField'

    def ready(self):
        # Contribute TUP→Trust←Category and TUP→Trust←Ticket to the
        # package-owned registry that belongs to *this* Apps instance.
        # isolate_apps() constructs a second TestsConfig whose apps
        # registry does not include trusts; that instance must not
        # donate onto the live registry.
        if getattr(self, 'apps', None) is None or not self.apps.is_installed('trusts'):
            return

        from tests.models import Category, Ticket
        from trusts.core import Ref
        from trusts.models import TrustUserPermission

        registry = self.apps.get_app_config('trusts').registry

        # Instance-local sentinels: one per contribution, identity
        # comparison only, set only after register() succeeds. Never
        # inspect registry.records for content_model is Category/Ticket.
        # Do not infer Ticket completion from Category's sentinel.
        donated_category = getattr(self, '_trusts_tup_category_registry_id', None)
        if donated_category is not registry:
            j = Ref(TrustUserPermission)
            rev = Category._meta.get_field('trust').remote_field.get_accessor_name()
            registry.register(
                content=getattr(j.trust, rev),
                user=j.entity,
                permission=j.permission,
            )
            self._trusts_tup_category_registry_id = registry

        donated_ticket = getattr(self, '_trusts_tup_ticket_registry_id', None)
        if donated_ticket is not registry:
            j = Ref(TrustUserPermission)
            rev = Ticket._meta.get_field('trust').remote_field.get_accessor_name()
            registry.register(
                content=getattr(j.trust, rev),
                user=j.entity,
                permission=j.permission,
            )
            self._trusts_tup_ticket_registry_id = registry
