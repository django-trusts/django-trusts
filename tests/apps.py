from django.apps import AppConfig


def junction_content_field(junction_model):
    """Return the Junction→content field from the concrete Junction contract.

    Uses ``get_content_model()`` plus Django ``_meta``. Does not consult
    a static content map, hard-code ``content``, or guess reverse names.
    """
    from trusts.core import TrustsConfigurationError

    content_model = junction_model.get_content_model()._meta.concrete_model
    matches = [
        field for field in junction_model._meta.fields
        if field.remote_field is not None
        and field.remote_field.model._meta.concrete_model is content_model
    ]
    if len(matches) != 1:
        raise TrustsConfigurationError(
            '%s does not expose exactly one content field for %s.'
            % (junction_model._meta.label, content_model._meta.label)
        )
    return matches[0]


def junction_group_content_ref(root_ref, junction_model):
    """J1 content ref: TUP → Trust ← Junction → Group/content."""
    rev = junction_model._meta.get_field('trust').remote_field.get_accessor_name()
    content_name = junction_content_field(junction_model).name
    return getattr(getattr(root_ref.trust, rev), content_name)


class TestsConfig(AppConfig):
    name = 'tests'
    label = 'trusts_tests'
    default_auto_field = 'django.db.models.AutoField'

    def ready(self):
        # Contribute TUP→Trust←Category, TUP→Trust←Ticket, and the
        # Junction-backed Group terminal to the package-owned registry
        # that belongs to *this* Apps instance. isolate_apps() constructs
        # a second TestsConfig whose apps registry does not include
        # trusts; that instance must not donate onto the live registry.
        if getattr(self, 'apps', None) is None or not self.apps.is_installed('trusts'):
            return

        from tests.models import Category, TestGroupJunction, Ticket
        from trusts.core import Ref
        from trusts.models import TrustUserPermission

        # Exact handle. With one Trusts path this is the unique registry
        # (``config.registry is handle.registry``). With several, omission
        # fails before writing.
        backend = self.apps.get_app_config('trusts').configured_backend()
        registry = backend.registry

        # Instance-local sentinels: one per contribution, identity
        # comparison only, set only after register() succeeds. Never
        # inspect registry.records for content_model is Category/Ticket/
        # Group. Do not infer Ticket or Group completion from another
        # contribution's sentinel.
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

        donated_group = getattr(self, '_trusts_tup_group_registry_id', None)
        if donated_group is not registry:
            j = Ref(TrustUserPermission)
            registry.register(
                content=junction_group_content_ref(j, TestGroupJunction),
                user=j.entity,
                permission=j.permission,
            )
            self._trusts_tup_group_registry_id = registry
