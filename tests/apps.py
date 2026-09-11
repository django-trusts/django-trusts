from contextlib import contextmanager

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


@contextmanager
def override_apps_ready(ready, apps_registry=None):
    """Temporarily set ``Apps.ready`` so tests can simulate populate.

    Contributor ``ready()`` methods run while that Apps instance is not
    yet ready. Isolation tests that re-enter a host or package
    AppConfig after Django has finished populate must restore this
    window; they must not treat ``registries[path]`` as a live
    contributor route.
    """
    from django.apps import apps as django_apps

    target = django_apps if apps_registry is None else apps_registry
    was = target.ready
    target.ready = ready
    try:
        yield
    finally:
        target.ready = was


def install_writable_registry(config, path, contribute=None):
    """Install a standalone registry on a live path for test isolation.

    Callers register on the standalone instance *before* the first
    supported handle read after ``Apps.ready``. The live store is not a
    public contributor API.
    """
    from trusts.core import TrustsRegistry

    registry = TrustsRegistry()
    if contribute is not None:
        contribute(registry)
    config.registries[path] = registry
    return registry


def forget_models(*model_classes):
    """Drop dynamically created models from the default Apps registry."""
    from django.apps import apps as django_apps

    all_models = django_apps.all_models
    for model in model_classes:
        app_models = all_models.get(model._meta.app_label, {})
        app_models.pop(model._meta.model_name, None)
        for name, existing in list(app_models.items()):
            if existing is model:
                app_models.pop(name, None)
    django_apps.clear_cache()


def clone_writable_registry(registry):
    """Copy records onto a new unfrozen registry for test isolation."""
    from trusts.core import TrustsRegistry

    cloned = TrustsRegistry()
    cloned._by_root = {
        root: list(rows) for root, rows in registry._by_root.items()
    }
    cloned._order = list(registry._order)
    return cloned
