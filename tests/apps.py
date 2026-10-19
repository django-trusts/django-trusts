from contextlib import contextmanager

from django.apps import AppConfig

from trusts.apps import TrustsImplementationConfig



ZERO_BACKEND = 'trusts.zero.backends.TrustModelBackend'


class IsolatedOwnerConfig(TrustsImplementationConfig):
    """Unbound pair-test owner. Not installed; constructed in isolation.

    ``ready()`` only ensures local registries. It does not validate against
    the live ZeroConfig that already owns the canonical Zero path.
    """

    name = 'tests'
    label = 'trusts_isolated_owner'
    default = False
    trusts_backend_paths = (ZERO_BACKEND,)

    def ready(self):
        for path in self.owned_backend_paths():
            self._ensure(path)


def isolated_owner():
    """Construct a standalone implementation owner for isolation tests."""
    import tests as tests_module

    return IsolatedOwnerConfig('tests', tests_module)


def built_registries(items):
    """Query-time registries for one inquiry.

    A factory is built now. A catalog contributes its built registry.
    A registry is returned as itself. ``None`` and other objects pass
    through so a caller can still prove a missing registry fails closed.
    """
    from trusts.compile.catalogs import Catalog
    from trusts.compile.factory import RegistryFactory
    from trusts.plan.registry import Registry

    if items is None:
        return None
    if isinstance(items, (str, bytes)) or not isinstance(items, (list, tuple)):
        items = (items,)
    built = []
    for item in items:
        if item is None or isinstance(item, Registry):
            built.append(item)
        elif isinstance(item, Catalog):
            built.append(item.registry)
        elif isinstance(item, RegistryFactory):
            built.append(item.build_registry())
        else:
            built.append(item)
    return tuple(built)


@contextmanager
def override_catalog(backend_cls, factory, path):
    """Publish one catalog for ``backend_cls`` and restore the previous entry."""
    from trusts.apps import catalogs
    from trusts.compile.catalogs import Catalog

    saved = catalogs.get(backend_cls, _MISSING)
    catalogs[backend_cls] = Catalog(
        cls=backend_cls,
        path=path,
        family=getattr(factory, 'family', 'relationship'),
        factory=factory,
        registry=factory.build_registry(),
        family_registries=(),
    )
    try:
        yield catalogs[backend_cls]
    finally:
        if saved is _MISSING:
            catalogs.pop(backend_cls, None)
        else:
            catalogs[backend_cls] = saved


def configured_catalog(config, path=None):
    """Catalog stored for one owned path. Registration is the recorder."""
    from trusts.apps import catalogs, implementation_for_path, listed_backend_class
    from trusts.errors import TrustsConfigurationError

    paths = config._configured_trusts_paths()
    if path is None:
        if len(paths) != 1:
            raise TrustsConfigurationError(
                'configured catalog needs an explicit path; got %r' % (paths,)
            )
        path = paths[0]
    elif path not in config.owned_backend_paths():
        try:
            other = implementation_for_path(path, getattr(config, 'apps', None))
        except TrustsConfigurationError:
            other = None
        if other is not None and other is not config:
            return configured_catalog(other, path)
        raise TrustsConfigurationError(
            '%r is not a configured Trusts backend' % (path,)
        )
    elif path not in paths:
        raise TrustsConfigurationError(
            '%r is not a configured Trusts backend' % (path,)
        )
    cls = listed_backend_class(path)
    catalog = catalogs.get(cls) if isinstance(cls, type) else None
    if catalog is None:
        raise TrustsConfigurationError(
            '%r is not a configured Trusts backend' % (path,)
        )
    return catalog


def live_config(apps_registry=None):
    """The kernel-host or unique installed ``TrustsImplementationConfig``.

    Kernel-only tests prefer ``KernelHostConfig`` when the README
    consumer is also installed. The supported Zero pair still has
    exactly one owner (``ZeroConfig``).
    """
    from tests.kernel_host.apps import KernelHostConfig
    from trusts.apps import implementation_configs
    from trusts.errors import TrustsConfigurationError

    configs = implementation_configs(apps_registry)
    if len(configs) == 1:
        return configs[0]
    hosts = [config for config in configs if type(config) is KernelHostConfig]
    if len(hosts) == 1:
        return hosts[0]
    raise TrustsConfigurationError(
        'live_config() needs exactly one implementation owner; got %r'
        % (configs,)
    )


def junction_content_field(junction_model):
    """Return the Junction→content field from the concrete Junction contract.

    Uses ``get_content_model()`` plus Django ``_meta``. Does not consult
    a static content map, hard-code ``content``, or guess reverse names.
    """
    from trusts.errors import TrustsConfigurationError

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
        # Junction-backed Group terminal to the implementation-owned
        # recorder when this Apps instance has exactly one owner.
        # isolate_apps() constructs a second TestsConfig whose apps
        # registry has no implementation owner; that instance must not
        # donate or seal the live recorders.
        if getattr(self, 'apps', None) is None:
            return

        from django.apps import apps as django_apps

        from trusts.apps import implementation_configs
        from trusts.backends import seal_configured_backends
        from trusts.errors import TrustsConfigurationError

        owners = implementation_configs(self.apps)
        if len(owners) == 1:
            try:
                TrustUserPermission = self.apps.get_model(
                    'trusts', 'TrustUserPermission',
                )
                from tests.models import Category, TestGroupJunction, Ticket
            except (LookupError, ImportError):
                TrustUserPermission = None
            if TrustUserPermission is not None:
                self._donate_tup(
                    owners[0], TrustUserPermission, Category, Ticket,
                    TestGroupJunction,
                )
        if self.apps is django_apps:
            seal_configured_backends(self.apps)

    def _donate_tup(self, owner, TrustUserPermission, Category, Ticket,
                    TestGroupJunction):
        from django.contrib.auth import get_backends

        from trusts.apps import listed_backend_class
        from trusts.errors import TrustsConfigurationError

        paths = owner._configured_trusts_paths()
        if len(paths) != 1:
            raise TrustsConfigurationError(
                'configured_backend() needs an explicit path; got %r'
                % (paths,)
            )
        get_backends()
        cls = listed_backend_class(paths[0])
        backend = next(b for b in get_backends() if type(b) is cls)
        recorder = backend.get_registry()
        if not getattr(self, '_trusts_tup_category_done', False):
            rev = Category._meta.get_field('trust').remote_field.get_accessor_name()
            recorder.register(
                trust=TrustUserPermission,
                user='entity',
                permission='permission',
                content=lambda relationship, _rev=rev: (
                    getattr(relationship.trust, _rev)
                ),
            )
            self._trusts_tup_category_done = True
        if not getattr(self, '_trusts_tup_ticket_done', False):
            rev = Ticket._meta.get_field('trust').remote_field.get_accessor_name()
            recorder.register(
                trust=TrustUserPermission,
                user='entity',
                permission='permission',
                content=lambda relationship, _rev=rev: (
                    getattr(relationship.trust, _rev)
                ),
            )
            self._trusts_tup_ticket_done = True
        if not getattr(self, '_trusts_tup_group_done', False):
            content_name = junction_content_field(TestGroupJunction).name
            rev = TestGroupJunction._meta.get_field(
                'trust',
            ).remote_field.get_accessor_name()
            recorder.register(
                trust=TrustUserPermission,
                user='entity',
                permission='permission',
                content=lambda relationship, _rev=rev, _name=content_name: (
                    getattr(getattr(relationship.trust, _rev), _name)
                ),
            )
            self._trusts_tup_group_done = True


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


_MISSING = object()


def _publish_catalog(backend_cls, factory, *, path=None, peers=()):
    """Store one catalog for ``backend_cls``. ``factory`` is the registration object."""
    from trusts.apps import catalogs
    from trusts.compile.catalogs import Catalog

    if factory is None:
        catalogs.pop(backend_cls, None)
        return None
    built = factory.build_registry()
    catalogs[backend_cls] = Catalog(
        cls=backend_cls,
        path=path or factory.path or (
            '%s.%s' % (backend_cls.__module__, backend_cls.__qualname__)
        ),
        family=factory.family,
        factory=factory,
        registry=built,
        family_registries=built_registries(tuple(peers)),
    )
    return built


@contextmanager
def bound_handle(backend, factory):
    """Publish ``factory`` as this backend class's catalog for one block."""
    from trusts.apps import catalogs

    cls = type(backend)
    previous = catalogs.get(cls, _MISSING)
    peers = () if previous is _MISSING else previous.family_registries
    _publish_catalog(cls, factory, peers=peers)
    try:
        yield
    finally:
        if previous is _MISSING:
            catalogs.pop(cls, None)
        else:
            catalogs[cls] = previous


def install_class_handle(backend_cls, factory):
    """Publish ``factory`` as ``backend_cls``'s catalog. ``None`` removes it."""
    _publish_catalog(backend_cls, factory)


def isolate_live_registry(config, registry, path=None):
    """Publish a standalone registry as the catalog for one owned path."""
    from trusts.apps import listed_backend_class

    if path is None:
        paths = config._configured_trusts_paths()
        path = paths[0]
    cls = listed_backend_class(path)
    _publish_catalog(cls, registry, path=path)
    return registry


def install_writable_registry(config, path, contribute=None):
    """Install a standalone factory as the catalog for one live path."""
    from trusts.compile.factory import RegistryFactory

    registry = RegistryFactory(path=path)
    if contribute is not None:
        contribute(registry)
    isolate_live_registry(config, registry, path)
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


def apply_zero_trust_donation(config):
    """Donate package Trust-as-content the way Zero does on IIa.

    Implementation ``ready()`` owns live donation. Tests that need the
    historical TUP→Trust declaration on a standalone or swapped store
    call this instead of expecting a core AppConfig to donate.
    Mixin-only paths are skipped (C1 package donation rule).
    """
    from django.utils.module_loading import import_string

    from trusts.zero.backends import TrustModelBackend
    from trusts.zero.models import register_zero_relations

    paths = config._configured_trusts_paths()
    for path in paths:
        cls = import_string(path)
        if not issubclass(cls, TrustModelBackend):
            continue
        registry = config._ensure(path)
        register_zero_relations(registry)
        ids = dict(getattr(config, '_trusts_tup_trust_registry_ids', None) or {})
        ids[path] = registry
        config._trusts_tup_trust_registry_ids = ids
        if len(paths) == 1:
            config._trusts_tup_trust_registry_id = registry
    return config


def clone_writable_registry(registry):
    """Copy records onto a new writable registry for test isolation."""
    from trusts.compile.factory import RegistryFactory

    cloned = RegistryFactory()
    cloned._by_root = {
        root: list(rows) for root, rows in registry._by_root.items()
    }
    cloned._order = list(registry._order)
    return cloned
