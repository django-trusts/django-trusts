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
        from django.utils.module_loading import import_string

        from trusts.backends import SimpleRegistry, registries

        for path in self.owned_backend_paths():
            cls = import_string(path)
            if cls not in registries:
                registries[cls] = SimpleRegistry(cls)


def isolated_owner():
    """Construct a standalone implementation owner for isolation tests."""
    import tests as tests_module

    return IsolatedOwnerConfig('tests', tests_module)


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
        # registry that belongs to *this* Apps instance. isolate_apps()
        # constructs a second TestsConfig whose apps registry has no
        # implementation owner; that instance must not donate onto the
        # live registry.
        if getattr(self, 'apps', None) is None:
            return

        from trusts.apps import implementation_configs
        from trusts.errors import TrustsConfigurationError

        owners = implementation_configs(self.apps)
        if len(owners) != 1:
            return
        config = owners[0]

        try:
            TrustUserPermission = self.apps.get_model('trusts', 'TrustUserPermission')
            from tests.models import Category, TestGroupJunction, Ticket
        except (LookupError, ImportError):
            return

        # Exact handle. With one Trusts path this is the unique registry
        # (``config.registry is handle.registry``). With several, omission
        # fails before writing.
        from django.utils.module_loading import import_string

        paths = config._configured_trusts_paths()
        if len(paths) != 1:
            return
        registry = import_string(paths[0])().get_registry()

        # Instance-local sentinels: one per contribution, identity
        # comparison only, set only after register() succeeds. Never
        # inspect registry.records for content_model is Category/Ticket/
        # Group. Do not infer Ticket or Group completion from another
        # contribution's sentinel.
        donated_category = getattr(self, '_trusts_tup_category_registry_id', None)
        if donated_category is not registry:
            rev = Category._meta.get_field('trust').remote_field.get_accessor_name()
            registry.register(
                trust=TrustUserPermission,
                content='trust__%s' % rev,
                user='entity',
                permission='permission',
            )
            self._trusts_tup_category_registry_id = registry

        donated_ticket = getattr(self, '_trusts_tup_ticket_registry_id', None)
        if donated_ticket is not registry:
            rev = Ticket._meta.get_field('trust').remote_field.get_accessor_name()
            registry.register(
                trust=TrustUserPermission,
                content='trust__%s' % rev,
                user='entity',
                permission='permission',
            )
            self._trusts_tup_ticket_registry_id = registry

        donated_group = getattr(self, '_trusts_tup_group_registry_id', None)
        if donated_group is not registry:
            rev = TestGroupJunction._meta.get_field('trust').remote_field.get_accessor_name()
            content_name = junction_content_field(TestGroupJunction).name
            registry.register(
                trust=TrustUserPermission,
                content='trust__%s__%s' % (rev, content_name),
                user='entity',
                permission='permission',
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


def isolate_live_registry(config, registry, path=None):
    """Bind a standalone registry for one backend class (test isolation).

    Test isolation only. Not a host contributor route. This writes the
    per-backend-class ``registries`` dict in ``trusts.backends``.
    """
    from django.utils.module_loading import import_string

    from trusts.backends import registries

    if path is None:
        paths = config._configured_trusts_paths()
        path = paths[0]
    cls = import_string(path)
    from trusts.backends import SimpleRegistry
    from trusts.compile.factory import TrustsCompiler

    if isinstance(registry, TrustsCompiler):
        wrapper = SimpleRegistry(cls)
        wrapper._compiler = registry
        registries[cls] = wrapper
        return wrapper
    if getattr(registry, '_backend_class', None) is None:
        try:
            registry._backend_class = cls
        except Exception:
            pass
    registries[cls] = registry
    return registry


def install_writable_registry(config, path, contribute=None):
    """Install a standalone registry on a live path for test isolation.

    Callers register on the standalone instance *before* the first
    supported handle read after ``Apps.ready``. The live store is not a
    public contributor API.
    """
    
    from django.utils.module_loading import import_string

    from trusts.backends import registries
    from trusts.compile.factory import TrustsCompiler

    registry = TrustsCompiler()
    if contribute is not None:
        contribute(registry)
    registries[import_string(path)] = registry
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
        from trusts.backends import registries as backend_registries
        from trusts.compile.factory import TrustsCompiler

        registry = TrustsCompiler()
        backend_registries[cls] = registry
        register_zero_relations(registry)
        ids = dict(getattr(config, '_trusts_tup_trust_registry_ids', None) or {})
        ids[path] = registry
        config._trusts_tup_trust_registry_ids = ids
        if len(paths) == 1:
            config._trusts_tup_trust_registry_id = registry
    return config


def clone_writable_registry(registry):
    """Copy records onto a new writable registry for test isolation."""
    
    cloned = TrustsCompiler()
    cloned._by_root = {
        root: list(rows) for root, rows in registry._by_root.items()
    }
    cloned._order = list(registry._order)
    return cloned


def backend_handle(path, registry, compiler):
    """Test-only compiled-plan namespace replacing the deleted handle.

    Returns a namespace with ``path`` / ``registry`` / ``compiler``,
    ``register`` and ``add_named_filter`` forwarding to the registry's
    public registration, and ``build_compiled()`` building (or passing
    through) the query-time plan.
    """
    from types import SimpleNamespace

    def register(**kwargs):
        public = getattr(registry, '_register_public', None)
        if callable(public):
            return public(**kwargs)
        return registry.register(**kwargs)

    def add_named_filter(model, code, predicate):
        fn = getattr(registry, 'register_permission_condition', None)
        if callable(fn) and type(registry).__name__ != 'SimpleRegistry':
            return fn(model, code, predicate)
        return registry.add_named_filter(model, code, predicate)

    def build_compiled():
        if registry is None:
            return None
        build = getattr(registry, 'build_compiled', None)
        return build() if callable(build) else registry

    handle = SimpleNamespace(
        path=path, registry=registry, compiler=compiler,
        register=register, add_named_filter=add_named_filter,
        build_compiled=build_compiled,
    )
    handle.historical_fallback = bool(
        getattr(compiler, 'historical_fallback', False)
    )
    return handle
