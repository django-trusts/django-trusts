import sys
import types
from contextlib import contextmanager

from django.apps import apps as django_apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.test import override_settings
from django.utils.module_loading import import_string

from trusts.apps import TrustsConfigMixin
from trusts.backends import (
    RELATIONSHIP_BACKEND_KEY,
    RelationshipBackend,
    TrustModelBackendMixin,
)
from trusts.compile.appbuild import build_app_catalog
from trusts.compile.compilers import Compiler
from trusts.errors import TrustsConfigurationError
from trusts.inspect.snapshot import render_policy_sql_bytes


def built_catalog(compiler):
    """Catalog for one compiler. ``compile`` runs here."""
    return compiler.compile()


def built_registries(items):
    """Build a catalog for each factory. Callers pass factories."""
    return tuple(built_catalog(item) for item in items)


def scoped_permitted_content(queryset, user, permission, *, content,
                             registry, **skip_flags):
    """Prefix filter for one explicit registry in a unit test.

    The public filter ORs listed backends and takes no registry
    argument. This helper is the direct registry question.
    """
    if registry.family != 'relationship':
        return queryset.none()
    return registry.filter_by_permitted_content(
        queryset, user, permission, content=content, **skip_flags,
    )


def mixin_configs(apps_registry=None):
    """Installed ``TrustsConfigMixin`` configs, in ``INSTALLED_APPS`` order."""
    registry = django_apps if apps_registry is None else apps_registry
    return tuple(
        config for config in registry.get_app_configs()
        if isinstance(config, TrustsConfigMixin)
    )


def config_for_class(backend_cls, apps_registry=None):
    """App config that contains ``backend_cls``."""
    registry = django_apps if apps_registry is None else apps_registry
    return registry.get_containing_app_config(backend_cls.__module__)


def app_catalog_path(config):
    """Catalog path stored for ``config``: its class module and qualname."""
    return '%s.%s' % (type(config).__module__, type(config).__qualname__)


def backend_state(config):
    """State object for ``config``, or ``None`` when unset."""
    lookup = getattr(config, 'get_config', None)
    if not callable(lookup):
        return None
    return lookup(RELATIONSHIP_BACKEND_KEY)


def ensure_backend_state(config):
    """Return the relationship state, creating it when ``ready`` has not."""
    state = backend_state(config)
    if state is not None:
        return state
    return config.get_or_create_config(
        RELATIONSHIP_BACKEND_KEY,
        RelationshipBackend,
        on_ready=build_app_catalog,
    )


def read_catalog(config):
    state = backend_state(config)
    if state is None:
        return None
    return state.catalog


def write_catalog(config, catalog):
    ensure_backend_state(config).catalog = catalog


def read_family(config):
    state = backend_state(config)
    if state is None:
        return TrustModelBackendMixin.family
    return state.family


def read_recorder(config):
    state = backend_state(config)
    if state is None:
        return None
    return state.recorder


def compiler(**kwargs):
    """Standalone ``Compiler``. The user model is already known."""
    kwargs.setdefault('user_model', get_user_model())
    kwargs.setdefault('query_compiler', Compiler.default_query_compiler())
    kwargs.setdefault('path', 'tests.support.Compiler')
    kwargs.setdefault('family', 'relationship')
    return Compiler(**kwargs)


@contextmanager
def _publish_built(built):
    """Store each catalog on one mixin config. The real walk lists them.

    One catalog is not copied onto every config: that repeats its path.
    Extra catalogs beyond the installed mixin apps are not given a
    second backend in the same app.
    """
    configs = mixin_configs()
    if not configs:
        raise TrustsConfigurationError(
            'listed_relationship needs a TrustsConfigMixin app.')
    saved = [(config, read_catalog(config)) for config in configs]
    try:
        for config, catalog in zip(configs, built):
            write_catalog(config, catalog)
        for config in configs[len(built):]:
            write_catalog(config, built_catalog(Compiler(
                path='%s.empty' % app_catalog_path(config),
                family=read_family(config),
                query_compiler=Compiler.default_query_compiler(),
                user_model=get_user_model(),
            )))
        owners = configs[:len(built)] or configs[:1]
        paths = tuple(
            '%s.%s' % (cls.__module__, cls.__name__)
            for cls in _inquiry_backend_classes(owners))
        with override_settings(AUTHENTICATION_BACKENDS=paths):
            yield tuple(built)
    finally:
        for config, catalog in saved:
            write_catalog(config, catalog)


@contextmanager
def override_catalog(backend_cls, factory, path):
    """Publish one catalog for the app that contains ``backend_cls``."""

    config = config_for_class(backend_cls)
    saved = read_catalog(config)
    factory.path = path
    published = built_catalog(factory)
    write_catalog(config, published)
    try:
        with override_settings(AUTHENTICATION_BACKENDS=tuple(
            settings.AUTHENTICATION_BACKENDS,
        )):
            yield published
    finally:
        write_catalog(config, saved)


def configured_catalog(path):
    """Catalog of the app that contains the backend class at ``path``."""

    cls = import_string(path)
    return read_catalog(config_for_class(cls))


@contextmanager
def empty_catalogs():
    """Give every mixin config an empty catalog, then restore."""

    with _publish_built(()):
        yield


def sweep_listed_backends():
    """Rebuild each installed mixin config's catalog from its recorder."""

    for config in mixin_configs():
        config.ready()


def _publish_catalog(backend_cls, factory, *, path=None):
    """Store one catalog on the app that contains ``backend_cls``."""

    config = config_for_class(backend_cls)
    if factory is None:
        write_catalog(config, built_catalog(Compiler(
            path=path or app_catalog_path(config),
            family=read_family(config),
            query_compiler=Compiler.default_query_compiler(),
            user_model=get_user_model(),
        )))
        return None
    published = path or factory.path or (
        '%s.%s' % (backend_cls.__module__, backend_cls.__qualname__)
    )
    factory.path = published
    catalog = built_catalog(factory)
    write_catalog(config, catalog)
    return catalog


@contextmanager
def bound_handle(backend, factory):
    """Publish ``factory`` as this backend's app catalog for one block."""

    config = config_for_class(type(backend))
    previous = read_catalog(config)
    _publish_catalog(type(backend), factory)
    try:
        yield
    finally:
        write_catalog(config, previous)


def push_catalog(backend_cls, factory):
    """Publish ``factory`` on the app that contains ``backend_cls``.

    Returns a zero-argument restore of the catalog that was there.
    """

    config = config_for_class(backend_cls)
    saved = read_catalog(config)
    if not factory.path:
        factory.path = '%s.%s' % (
            backend_cls.__module__, backend_cls.__qualname__,
        )
    factory.family = read_family(config)
    write_catalog(config, built_catalog(factory))

    def restore():
        write_catalog(config, saved)

    return restore


@contextmanager
def published_class_catalog(backend_cls, factory):
    """Publish ``factory`` for one block, then restore the app catalog."""

    restore = push_catalog(backend_cls, factory)
    try:
        yield read_catalog(config_for_class(backend_cls))
    finally:
        restore()


def snapshot_config_catalogs():
    """``(config, catalog)`` pairs for the installed mixin configs."""

    return tuple((config, read_catalog(config)) for config in mixin_configs())


def restore_config_catalogs(saved):
    """Put back catalogs captured by ``snapshot_config_catalogs``."""

    for config, catalog in saved:
        write_catalog(config, catalog)


def render_configured_policy(*subjects):
    """Publish registries and render policy SQL through the listed catalogs."""

    with listed_relationship(subjects):
        return render_policy_sql_bytes()


@contextmanager
def published_subjects(subjects):
    """Store these objects as the catalogs the policy walk lists."""

    with _publish_built(tuple(subjects)):
        yield


def render_published_subjects(*subjects):
    """Render policy SQL for objects already shaped like catalogs."""

    with published_subjects(subjects):
        return render_policy_sql_bytes()


def install_class_handle(backend_cls, factory):
    """Publish ``factory`` as the catalog of ``backend_cls``'s app."""
    _publish_catalog(backend_cls, factory)


def isolate_live_registry(config, registry, path):
    """Publish a standalone registry as the catalog for one backend path."""

    del config
    cls = import_string(path)
    _publish_catalog(cls, registry, path=path)
    return registry


def install_writable_registry(config, path, contribute=None):
    """Install a standalone factory as the catalog for one live path."""

    registry = Compiler(
        path=path,
        family=read_family(config),
        query_compiler=Compiler.default_query_compiler(),
        user_model=get_user_model(),
    )
    if contribute is not None:
        contribute(registry)
    isolate_live_registry(config, registry, path)
    return registry


@contextmanager
def listed_relationship(factories):
    """Publish these factories as the catalogs inquiry and the lockfile see.

    Each factory is stored on its own mixin config, in ``INSTALLED_APPS``
    order. Each listed backend's module lives in that config.
    """

    built = []
    for index, factory in enumerate(tuple(factories)):
        if not factory.path:
            factory.path = 'tests.support.Listed%d' % index
        built.append(built_catalog(factory))
    with _publish_built(built) as published:
        yield published


def replay_recorder(compiler, backend_cls):
    """Register the document app's rows onto a compiler this test owns.

    Those rows are the models.py registration. The host app registers
    nothing, so other backends are left empty.
    """
    from tests.myapp.backends import DocumentBackend
    from tests.myapp.models import register_document_app

    if backend_cls is not DocumentBackend:
        return compiler
    register_document_app(compiler)
    return compiler


def register_installed_document_app():
    """Register document rows on the current myapp config.

    ``override_settings(INSTALLED_APPS=...)`` builds a new app config
    and does not re-execute models.py.
    """
    from django.apps import apps
    from tests.myapp.models import register_document_app

    config = apps.get_app_config('myapp')
    if read_catalog(config) is not None or getattr(
        config, '_registered_from_models', False,
    ):
        return
    register_document_app(read_recorder(config) or ensure_backend_state(config).recorder)


@contextmanager
def unbound_named_filters(backend_cls):
    """Publish a document catalog whose lookup has no named filters."""

    from tests.myapp.models import register_document_grants

    config = config_for_class(backend_cls)
    saved = read_catalog(config)
    compiler = Compiler(
        query_compiler=Compiler.default_query_compiler(),
        path=saved.path,
        family=read_family(config),
        user_model=saved.user_model or get_user_model(),
    )
    register_document_grants(compiler)
    published = compiler.compile()
    write_catalog(config, published)
    try:
        yield published
    finally:
        write_catalog(config, saved)


def _inquiry_backend_classes(configs):
    """One backend class in each config's package, so construction finds it."""
    built = []
    for index, config in enumerate(configs):
        module_name = '%s.listed_inquiry' % config.name
        module = sys.modules.get(module_name)
        if module is None:
            module = types.ModuleType(module_name)
            sys.modules[module_name] = module

        class Backend(TrustModelBackendMixin, ModelBackend):
            pass

        name = 'ListedInquiryBackend%d' % index
        Backend.__name__ = name
        Backend.__qualname__ = name
        Backend.__module__ = module_name
        setattr(module, name, Backend)
        built.append(Backend)
    return built


def forget_models(*model_classes):
    """Drop dynamically created models from the default Apps registry."""

    all_models = django_apps.all_models
    for model in model_classes:
        app_models = all_models.get(model._meta.app_label, {})
        app_models.pop(model._meta.model_name, None)
        for name, existing in list(app_models.items()):
            if existing is model:
                app_models.pop(name, None)
    django_apps.clear_cache()

