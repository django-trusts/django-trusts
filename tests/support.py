import sys
from contextlib import contextmanager

from django.apps import apps as django_apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.test import override_settings
from django.utils.module_loading import import_string

from trusts.apps import TrustsConfigMixin
from trusts.backends import TrustModelBackendMixin
from trusts.compile.factory import Compiler
from trusts.errors import TrustsConfigurationError
from trusts.inspect.snapshot import render_policy_sql_bytes


ZERO_BACKEND = 'trusts.zero.backends.TrustModelBackend'


def built_catalog(compiler):
    """Catalog for one compiler. ``compile`` runs here."""
    return compiler.compile()


def built_registries(items):
    """Build a catalog for each factory. Callers pass factories."""
    return tuple(built_catalog(item) for item in items)


def scoped_permitted_content(queryset, user, permission, *, content,
                             compiler, **skip_flags):
    """Prefix filter for one explicit catalog in a unit test.

    The public filter walks ``get_catalog()`` and takes no catalog
    argument. This helper is the direct catalog question.
    """
    if compiler.family != 'relationship':
        return queryset.none()
    return compiler.filter_by_permitted_content(
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
    config = registry.get_containing_app_config(backend_cls.__module__)
    if not isinstance(config, TrustsConfigMixin):
        raise TrustsConfigurationError(
            '%s.%s must live inside an app whose config subclasses '
            'TrustsConfigMixin.'
            % (backend_cls.__module__, backend_cls.__qualname__)
        )
    return config


def _ensure_factory_user(factory):
    if factory.user_model is None:
        factory.user_model = get_user_model()
    return factory


@contextmanager
def _publish_built(built):
    """Point installed configs and the catalog walk at ``built``."""
    import trusts.apps as apps_mod
    import trusts.inspect.checks as checks_mod
    import trusts.inspect.snapshot as snapshot_mod

    configs = mixin_configs()
    saved = [(config, config.catalog) for config in configs]
    originals = (
        apps_mod.installed_catalogs,
        checks_mod.installed_catalogs,
        snapshot_mod.installed_catalogs,
    )

    def published():
        return tuple(built)

    try:
        if not built:
            for config in configs:
                config.catalog = built_catalog(Compiler(
                    path='%s.empty' % config.catalog_path(),
                    user_model=get_user_model(),
                ))
        elif len(built) == 1:
            for config in configs:
                config.catalog = built[0]
        else:
            for config, catalog in zip(configs, built):
                config.catalog = catalog
        apps_mod.installed_catalogs = published
        checks_mod.installed_catalogs = published
        snapshot_mod.installed_catalogs = published
        count = max(len(built), 1)
        paths = tuple(
            '%s.%s' % (cls.__module__, cls.__name__)
            for cls in _inquiry_backend_classes(count)
        )
        with override_settings(AUTHENTICATION_BACKENDS=paths):
            yield tuple(built)
    finally:
        apps_mod.installed_catalogs = originals[0]
        checks_mod.installed_catalogs = originals[1]
        snapshot_mod.installed_catalogs = originals[2]
        for config, catalog in saved:
            config.catalog = catalog


@contextmanager
def override_catalog(backend_cls, factory, path):
    """Publish one catalog for the app that contains ``backend_cls``."""

    config = config_for_class(backend_cls)
    saved = config.catalog
    factory.path = path
    _ensure_factory_user(factory)
    config.catalog = built_catalog(factory)
    try:
        with override_settings(AUTHENTICATION_BACKENDS=tuple(
            settings.AUTHENTICATION_BACKENDS,
        )):
            yield config.catalog
    finally:
        config.catalog = saved


def configured_catalog(path):
    """Catalog of the app that contains the backend class at ``path``."""

    cls = import_string(path)
    return config_for_class(cls).get_catalog()


@contextmanager
def empty_catalogs():
    """Give every mixin config an empty catalog, then restore."""

    with _publish_built(()):
        yield


def sweep_listed_backends():
    """Rebuild each installed mixin config's catalog from its recorder."""

    for config in mixin_configs():
        config.ready()


def live_config(apps_registry=None):
    """There is no sweep config. Callers use the owning app config."""

    del apps_registry
    raise TrustsConfigurationError(
        'TrustsConfigMixin apps own their catalogs. There is no sweep config.'
    )


@contextmanager
def override_apps_ready(ready, apps_registry=None):
    """Temporarily set ``Apps.ready`` so tests can simulate populate.

    Contributor ``ready()`` methods run while that Apps instance is not
    yet ready. Isolation tests that re-enter a host or package
    AppConfig after Django has finished populate must restore this
    window; they must not treat ``registries[path]`` as a live
    contributor route.
    """

    target = django_apps if apps_registry is None else apps_registry
    was = target.ready
    target.ready = ready
    try:
        yield
    finally:
        target.ready = was

def _publish_catalog(backend_cls, factory, *, path=None):
    """Store one catalog on the app that contains ``backend_cls``."""

    config = config_for_class(backend_cls)
    if factory is None:
        config.catalog = built_catalog(Compiler(
            path=path or config.catalog_path(),
            user_model=get_user_model(),
        ))
        return None
    published = path or factory.path or (
        '%s.%s' % (backend_cls.__module__, backend_cls.__qualname__)
    )
    factory.path = published
    _ensure_factory_user(factory)
    catalog = built_catalog(factory)
    config.catalog = catalog
    return catalog


@contextmanager
def bound_handle(backend, factory):
    """Publish ``factory`` as this backend's app catalog for one block."""

    config = config_for_class(type(backend))
    previous = config.catalog
    previous_backend = backend.catalog
    _publish_catalog(type(backend), factory)
    backend.catalog = config.catalog
    try:
        yield
    finally:
        config.catalog = previous
        backend.catalog = previous_backend


def push_catalog(backend_cls, factory):
    """Publish ``factory`` on the app that contains ``backend_cls``.

    Returns a zero-argument restore of the catalog that was there.
    """

    config = config_for_class(backend_cls)
    saved = config.catalog
    if not factory.path:
        factory.path = '%s.%s' % (
            backend_cls.__module__, backend_cls.__qualname__,
        )
    factory.family = backend_cls.family
    _ensure_factory_user(factory)
    config.catalog = built_catalog(factory)

    def restore():
        config.catalog = saved

    return restore


@contextmanager
def published_class_catalog(backend_cls, factory):
    """Publish ``factory`` for one block, then restore the app catalog."""

    restore = push_catalog(backend_cls, factory)
    try:
        yield config_for_class(backend_cls).catalog
    finally:
        restore()


def snapshot_installed_catalogs():
    """``(config, catalog)`` pairs for the installed mixin configs."""

    return tuple((config, config.catalog) for config in mixin_configs())


def restore_installed_catalogs(saved):
    """Put back catalogs captured by ``snapshot_installed_catalogs``."""

    for config, catalog in saved:
        config.catalog = catalog


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


def isolate_live_compiler(config, compiler, path):
    """Publish a standalone compiler as the catalog for one backend path."""

    del config
    cls = import_string(path)
    _publish_catalog(cls, compiler, path=path)
    return compiler


def install_writable_compiler(config, path, contribute=None):
    """Install a standalone factory as the catalog for one live path."""

    compiler = Compiler(path=path, user_model=get_user_model())
    if contribute is not None:
        contribute(compiler)
    isolate_live_compiler(config, compiler, path)
    return compiler


@contextmanager
def listed_relationship(factories):
    """Publish these factories as the catalogs inquiry and the lockfile see.

    One factory is installed on every mixin config, so the app that
    contains a model answers from it. Several factories are what
    ``installed_catalogs`` returns. A model still reads its own app.
    """

    built = []
    for index, factory in enumerate(tuple(factories)):
        if not factory.path:
            factory.path = 'tests.support.Listed%d' % index
        _ensure_factory_user(factory)
        built.append(built_catalog(factory))
    with _publish_built(built) as published:
        yield published


def replay_recorder(compiler, backend_cls):
    """Replay an app recorder onto a compiler this test owns."""

    config_for_class(backend_cls).recorder.play(compiler)
    return compiler


@contextmanager
def unbound_named_filters(backend_cls):
    """Publish a document catalog whose lookup has no named filters."""

    from tests.myapp.models import DocumentDelegation, DocumentGrant
    from trusts.apps import Recorder

    config = config_for_class(backend_cls)
    saved = config.catalog
    recorder = Recorder()
    recorder.register(
        trust=DocumentGrant, user='user', permission='permission',
        content='document',
    )
    recorder.register(
        trust=DocumentDelegation, delegate='delegate', sponsor='sponsor',
        content='document',
        condition=lambda relationship, permission: (
            relationship.allowed_permissions.contains(permission)
        ),
    )
    recorder.freeze()
    compiler = Compiler(
        query_compiler=backend_cls.query_compiler,
        path=saved.path,
        family=backend_cls.family,
        user_model=saved.user_model or get_user_model(),
    )
    recorder.play(compiler)
    config.catalog = compiler.compile()
    try:
        yield config.catalog
    finally:
        config.catalog = saved


def _inquiry_backend_classes(count):

    module = sys.modules[__name__]
    while len(_inquiry_backend_classes.cache) < count:
        index = len(_inquiry_backend_classes.cache)

        class Backend(TrustModelBackendMixin, ModelBackend):
            pass

        name = 'ListedInquiryBackend%d' % index
        Backend.__name__ = name
        Backend.__qualname__ = name
        Backend.__module__ = __name__
        setattr(module, name, Backend)
        _inquiry_backend_classes.cache.append(Backend)
    return _inquiry_backend_classes.cache[:count]

_inquiry_backend_classes.cache = []


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

