import sys
from contextlib import contextmanager

from django.apps import apps as django_apps
from django.conf import settings
from django.contrib.auth import get_user_model
from django.contrib.auth.backends import ModelBackend
from django.test import override_settings
from django.utils.module_loading import import_string

from trusts.backends import TrustModelBackendMixin, catalogs, recorders
from trusts.compile.catalogs import Catalog
from trusts.compile.factory import RegistryFactory, build_configured_catalogs
from trusts.errors import TrustsConfigurationError
from trusts.inspect.snapshot import render_policy_sql_bytes
import trusts.plan.standards as standards


ZERO_BACKEND = 'trusts.zero.backends.TrustModelBackend'


def built_catalog(factory, *, cls=None, path=None, family=None):
    """Catalog for one factory. The factory is built here.

    ``cls``, ``path``, and ``family`` stamp that one build when the
    catalog's identity differs from the factory's. The factory's own
    attributes are restored.
    """
    saved = (factory.cls, factory.path, factory.family)
    if cls is not None:
        factory.cls = cls
    if path is not None:
        factory.path = path
    if family is not None:
        factory.family = family
    try:
        return Catalog(factory.build())
    finally:
        factory.cls, factory.path, factory.family = saved


def built_registries(items):
    """Build a catalog for each factory. Callers pass factories."""
    return tuple(built_catalog(item) for item in items)


def scoped_permitted_content(queryset, user, permission, *, content,
                             registry, **skip_flags):
    """Prefix filter for one explicit registry in a unit test.

    The public filter walks ``get_catalog()`` and takes no registry
    argument. This helper is the direct registry question.
    """
    if registry.family != 'relationship':
        return queryset.none()
    return registry.filter_by_permitted_content(
        queryset, user, permission, content=content, **skip_flags,
    )


@contextmanager
def override_catalog(backend_cls, factory, path):
    """Publish one catalog for ``backend_cls`` and restore the previous entry."""

    saved = catalogs.get(backend_cls, _MISSING)
    catalogs[backend_cls] = built_catalog(factory, cls=backend_cls, path=path)
    try:
        yield catalogs[backend_cls]
    finally:
        if saved is _MISSING:
            catalogs.pop(backend_cls, None)
        else:
            catalogs[backend_cls] = saved


def configured_catalog(path):
    """Catalog stored for one ``AUTHENTICATION_BACKENDS`` dotted path."""

    cls = import_string(path)
    catalog = catalogs.get(cls)
    if catalog is None or catalog.path != path:
        raise TrustsConfigurationError(
            '%r is not a configured Trusts backend' % (path,)
        )
    return catalog


@contextmanager
def empty_catalogs():
    """Clear built catalogs for one sweep, then restore them."""

    saved = dict(catalogs)
    catalogs.clear()
    try:
        yield
    finally:
        catalogs.clear()
        catalogs.update(saved)


def sweep_listed_backends():
    """Run the ready-time build against the current ``AUTHENTICATION_BACKENDS``."""

    build_configured_catalogs(
        tuple(settings.AUTHENTICATION_BACKENDS),
        get_user_model(),
    )


def live_config(apps_registry=None):
    """The sweep config. It does not own a backend path."""

    registry = django_apps if apps_registry is None else apps_registry
    try:
        return registry.get_app_config('trusts_lifecycle')
    except LookupError as exc:
        raise TrustsConfigurationError(
            'TrustsImplementationConfig is not installed.'
        ) from exc


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

_MISSING = object()


def _publish_catalog(backend_cls, factory, *, path=None):
    """Store one catalog for ``backend_cls``. ``factory`` is the registration object."""

    if factory is None:
        catalogs.pop(backend_cls, None)
        return None
    published = path or factory.path or (
        '%s.%s' % (backend_cls.__module__, backend_cls.__qualname__)
    )
    catalog = built_catalog(factory, cls=backend_cls, path=published)
    catalogs[backend_cls] = catalog
    return catalog


@contextmanager
def bound_handle(backend, factory):
    """Publish ``factory`` as this backend class's catalog for one block."""

    cls = type(backend)
    previous = catalogs.get(cls, _MISSING)
    _publish_catalog(cls, factory)
    try:
        yield
    finally:
        if previous is _MISSING:
            catalogs.pop(cls, None)
        else:
            catalogs[cls] = previous


def render_configured_policy(*subjects):
    """Publish registries and render policy SQL through the listed catalogs."""

    with listed_relationship(subjects):
        return render_policy_sql_bytes()


@contextmanager
def published_subjects(subjects):
    """Store these objects as the listed catalogs, without wrapping them."""

    subjects = tuple(subjects)
    classes = _inquiry_backend_classes(len(subjects))
    saved = {cls: catalogs.get(cls, _MISSING) for cls in classes}
    paths = []
    for cls, subject in zip(classes, subjects):
        listing = '%s.%s' % (cls.__module__, cls.__name__)
        paths.append(listing)
        catalogs[cls] = subject
    with override_settings(AUTHENTICATION_BACKENDS=tuple(paths)):
        try:
            yield
        finally:
            for cls, previous in saved.items():
                if previous is _MISSING:
                    catalogs.pop(cls, None)
                else:
                    catalogs[cls] = previous


def render_published_subjects(*subjects):
    """Render policy SQL for objects already shaped like catalogs."""

    with published_subjects(subjects):
        return render_policy_sql_bytes()


def install_class_handle(backend_cls, factory):
    """Publish ``factory`` as ``backend_cls``'s catalog. ``None`` removes it."""
    _publish_catalog(backend_cls, factory)


def isolate_live_registry(config, registry, path):
    """Publish a standalone registry as the catalog for one listed path."""

    del config
    cls = import_string(path)
    _publish_catalog(cls, registry, path=path)
    return registry


def install_writable_registry(config, path, contribute=None):
    """Install a standalone factory as the catalog for one live path."""

    registry = RegistryFactory(path=path)
    if contribute is not None:
        contribute(registry)
    isolate_live_registry(config, registry, path)
    return registry


@contextmanager
def listed_relationship(factories):
    """List inquiry backends whose catalogs are these factories.

    ``authorized`` and the other consumers read ``get_backends()`` and
    ``get_catalog()``. This publishes one catalog per factory on a
    mixin class and sets ``AUTHENTICATION_BACKENDS`` to those classes
    for the block.
    """

    factories = tuple(factories)
    classes = _inquiry_backend_classes(len(factories))
    saved = {cls: catalogs.get(cls, _MISSING) for cls in classes}
    paths = []
    for cls, factory in zip(classes, factories):
        listing = '%s.%s' % (cls.__module__, cls.__name__)
        paths.append(listing)
        catalogs[cls] = built_catalog(
            factory, cls=cls, path=factory.path or listing,
        )
    with override_settings(AUTHENTICATION_BACKENDS=tuple(paths)):
        try:
            yield tuple(catalogs[cls] for cls in classes)
        finally:
            for cls, previous in saved.items():
                if previous is _MISSING:
                    catalogs.pop(cls, None)
                else:
                    catalogs[cls] = previous


def replay_recorder(factory, backend_cls):
    """Replay a backend recorder onto a factory this test owns."""

    recorder = recorders.get(backend_cls)
    if recorder is None:
        return factory
    rows = list(recorder.rows)
    for entry in rows:
        if entry[0] == 'condition':
            factory.set_user_condition(entry[1], entry[2], on=entry[3])
        elif entry[0] == 'override':
            factory.set_user_override(entry[1], entry[2], on=entry[3])
    for entry in rows:
        if entry[0] == 'filter':
            factory.register_permission_condition(entry[1], entry[2], entry[3])
        elif entry[0] == 'register':
            factory.register_public(**entry[1])
    return factory


@contextmanager
def unbound_named_filters(backend_cls):
    """Publish a catalog built with the recorder rows and no named-filter lookup."""

    saved = catalogs.get(backend_cls, _MISSING)
    live = None if saved is _MISSING else saved
    factory = RegistryFactory(
        compiler=backend_cls.query_compiler,
        path='' if live is None else live.path,
        family=backend_cls.family,
        user_model=standards.user_model,
    )
    factory.set_filter_lookup(None)
    replay_recorder(factory, backend_cls)
    catalogs[backend_cls] = built_catalog(factory, cls=backend_cls)
    try:
        yield catalogs[backend_cls]
    finally:
        if saved is _MISSING:
            catalogs.pop(backend_cls, None)
        else:
            catalogs[backend_cls] = saved


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


def clone_writable_registry(registry):
    """Copy records onto a new writable registry for test isolation."""

    cloned = RegistryFactory()
    cloned._by_root = {
        root: list(rows) for root, rows in registry._by_root.items()
    }
    cloned._order = list(registry._order)
    return cloned
