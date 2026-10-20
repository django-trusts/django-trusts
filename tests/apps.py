from contextlib import contextmanager

from django.apps import AppConfig

ZERO_BACKEND = 'trusts.zero.backends.TrustModelBackend'


def built_registries(items):
    """Build factories for a direct ``granted`` / filter call.

    A factory is built now. A catalog is returned as itself. A registry
    is returned as itself. ``None`` and other objects pass through so a
    caller can still prove a missing registry fails closed.
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
        if item is None or isinstance(item, (Catalog, Registry)):
            built.append(item)
        elif isinstance(item, RegistryFactory):
            built.append(item.build_registry())
        else:
            built.append(item)
    return tuple(built)


def scoped_permitted_content(queryset, user, permission, *, content,
                             registries, **skip_flags):
    """Prefix filter for one explicit registry in a unit test.

    The public filter walks ``get_catalog()`` and takes no registry
    argument. This helper is the direct registry question.
    """
    parts = []
    for registry in built_registries(registries) or ():
        if registry.family != 'relationship':
            continue
        parts.append(registry.filter_by_permitted_content(
            queryset, user, permission, content=content, **skip_flags,
        ))
    if not parts:
        return queryset.none()
    if len(parts) == 1:
        return parts[0]
    combined = parts[0]
    for part in parts[1:]:
        combined = combined | part
    return combined


@contextmanager
def override_catalog(backend_cls, factory, path):
    """Publish one catalog for ``backend_cls`` and restore the previous entry."""
    from trusts.backends import catalogs
    from trusts.compile.catalogs import Catalog

    saved = catalogs.get(backend_cls, _MISSING)
    catalogs[backend_cls] = Catalog(
        cls=backend_cls,
        path=path,
        family=getattr(factory, 'family', 'relationship'),
        registry=factory.build_registry(),
    )
    try:
        yield catalogs[backend_cls]
    finally:
        if saved is _MISSING:
            catalogs.pop(backend_cls, None)
        else:
            catalogs[backend_cls] = saved


def configured_catalog(path, explicit=None):
    """Catalog stored for one ``AUTHENTICATION_BACKENDS`` dotted path.

    The optional second argument is that path when a caller still passes
    an app config as the first argument. The config does not own paths.
    """
    from django.utils.module_loading import import_string

    from trusts.backends import catalogs
    from trusts.errors import TrustsConfigurationError

    if explicit is not None:
        path = explicit
    if not isinstance(path, str):
        raise TrustsConfigurationError(
            'configured_catalog takes the dotted AUTHENTICATION_BACKENDS '
            'path, not %r' % (path,)
        )
    cls = import_string(path)
    catalog = catalogs.get(cls) if isinstance(cls, type) else None
    if catalog is None or catalog.path != path:
        for stored in catalogs.values():
            if stored.path == path:
                return stored
        raise TrustsConfigurationError(
            '%r is not a configured Trusts backend' % (path,)
        )
    return catalog


@contextmanager
def empty_catalogs():
    """Clear built catalogs for one sweep, then restore them."""
    from trusts.backends import catalogs

    saved = dict(catalogs)
    catalogs.clear()
    try:
        yield
    finally:
        catalogs.clear()
        catalogs.update(saved)


def sweep_listed_backends():
    """Run the ready-time build against the current ``AUTHENTICATION_BACKENDS``."""
    from django.conf import settings
    from django.contrib.auth import get_user_model

    from trusts.compile.factory import build_configured_catalogs

    build_configured_catalogs(
        tuple(settings.AUTHENTICATION_BACKENDS),
        get_user_model(),
    )


def live_config(apps_registry=None):
    """The sweep config. It does not own a backend path."""
    from django.apps import apps as django_apps

    from trusts.errors import TrustsConfigurationError

    registry = django_apps if apps_registry is None else apps_registry
    try:
        return registry.get_app_config('trusts_lifecycle')
    except LookupError as exc:
        raise TrustsConfigurationError(
            'TrustsImplementationConfig is not installed.'
        ) from exc


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
        from django.contrib.auth import get_backends

        from trusts.backends import TrustModelBackendMixin

        if self.apps is not django_apps:
            return
        classes = []
        for backend in get_backends():
            if isinstance(backend, TrustModelBackendMixin):
                cls = type(backend)
                if cls not in classes:
                    classes.append(cls)
        if len(classes) != 1:
            return
        try:
            TrustUserPermission = self.apps.get_model(
                'trusts', 'TrustUserPermission',
            )
            from tests.models import Category, TestGroupJunction, Ticket
        except (LookupError, ImportError):
            return
        self._donate_tup(
            classes[0], TrustUserPermission, Category, Ticket,
            TestGroupJunction,
        )

    def _donate_tup(self, backend_cls, TrustUserPermission, Category, Ticket,
                    TestGroupJunction):
        recorder = backend_cls().get_registry()
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


def _publish_catalog(backend_cls, factory, *, path=None):
    """Store one catalog for ``backend_cls``. ``factory`` is the registration object."""
    from trusts.backends import catalogs
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
        registry=built,
    )
    return built


@contextmanager
def bound_handle(backend, factory):
    """Publish ``factory`` as this backend class's catalog for one block."""
    from trusts.backends import catalogs

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
    from trusts.inspect.snapshot import render_policy_sql_bytes

    with listed_relationship(subjects):
        return render_policy_sql_bytes()


@contextmanager
def published_subjects(subjects):
    """Store these objects as the listed catalogs, without wrapping them."""
    from django.test import override_settings

    from trusts.backends import catalogs

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
    from trusts.inspect.snapshot import render_policy_sql_bytes

    with published_subjects(subjects):
        return render_policy_sql_bytes()


def install_class_handle(backend_cls, factory):
    """Publish ``factory`` as ``backend_cls``'s catalog. ``None`` removes it."""
    _publish_catalog(backend_cls, factory)


def isolate_live_registry(config, registry, path):
    """Publish a standalone registry as the catalog for one listed path."""
    from django.utils.module_loading import import_string

    del config
    cls = import_string(path)
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


@contextmanager
def listed_relationship(factories):
    """List inquiry backends whose catalogs are these factories.

    ``authorized`` and the other consumers read ``get_backends()`` and
    ``get_catalog()``. This publishes one catalog per factory on a
    mixin class and sets ``AUTHENTICATION_BACKENDS`` to those classes
    for the block.
    """
    from django.test import override_settings

    from trusts.backends import catalogs

    from trusts.compile.catalogs import Catalog
    from trusts.compile.factory import RegistryFactory
    from trusts.plan.registry import Registry

    factories = tuple(factories)
    classes = _inquiry_backend_classes(len(factories))
    saved = {cls: catalogs.get(cls, _MISSING) for cls in classes}
    paths = []
    prepared = []
    for cls, factory in zip(classes, factories):
        listing = '%s.%s' % (cls.__module__, cls.__name__)
        paths.append(listing)
        if isinstance(factory, Catalog):
            raise TypeError(
                'listed_relationship takes a registry or factory, not a catalog.'
            )
        if isinstance(factory, Registry):
            subject = factory
        elif isinstance(factory, RegistryFactory):
            subject = factory.build_registry()
        else:
            subject = factory.build_registry()
        prepared.append((cls, subject.path or listing, subject))
    for cls, path, subject in prepared:
        catalogs[cls] = Catalog(
            cls=cls,
            path=path,
            family=subject.family,
            registry=subject,
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
    from trusts.backends import recorders

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
    from trusts.backends import catalogs
    from trusts.compile.catalogs import Catalog
    from trusts.compile.factory import RegistryFactory
    import trusts.plan.standards as standards

    saved = catalogs.get(backend_cls, _MISSING)
    live = None if saved is _MISSING else saved
    factory = RegistryFactory(
        compiler=backend_cls.query_compiler,
        path='' if live is None else live.path,
        family=backend_cls.family,
        user_model=standards.user_model,
    )
    replay_recorder(factory, backend_cls)
    factory.set_filter_lookup(None)
    catalogs[backend_cls] = Catalog(
        cls=backend_cls,
        path=factory.path,
        family=factory.family,
        registry=factory.build_registry(),
    )
    try:
        yield catalogs[backend_cls]
    finally:
        if saved is _MISSING:
            catalogs.pop(backend_cls, None)
        else:
            catalogs[backend_cls] = saved


def _inquiry_backend_classes(count):
    import sys

    from django.contrib.auth.backends import ModelBackend

    from trusts.backends import TrustModelBackendMixin

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
    """Copy records onto a new writable registry for test isolation."""
    from trusts.compile.factory import RegistryFactory

    cloned = RegistryFactory()
    cloned._by_root = {
        root: list(rows) for root, rows in registry._by_root.items()
    }
    cloned._order = list(registry._order)
    return cloned
