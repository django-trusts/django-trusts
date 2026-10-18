from __future__ import annotations

from typing import TYPE_CHECKING

from django.apps import AppConfig as DjangoAppConfig
from django.core.exceptions import ImproperlyConfigured

from trusts._meta_options import _ensure_permission_conditions_option

if TYPE_CHECKING:
    from trusts.plan.handles import BackendHandle
    from trusts.plan.registry import HeldBackend

# Hosts load this module before Django constructs their models. Register
# Meta.permission_conditions here so applications do not import _ir.
_ensure_permission_conditions_option()


def _listed_mixin_paths():
    """Exact AUTHENTICATION_BACKENDS mixin paths, de-duped by string.

    Imports classes, never ``load_backend()``. Duplicate identical
    strings collapse to one path. Different strings that resolve to
    the same class are an ambiguity error.
    """
    from django.conf import settings
    from django.utils.module_loading import import_string

    from trusts.backends import TrustModelBackendMixin
    from trusts.errors import TrustsConfigurationError

    listed = getattr(settings, 'AUTHENTICATION_BACKENDS', ()) or ()
    paths = []
    class_to_paths = {}
    for path in listed:
        if path in paths:
            continue
        cls = import_string(path)
        if not issubclass(cls, TrustModelBackendMixin):
            continue
        paths.append(path)
        class_to_paths.setdefault(cls, []).append(path)
    ambiguous = [
        class_paths for class_paths in class_to_paths.values()
        if len(class_paths) > 1
    ]
    if ambiguous:
        raise TrustsConfigurationError(
            'Configured Trusts backend class is listed under multiple '
            'paths: %s.' % (
                '; '.join(
                    '%r → %s' % (class_paths[0], class_paths)
                    for class_paths in ambiguous
                ),
            )
        )
    return tuple(paths)


class _TrustsRegistryOwner(object):
    """Path-scoped registry store shared by implementation AppConfigs."""

    def _init_registries(self):
        # Import here: a module-level compile.factory import loads contenttypes
        # models before Apps.populate finishes. Backends may be imported
        # from _configured_trusts_paths; they must not import trusts.models.
        # Path-scoped store. Empty until ready() / _ensure. Never replace
        # this dict or an existing value on re-entry.
        self.registries = {}
        # Held lowered objects, keyed by the same path as ``registries``.
        # ``configured_backend()`` lowers the raw store once, holds the
        # result here, and returns that identical object until a new
        # registration (raw-version bump) invalidates it. This dict is
        # deliberately NOT named ``registries``: it holds lowered
        # answers, not registrations.
        self._lowered_by_path = {}

    def _configured_trusts_paths(self):
        raise NotImplementedError

    def _apps_instance_ready(self):
        """True when *this* AppConfig's Apps instance has finished populate.

        Uses ``self.apps.ready``, not Django's global ``apps`` object and
        not ``apps_ready``. A manually constructed AppConfig with no
        bound Apps stays unready. During ``Apps.populate`` phase 3,
        contributor ``ready()`` methods run while this flag is still
        false.
        """
        apps_registry = getattr(self, 'apps', None)
        return bool(apps_registry is not None and apps_registry.ready)

    def _create_registry(self, path):
        """Construct the path-owned registry. Protected / provisional.

        The default is Core ``TrustsRegistry``. An extension config may
        return a family-owned store. ``path`` is the exact configured
        backend string; the relationship default does not key on it.
        """
        from trusts.compile.factory import TrustsRegistry

        return TrustsRegistry()

    def _create_handle(self, path, registry, compiler):
        """Construct the held lowered object for ``path``.

        Protected / provisional. The default lowers ``registry``
        (the config-held raw ``TrustsRegistry``) once and wraps the
        result in a ``HeldBackend`` carrying ``path`` and
        ``compiler``. An extension config may return a family-owned
        held object, or a legacy ``BackendHandle``, which
        ``configured_backend()`` promotes to a held object. Not a
        public family API. A lowering failure raises and holds
        nothing.
        """
        from trusts.plan.registry import HeldBackend

        built = registry.build_registry() if hasattr(registry, 'build_registry') else registry
        if built is None:
            from trusts.errors import TrustsConfigurationError

            raise TrustsConfigurationError(
                'No registry for backend path %r.' % (path,)
            )
        kwargs = {}
        if hasattr(built, 'condition_lookup'):
            kwargs['condition_lookup'] = built.condition_lookup
        return HeldBackend(
            path=path, compiler=compiler, registry=registry,
            source_version=getattr(registry, '_raw_version', None),
            records=getattr(built, 'records', ()),
            delegations=getattr(built, 'delegations', ()),
            conditions=getattr(built, 'conditions', None),
            user_conditions=getattr(built, 'user_conditions', None),
            user_override=getattr(built, 'user_override', None),
            **kwargs,
        )

    def _promote_to_held(self, candidate, path, registry, compiler):
        """Hold ``candidate`` as the lowered object for ``path``.

        A ``HeldBackend`` is held as-is. A legacy ``BackendHandle``
        (from an extension ``_create_handle``) is promoted by
        lowering its registry. Anything else is held as-is only
        when it already answers as a registry (duck-typed in tests).
        """
        from trusts.plan.registry import HeldBackend

        if isinstance(candidate, HeldBackend):
            held = candidate
        elif hasattr(candidate, 'registry') and hasattr(candidate, 'compiler'):
            held = self._create_handle(
                candidate.path or path,
                candidate.registry,
                candidate.compiler,
            )
            # _create_handle above is this same (possibly overridden)
            # method only for the default class; for an overridden
            # factory that returned a handle, build the held object
            # directly to avoid recursing into the override again.
            if not isinstance(held, HeldBackend):
                held = TrustsImplementationConfig._create_handle(
                    self, candidate.path or path, candidate.registry,
                    candidate.compiler,
                )
        else:
            held = candidate
            # Duck-typed registry candidate: annotate it so the
            # identity/staleness check in configured_backend() can
            # recognise it as the held object for this raw store.
            try:
                held.path = path
                held.compiler = compiler
                held.source_version = getattr(registry, '_raw_version', None)
                held._held_registry = registry
            except Exception:
                pass
        return held

    def _ensure(self, path):
        if path not in self.registries:
            self.registries[path] = self._create_registry(path)
        return self.registries[path]

    def _exposed_registry(self, path):
        """Return the stored registry for ``path``.

        The stored builder is returned as-is at any readiness stage;
        each backend question builds a fresh ``Registry`` from its
        current records, so late registration takes effect on the
        next question.
        """
        return self._ensure(path)

    def configured_backend(self, path=None) -> HeldBackend:
        """Return THE held lowered backend object for one Trusts path.

        This is the one obtaining call (config method; also
        ``trusts.apps.configured_backend``). Chain: resolve ``path``
        -> this owning config -> ``self.registries[path]`` (the raw
        ``TrustsRegistry`` holding every ``register()`` call) ->
        lower it once -> HOLD the resulting object in
        ``self._lowered_by_path[path]`` -> return it. Every later
        call returns that identical object until a new registration
        bumps the raw version, which invalidates the held object;
        the next call then lowers, holds, and returns a fresh one.
        A failed lowering caches nothing and raises. With one
        Trusts path, ``path`` may be omitted; with zero or several,
        omission fails loud. An unconfigured path fails loud.
        """
        from django.utils.module_loading import import_string

        from trusts.errors import TrustsConfigurationError
        from trusts.plan.aggregates import compiler_for_class

        paths = self._configured_trusts_paths()
        if path is None:
            if len(paths) != 1:
                raise TrustsConfigurationError(
                    'configured_backend() needs an explicit path; got %r'
                    % (paths,)
                )
            path = paths[0]
        elif path not in paths:
            apps_registry = getattr(self, 'apps', None)
            try:
                other = implementation_for_path(path, apps_registry)
            except TrustsConfigurationError:
                other = None
            if other is not None and other is not self:
                return other.configured_backend(path)
            raise TrustsConfigurationError(
                '%r is not a configured Trusts backend' % (path,)
            )
        cls = import_string(path)
        compiler = compiler_for_class(cls)
        registry = self._exposed_registry(path)
        if not hasattr(self, '_lowered_by_path'):
            self._init_registries_lowered_only()
        held = self._lowered_by_path.get(path)
        held_registry = getattr(held, 'registry', None) if held is not None else None
        if held_registry is None and held is not None:
            held_registry = getattr(held, '_held_registry', None)
        if (
            held is not None
            and held_registry is registry
            and getattr(held, 'compiler', None) is compiler
            and getattr(held, 'source_version', None)
            == getattr(registry, '_raw_version', None)
        ):
            return held
        try:
            candidate = self._create_handle(path, registry, compiler)
            held = self._promote_to_held(candidate, path, registry, compiler)
        except Exception:
            # Failed lowering holds nothing new.
            self._lowered_by_path.pop(path, None)
            raise
        self._lowered_by_path[path] = held
        return held

    def _init_registries_lowered_only(self):
        # Configs constructed before the held store existed (or by
        # ``__new__`` in tests) get the dict lazily.
        self._lowered_by_path = {}

    def configured_handles(self):
        """Held lowered objects for every Trusts path, in settings order.

        Name kept for compatibility; each item is what
        ``configured_backend(path)`` returns (a held object, not a
        per-call handle).
        """
        return tuple(
            self.configured_backend(path)
            for path in self._configured_trusts_paths()
        )

    def path_for_backend(self, backend):
        """Resolve a disposable backend instance to its configured path."""
        return self.path_for_class(type(backend))

    def path_for_class(self, cls):
        from django.utils.module_loading import import_string

        from trusts.errors import TrustsConfigurationError

        matches = [
            path for path in self._configured_trusts_paths()
            if import_string(path) is cls
        ]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise TrustsConfigurationError(
                '%r is not a configured Trusts backend' % (cls,)
            )
        raise TrustsConfigurationError(
            '%r is listed under multiple paths: %s' % (cls, matches)
        )

    @property
    def registry(self):
        """One-path compatibility alias of ``registries[that_path]``.

        Zero or several configured Trusts paths fail loud. Isolated
        tests keep constructing their own ``TrustsRegistry()``.
        """
        from trusts.errors import TrustsConfigurationError

        paths = self._configured_trusts_paths()
        if len(paths) != 1:
            raise TrustsConfigurationError(
                'registry alias needs exactly one configured Trusts path; '
                'got %r' % (paths,)
            )
        return self._exposed_registry(paths[0])

    @registry.setter
    def registry(self, value):
        from trusts.errors import TrustsConfigurationError

        paths = self._configured_trusts_paths()
        if len(paths) != 1:
            raise TrustsConfigurationError(
                'registry alias needs exactly one configured Trusts path; '
                'got %r' % (paths,)
            )
        # Install the replacement as-is at any readiness stage.
        # Registration on it (by a contributor, or through a
        # caller-held reference) takes effect on the next build.
        self.registries[paths[0]] = value
        lowered = getattr(self, '_lowered_by_path', None)
        if lowered is not None:
            lowered.pop(paths[0], None)


class TrustsImplementationConfig(_TrustsRegistryOwner, DjangoAppConfig):
    """Reusable implementation AppConfig helper. Not installed by core.

    Host implementations (Zero, GH, Windows, or a project app) subclass
    this and declare ``trusts_backend_paths``. Core ships no AppConfig
    and no Django app label; do not list ``'trusts'`` in INSTALLED_APPS.

    Protected provisional hooks ``_create_registry``, ``_create_handle``,
    and ``_authorization_family`` are backend plumbing for first-party
    extensions. They are not a public family API.
    """

    default = False
    trusts_backend_paths = ()
    # Protected / provisional family discriminator. Not a public API.
    # Relationship-family configs keep the default; an extension config
    # may override it. Core list/guard/common-permission aggregates
    # include only ``"relationship"`` handles.
    _authorization_family = 'relationship'

    def __init__(self, *args, **kwargs):
        super(TrustsImplementationConfig, self).__init__(*args, **kwargs)
        self._init_registries()

    def owned_backend_paths(self):
        return tuple(self.trusts_backend_paths)

    def _configured_trusts_paths(self):
        owned = set(self.owned_backend_paths())
        return tuple(
            path for path in _listed_mixin_paths() if path in owned
        )

    def _validate_ownership(self):
        from django.utils.module_loading import import_string

        from trusts.backends import TrustModelBackendMixin
        from trusts.errors import TrustsConfigurationError

        owned = self.owned_backend_paths()
        if not owned:
            raise ImproperlyConfigured(
                '%s.trusts_backend_paths must be a non-empty tuple of '
                'exact AUTHENTICATION_BACKENDS paths.' % type(self).__name__
            )
        if len(set(owned)) != len(owned):
            raise ImproperlyConfigured(
                '%s.trusts_backend_paths must not repeat a path: %r'
                % (type(self).__name__, owned)
            )

        listed = _listed_mixin_paths()
        listed_set = set(listed)
        for path in owned:
            cls = import_string(path)
            if not issubclass(cls, TrustModelBackendMixin):
                raise TrustsConfigurationError(
                    '%s owns %r which is not a TrustModelBackendMixin.'
                    % (type(self).__name__, path)
                )
            if path not in listed_set:
                raise ImproperlyConfigured(
                    '%s owns %r but that path is not listed in '
                    'AUTHENTICATION_BACKENDS.'
                    % (type(self).__name__, path)
                )

        apps_registry = getattr(self, 'apps', None)
        for path in owned:
            others = [
                config for config in implementation_configs(apps_registry)
                if config is not self and path in config.owned_backend_paths()
            ]
            if others:
                raise TrustsConfigurationError(
                    'Backend path %r has multiple implementation owners: %r'
                    % (path, [self] + others)
                )

    def ready(self):
        # Discover trusts_policy_sql after models are populated. Core is not
        # an installed app and does not ship trusts/management (#129), so
        # the command attaches here. Subclasses that replace ready() must
        # call super() or the command stays unregistered.
        from trusts.inspect.commands import install_policy_commands

        install_policy_commands()
        self._validate_ownership()
        for path in self.owned_backend_paths():
            self._ensure(path)
        from trusts.inspect import checks as _trusts_checks  # noqa: F401


def configured_backend(path=None, apps_registry=None):
    """Module-level form of the one obtaining call.

    ``from trusts.apps import configured_backend`` -- delegates to
    the owning config's ``configured_backend()``; there is no second
    obtaining logic here. With no ``path``, exactly one configured
    Trusts path across all implementations is required.
    """
    from trusts.errors import TrustsConfigurationError

    if path is not None:
        return implementation_for_path(path, apps_registry).configured_backend(path)
    paths = []
    for config in implementation_configs(apps_registry):
        paths.extend(config._configured_trusts_paths())
    if len(paths) != 1:
        raise TrustsConfigurationError(
            'configured_backend() needs an explicit path; got %r' % (tuple(paths),)
        )
    return implementation_for_path(paths[0], apps_registry).configured_backend(paths[0])


def configured_implementation_handles(apps_registry=None):
    """Held objects from every installed implementation, in owner then path order.

    Empty when no ``TrustsImplementationConfig`` is installed. This
    listing is not the Core list/guard aggregate: callers that authorize
    a QuerySet, view guard, or common-permission set must use
    ``_relationship_implementation_handles``.
    """
    handles = []
    for config in implementation_configs(apps_registry):
        handles.extend(config.configured_handles())
    return tuple(handles)


def _handle_authorization_family(handle, apps_registry=None):
    """Family of the implementation that owns ``handle.path``.

    Unowned or pathless handles default to ``"relationship"`` so isolated
    compiler tests stay on the Core contract. Missing owners do not raise.
    """
    from trusts.errors import TrustsConfigurationError

    path = getattr(handle, 'path', None)
    if not path:
        return 'relationship'
    try:
        config = implementation_for_path(path, apps_registry)
    except TrustsConfigurationError:
        return 'relationship'
    return getattr(config, '_authorization_family', 'relationship')


def _relationship_family_handles(handles, apps_registry=None):
    """Keep handles whose owned family is ``"relationship"``."""
    return tuple(
        handle for handle in handles
        if _handle_authorization_family(handle, apps_registry) == 'relationship'
    )


def _relationship_implementation_handles(apps_registry=None):
    """Configured handles that participate in Core list/guard aggregates."""
    return _relationship_family_handles(
        configured_implementation_handles(apps_registry),
        apps_registry,
    )


def implementation_configs(apps_registry=None):
    """Installed ``TrustsImplementationConfig`` instances on one Apps registry.

    Optional ``apps_registry`` is an ``Apps`` instance; the default is
    Django's global registry. Isolated tests pass the isolated Apps.
    """
    from django.apps import apps as django_apps

    registry = django_apps if apps_registry is None else apps_registry
    return tuple(
        config for config in registry.get_app_configs()
        if isinstance(config, TrustsImplementationConfig)
    )


def implementation_for_path(path, apps_registry=None):
    """Return the unique implementation that owns ``path``."""
    from trusts.errors import TrustsConfigurationError

    matches = [
        config for config in implementation_configs(apps_registry)
        if path in config.owned_backend_paths()
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise TrustsConfigurationError(
            'No implementation owns backend path %r.' % (path,)
        )
    raise TrustsConfigurationError(
        'Backend path %r has multiple implementation owners: %r'
        % (path, matches)
    )


def implementation_for_class(cls, apps_registry=None, required=True):
    """Return the unique implementation that owns ``cls``.

    Ownership is exact class identity of an owned import path
    (``import_string(path) is cls``). ``required=False`` returns
    ``None`` when no owner exists. Duplicate owners always fail loud.
    Supported mixins require an owner.
    """
    from django.utils.module_loading import import_string

    from trusts.errors import TrustsConfigurationError

    matches = []
    for config in implementation_configs(apps_registry):
        for path in config.owned_backend_paths():
            if import_string(path) is cls:
                if config not in matches:
                    matches.append(config)
                break
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        raise TrustsConfigurationError(
            '%r has multiple implementation owners: %r' % (cls, matches)
        )
    if required:
        raise TrustsConfigurationError(
            '%r has no implementation owner.' % (cls,)
        )
    return None
