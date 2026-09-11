from django.apps import AppConfig as DjangoAppConfig
from django.core.exceptions import ImproperlyConfigured


def _listed_mixin_paths():
    """Exact AUTHENTICATION_BACKENDS mixin paths, de-duped by string.

    Imports classes, never ``load_backend()``. Duplicate identical
    strings collapse to one path. Different strings that resolve to
    the same class are an ambiguity error.
    """
    from django.conf import settings
    from django.utils.module_loading import import_string

    from trusts.core_backends import TrustModelBackendMixin
    from trusts.core import TrustsConfigurationError

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
    """Path-scoped registry store shared by kernel and implementations."""

    def _init_registries(self):
        # Import here: a module-level trusts.core import loads contenttypes
        # models before Apps.populate finishes. Backends may be imported
        # from _configured_trusts_paths; they must not import trusts.models.
        # Path-scoped store. Empty until ready() / _ensure. Never replace
        # this dict or an existing value on re-entry.
        self.registries = {}

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

    def _ensure(self, path):
        from trusts.core import TrustsRegistry

        if path not in self.registries:
            self.registries[path] = TrustsRegistry()
        return self.registries[path]

    def _exposed_registry(self, path):
        """Return the stored registry; freeze on first live read after ready."""
        registry = self._ensure(path)
        if self._apps_instance_ready():
            registry.freeze()
        return registry

    def configured_backend(self, path=None):
        """Return a handle for one exact configured Trusts path.

        With one Trusts path, ``path`` may be omitted. With zero or
        several, omission fails loud. An unconfigured path fails loud.
        After this AppConfig's Apps instance is ready, the stored
        registry is frozen before the handle is returned.
        """
        from django.utils.module_loading import import_string

        from trusts.core import BackendHandle, TrustsConfigurationError, compiler_for_class

        paths = self._configured_trusts_paths()
        if path is None:
            if len(paths) != 1:
                raise TrustsConfigurationError(
                    'configured_backend() needs an explicit path; got %r'
                    % (paths,)
                )
            path = paths[0]
        elif path not in paths:
            raise TrustsConfigurationError(
                '%r is not a configured Trusts backend' % (path,)
            )
        cls = import_string(path)
        return BackendHandle(
            path=path,
            registry=self._exposed_registry(path),
            compiler=compiler_for_class(cls),
        )

    def configured_handles(self):
        """Handles for every configured Trusts path, in settings order."""
        return tuple(
            self.configured_backend(path)
            for path in self._configured_trusts_paths()
        )

    def path_for_backend(self, backend):
        """Resolve a disposable backend instance to its configured path."""
        return self.path_for_class(type(backend))

    def path_for_class(self, cls):
        from django.utils.module_loading import import_string

        from trusts.core import TrustsConfigurationError

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
        from trusts.core import TrustsConfigurationError

        paths = self._configured_trusts_paths()
        if len(paths) != 1:
            raise TrustsConfigurationError(
                'registry alias needs exactly one configured Trusts path; '
                'got %r' % (paths,)
            )
        return self._exposed_registry(paths[0])

    @registry.setter
    def registry(self, value):
        from trusts.core import TrustsConfigurationError

        paths = self._configured_trusts_paths()
        if len(paths) != 1:
            raise TrustsConfigurationError(
                'registry alias needs exactly one configured Trusts path; '
                'got %r' % (paths,)
            )
        # After populate, the compatibility setter is a live surface:
        # it must not install a writable registry. Freeze the replacement
        # before storing so a caller-held reference cannot mutate late.
        # Assignment before ready stays writable for contributor setup.
        if self._apps_instance_ready():
            freeze = getattr(value, 'freeze', None)
            if callable(freeze):
                freeze()
        self.registries[paths[0]] = value


class TrustsImplementationConfig(_TrustsRegistryOwner, DjangoAppConfig):
    """Reusable implementation AppConfig helper. Not installed by core.

    Host implementations (Zero, GH, Windows, or a project app) subclass
    this and declare ``trusts_backend_paths``. Core's kernel
    ``AppConfig`` is *not* a subclass; ``isinstance`` resolvers skip it.
    """

    trusts_backend_paths = ()

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

        from trusts.core_backends import TrustModelBackendMixin
        from trusts.core import TrustsConfigurationError

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
        self._validate_ownership()
        for path in self.owned_backend_paths():
            self._ensure(path)
        from trusts import checks as _trusts_checks  # noqa: F401


class AppConfig(_TrustsRegistryOwner, DjangoAppConfig):
    name = 'trusts'
    verbose_name = "Django Trusts Add-in"
    label = 'trusts_core'
    # Preserve AutoField if a later kernel model is added. Historical
    # Trusts PKs live on ZeroConfig (label='trusts').
    default_auto_field = 'django.db.models.AutoField'

    def __init__(self, *args, **kwargs):
        super(AppConfig, self).__init__(*args, **kwargs)
        self._init_registries()

    def _configured_trusts_paths(self):
        return _listed_mixin_paths()

    def ready(self):
        # Auto ModelAdmin registration does not import trusts.models.
        # Concrete Trust/Role admins are owned by Zero when installed.
        from django.apps import apps as django_apps

        if django_apps.is_installed('django.contrib.admin'):
            from trusts.admin import register_auto_modeladmins
            register_auto_modeladmins()
        # Register system checks. Do not validate conditions here: raising
        # from ready() would block shell, migrations, and recovery.
        from trusts import checks as _trusts_checks  # noqa: F401

        # S3a: ensure one registry per configured Trusts path. Re-entry
        # must not replace self.registries or any stored object. Freeze
        # is applied by the supported handle surfaces after this Apps
        # instance is ready, not by replacing stored objects here.
        # Package Trust-as-content donation left this ready() on C2;
        # ZeroConfig.ready() registers TUP+TGP on the kernel store.
        paths = self._configured_trusts_paths()
        for path in paths:
            self._ensure(path)


def kernel_config(apps_registry=None):
    """Return the kernel ``trusts.apps.AppConfig`` by class identity.

    Does not look up the string label ``'trusts'`` (that label is Zero
    after C2). Optional ``apps_registry`` is an ``Apps`` instance; the
    default is Django's global registry.
    """
    from django.apps import apps as django_apps

    registry = django_apps if apps_registry is None else apps_registry
    matches = [
        config for config in registry.get_app_configs()
        if type(config) is AppConfig
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise LookupError('No installed Trusts kernel AppConfig.')
    raise LookupError(
        'Multiple Trusts kernel AppConfig instances: %r' % (matches,)
    )


def implementation_configs(apps_registry=None):
    """Installed ``TrustsImplementationConfig`` instances on one Apps registry.

    Kernel ``AppConfig`` is excluded (it is not a subclass). Optional
    ``apps_registry`` is an ``Apps`` instance; the default is Django's
    global registry. Isolated tests pass the isolated Apps.
    """
    from django.apps import apps as django_apps

    registry = django_apps if apps_registry is None else apps_registry
    return tuple(
        config for config in registry.get_app_configs()
        if isinstance(config, TrustsImplementationConfig)
    )


def implementation_for_path(path, apps_registry=None):
    """Return the unique implementation that owns ``path``."""
    from trusts.core import TrustsConfigurationError

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
    ``None`` when no owner exists so the Step I mixin can fall back to
    ``kernel_config()``. Duplicate owners always fail loud.
    """
    from django.utils.module_loading import import_string

    from trusts.core import TrustsConfigurationError

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
