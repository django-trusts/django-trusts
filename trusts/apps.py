from django.apps import AppConfig as DjangoAppConfig


class AppConfig(DjangoAppConfig):
    name = 'trusts'
    verbose_name = "Django Trusts Add-in"
    label = 'trusts_core'
    default = True
    # Preserve AutoField if a later kernel model is added. Historical
    # Trusts PKs live on ZeroConfig (label='trusts').
    default_auto_field = 'django.db.models.AutoField'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Import here: a module-level trusts.core import loads contenttypes
        # models before Apps.populate finishes. Backends may be imported
        # from _configured_trusts_paths; they must not import trusts.models.
        # Path-scoped store. Empty until ready() / _ensure. Never replace
        # this dict or an existing value on re-entry.
        self.registries = {}

    def _configured_trusts_paths(self):
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


class TrustsImplementationConfig(DjangoAppConfig):
    """Reusable library helper: implementation-owned registry lifecycle.

    Not an installed Django app. Hosts subclass this and declare the
    exact ``AUTHENTICATION_BACKENDS`` import paths they own. Resolvers
    find owners by scanning the active ``Apps`` registry with
    ``isinstance(config, TrustsImplementationConfig)``.
    """

    default = False
    trusts_backend_paths = ()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Path-scoped store. Empty until ready() / _ensure. Never
        # replace this dict or an existing value on re-entry.
        self.registries = {}

    def owned_backend_paths(self):
        return tuple(self.trusts_backend_paths)

    def _require_owned_paths(self):
        from django.core.exceptions import ImproperlyConfigured

        paths = self.owned_backend_paths()
        if not paths:
            raise ImproperlyConfigured(
                '%s.trusts_backend_paths must be a non-empty sequence of '
                'exact backend import paths.' % type(self).__name__
            )
        if len(paths) != len(set(paths)):
            raise ImproperlyConfigured(
                '%s.trusts_backend_paths contains duplicate paths: %r'
                % (type(self).__name__, paths)
            )
        return paths

    def _apps_instance_ready(self):
        """True when *this* AppConfig's Apps instance has finished populate."""
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
        """Return a handle for one exact owned Trusts path.

        With one owned path, ``path`` may be omitted. With zero or
        several, omission fails loud. An unowned path fails loud.
        After this AppConfig's Apps instance is ready, the stored
        registry is frozen before the handle is returned.
        """
        from django.utils.module_loading import import_string

        from trusts.core import BackendHandle, TrustsConfigurationError, compiler_for_class

        paths = self.owned_backend_paths()
        if path is None:
            if len(paths) != 1:
                raise TrustsConfigurationError(
                    'configured_backend() needs an explicit path; got %r'
                    % (paths,)
                )
            path = paths[0]
        elif path not in paths:
            raise TrustsConfigurationError(
                '%r is not owned by %s' % (path, type(self).__name__)
            )
        cls = import_string(path)
        return BackendHandle(
            path=path,
            registry=self._exposed_registry(path),
            compiler=compiler_for_class(cls),
        )

    def configured_handles(self):
        """Handles for every owned Trusts path, in declaration order."""
        return tuple(
            self.configured_backend(path)
            for path in self.owned_backend_paths()
        )

    def path_for_backend(self, backend):
        """Resolve a disposable backend instance to its owned path."""
        return self.path_for_class(type(backend))

    def path_for_class(self, cls):
        from django.utils.module_loading import import_string

        from trusts.core import TrustsConfigurationError

        matches = [
            path for path in self.owned_backend_paths()
            if import_string(path) is cls
        ]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise TrustsConfigurationError(
                '%r is not owned by %s' % (cls, type(self).__name__)
            )
        raise TrustsConfigurationError(
            '%r is listed under multiple owned paths: %s' % (cls, matches)
        )

    @property
    def registry(self):
        """One-path compatibility alias of ``registries[that_path]``."""
        from trusts.core import TrustsConfigurationError

        paths = self.owned_backend_paths()
        if len(paths) != 1:
            raise TrustsConfigurationError(
                'registry alias needs exactly one owned Trusts path; '
                'got %r' % (paths,)
            )
        return self._exposed_registry(paths[0])

    @registry.setter
    def registry(self, value):
        from trusts.core import TrustsConfigurationError

        paths = self.owned_backend_paths()
        if len(paths) != 1:
            raise TrustsConfigurationError(
                'registry alias needs exactly one owned Trusts path; '
                'got %r' % (paths,)
            )
        if self._apps_instance_ready():
            freeze = getattr(value, 'freeze', None)
            if callable(freeze):
                freeze()
        self.registries[paths[0]] = value

    def ready(self):
        from django.core.exceptions import ImproperlyConfigured
        from django.utils.module_loading import import_string

        from trusts.core_backends import TrustModelBackendMixin

        paths = self._require_owned_paths()
        class_to_paths = {}
        for path in paths:
            cls = import_string(path)
            if not issubclass(cls, TrustModelBackendMixin):
                raise ImproperlyConfigured(
                    '%s owns %r which is not a TrustModelBackendMixin.'
                    % (type(self).__name__, path)
                )
            class_to_paths.setdefault(cls, []).append(path)
            self._ensure(path)
        ambiguous = [
            class_paths for class_paths in class_to_paths.values()
            if len(class_paths) > 1
        ]
        if ambiguous:
            raise _implementation_error(
                'ambiguous_path',
                'Owned Trusts backend class is listed under multiple '
                'paths: %s.' % (
                    '; '.join(
                        '%r → %s' % (class_paths[0], class_paths)
                        for class_paths in ambiguous
                    ),
                ),
            )
        apps_registry = getattr(self, 'apps', None)
        if apps_registry is not None:
            _assert_unique_implementation_ownership(apps_registry)
        import trusts.checks  # noqa: F401


def _apps_registry(apps_registry=None):
    from django.apps import apps as django_apps

    return django_apps if apps_registry is None else apps_registry


def implementation_configs(apps_registry=None):
    """Installed ``TrustsImplementationConfig`` instances in Apps order."""
    return tuple(
        config for config in _apps_registry(apps_registry).get_app_configs()
        if isinstance(config, TrustsImplementationConfig)
    )


def _implementation_error(reason, message):
    from trusts.core import TrustsConfigurationError

    error = TrustsConfigurationError(message)
    error.reason = reason
    return error


def _owners_for_path(path, apps_registry=None):
    return tuple(
        config for config in implementation_configs(apps_registry)
        if path in config.owned_backend_paths()
    )


def _owners_and_paths_for_class(cls, apps_registry=None):
    from django.utils.module_loading import import_string

    owners = []
    paths_by_owner = {}
    for config in implementation_configs(apps_registry):
        matches = [
            path for path in config.owned_backend_paths()
            if import_string(path) is cls
        ]
        if matches:
            owners.append(config)
            paths_by_owner[config] = tuple(matches)
    return tuple(owners), paths_by_owner


def _assert_unique_implementation_ownership(apps_registry=None):
    """Reject duplicate owners, ambiguous class paths, and identity mismatch."""
    from django.utils.module_loading import import_string

    path_owners = {}
    class_owners = {}
    for config in implementation_configs(apps_registry):
        for path in config.owned_backend_paths():
            path_owners.setdefault(path, []).append(config)
            cls = import_string(path)
            class_owners.setdefault(cls, []).append((config, path))
    for path, owners in path_owners.items():
        if len(owners) > 1:
            raise _implementation_error(
                'duplicate_implementation',
                '%r has multiple implementation owners: %r' % (path, owners),
            )
    for cls, claimed in class_owners.items():
        owners = []
        paths = []
        for config, path in claimed:
            if config not in owners:
                owners.append(config)
            if path not in paths:
                paths.append(path)
        if len(owners) > 1:
            raise _implementation_error(
                'duplicate_implementation',
                '%r has multiple implementation owners: %r' % (cls, owners),
            )
        if len(paths) > 1:
            raise _implementation_error(
                'ambiguous_path',
                '%r is listed under multiple owned paths: %s' % (cls, paths),
            )
        owner, owned_path = claimed[0]
        if import_string(owned_path) is not cls:
            raise _implementation_error(
                'identity_mismatch',
                'class/path identity mismatch: %r imports %r'
                % (owned_path, cls),
            )


def implementation_for_path(path, apps_registry=None):
    """Return the unique implementation owner of an exact backend path."""
    from django.utils.module_loading import import_string

    _assert_unique_implementation_ownership(apps_registry)
    matches = _owners_for_path(path, apps_registry)
    if len(matches) == 1:
        owner = matches[0]
        cls = import_string(path)
        owned_path = owner.path_for_class(cls)
        if owned_path != path:
            raise _implementation_error(
                'identity_mismatch',
                'class/path identity mismatch: %r imports %r owned as %r'
                % (path, cls, owned_path),
            )
        return owner
    if not matches:
        raise _implementation_error(
            'missing_implementation',
            '%r has no implementation owner' % (path,),
        )
    raise _implementation_error(
        'duplicate_implementation',
        '%r has multiple implementation owners: %r' % (path, matches),
    )


def implementation_for_class(cls, apps_registry=None):
    """Return the unique implementation owner of a backend class."""
    _assert_unique_implementation_ownership(apps_registry)
    matches, paths_by_owner = _owners_and_paths_for_class(cls, apps_registry)
    if len(matches) == 1:
        paths = paths_by_owner[matches[0]]
        if len(paths) != 1:
            raise _implementation_error(
                'ambiguous_path',
                '%r is listed under multiple owned paths: %s' % (cls, paths),
            )
        return matches[0]
    if not matches:
        raise _implementation_error(
            'missing_implementation',
            '%r has no implementation owner' % (cls,),
        )
    raise _implementation_error(
        'duplicate_implementation',
        '%r has multiple implementation owners: %r' % (cls, matches),
    )
