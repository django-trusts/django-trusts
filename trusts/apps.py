from django.apps import AppConfig as DjangoAppConfig


class AppConfig(DjangoAppConfig):
    name = 'trusts'
    verbose_name = "Django Trusts Add-in"
    label = 'trusts'
    # Preserve the historical AutoField primary keys from 0001_initial.
    default_auto_field = 'django.db.models.AutoField'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Import here: a module-level trusts.core import loads contenttypes
        # models before Apps.populate finishes. Do not import trusts.backends
        # here (that module imports models; the mixin body calls
        # get_permission_model()).
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

        from trusts.backends import TrustModelBackendMixin
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

    def _trust_as_content_already_donated(self, path, registry):
        ids = getattr(self, '_trusts_tup_trust_registry_ids', None)
        if ids is not None and ids.get(path) is registry:
            return True
        return getattr(self, '_trusts_tup_trust_registry_id', None) is registry

    def _mark_trust_as_content_donated(self, path, registry):
        ids = dict(getattr(self, '_trusts_tup_trust_registry_ids', None) or {})
        ids[path] = registry
        self._trusts_tup_trust_registry_ids = ids
        if len(self._configured_trusts_paths()) == 1:
            self._trusts_tup_trust_registry_id = registry

    def _donate_package_trust_as_content(self, path):
        registry = self._ensure(path)
        if self._trust_as_content_already_donated(path, registry):
            return
        from trusts.core import Ref
        from trusts.models import Trust, TrustUserPermission

        j = Ref(TrustUserPermission)
        rev = Trust._meta.get_field('trust').remote_field.get_accessor_name()
        registry.register(
            content=getattr(j.trust, rev),
            user=j.entity,
            permission=j.permission,
        )
        self._mark_trust_as_content_donated(path, registry)

    def ready(self):
        # admin.py registers core ModelAdmins at import. Only load it when
        # django.contrib.admin is installed so a wheel import without admin
        # (CI verify-wheel-install) still starts.
        from django.apps import apps as django_apps
        from django.utils.module_loading import import_string

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
        paths = self._configured_trusts_paths()
        for path in paths:
            self._ensure(path)

        # T2: package Trust-as-content is contributed to every configured
        # class that is TrustModelBackend or a subclass. Mixin-only paths
        # receive no automatic package declaration. Sentinel is
        # contributor-instance + exact-registry, set only after success.
        from trusts.backends import TrustModelBackend

        for path in paths:
            cls = import_string(path)
            if issubclass(cls, TrustModelBackend):
                self._donate_package_trust_as_content(path)


def kernel_config():
    """Return the kernel ``trusts.apps.AppConfig`` by class identity.

    Does not hard-require the string label ``'trusts'``. On C1 that label
    is still ``trusts``, so this returns the same object as
    ``apps.get_app_config('trusts')``. Later retargets keep this helper
    and change only the label.
    """
    from django.apps import apps as django_apps

    matches = [
        config for config in django_apps.get_app_configs()
        if type(config) is AppConfig
    ]
    if len(matches) == 1:
        return matches[0]
    if not matches:
        raise LookupError('No installed Trusts kernel AppConfig.')
    raise LookupError(
        'Multiple Trusts kernel AppConfig instances: %r' % (matches,)
    )
