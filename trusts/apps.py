from __future__ import annotations

from typing import TYPE_CHECKING

from django.apps import AppConfig as DjangoAppConfig
from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string

from trusts._meta_options import _ensure_permission_conditions_option

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


def _compiled_for_path(path):
    """Compiled plan for one exact Trusts backend path.

    Resolves the plan through a disposable backend instance
    (``import_string(path)().get_registry()`` via ``_own_compiled``)
    so this module never imports ``trusts.backends``: hosts load
    ``trusts.apps`` during ``apps.populate()`` before Django has
    constructed any models, and ``trusts.backends`` imports
    ``django.contrib.auth.models.Permission``, which raises
    ``AppRegistryNotReady`` at that point. That load-order chain,
    not a plain import cycle, is why the backend module cannot be
    imported here at top level.
    """
    compiled = import_string(path)()._own_compiled()
    compiled.path = path
    return compiled


class TrustsImplementationConfig(DjangoAppConfig):
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

    def owned_backend_paths(self):
        return tuple(self.trusts_backend_paths)

    def _apps_instance_ready(self):
        """True when *this* AppConfig's Apps instance has finished populate."""
        apps_registry = getattr(self, 'apps', None)
        return bool(apps_registry is not None and apps_registry.ready)

    def _configured_trusts_paths(self):
        owned = set(self.owned_backend_paths())
        return tuple(
            path for path in _listed_mixin_paths() if path in owned
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

    def freeze_owned_backends(self):
        """Freeze and compile each owned backend's registry.

        Call at the end of an implementation ``ready()``, after that
        implementation has registered its grants. This is the startup
        freeze hook: contributor registrations must happen before it.
        """
        from django.utils.module_loading import import_string

        for path in self.owned_backend_paths():
            import_string(path)().ready()

    def ready(self):
        # Discover trusts_policy_sql after models are populated. Core is not
        # an installed app and does not ship trusts/management (#129), so
        # the command attaches here. Subclasses that replace ready() must
        # call super() or the command stays unregistered.
        from trusts.inspect.commands import install_policy_commands

        install_policy_commands()
        self._validate_ownership()
        for path in self.owned_backend_paths():
            import_string(path)().get_registry()
        from trusts.inspect import checks as _trusts_checks  # noqa: F401


def configured_compiled_plans(apps_registry=None):
    """Compiled plans from every installed implementation, in order.

    Empty when no ``TrustsImplementationConfig`` is installed. This
    listing is not the Core list/guard aggregate: callers that authorize
    a QuerySet, view guard, or common-permission set must use
    ``_relationship_compiled_plans``.
    """
    plans = []
    for config in implementation_configs(apps_registry):
        for path in config._configured_trusts_paths():
            plans.append(_compiled_for_path(path))
    return tuple(plans)


def _plan_authorization_family(handle, apps_registry=None):
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


def _relationship_family_plans(handles, apps_registry=None):
    """Keep handles whose owned family is ``"relationship"``."""
    return tuple(
        handle for handle in handles
        if _plan_authorization_family(handle, apps_registry) == 'relationship'
    )


def _relationship_compiled_plans(apps_registry=None):
    """Configured handles that participate in Core list/guard aggregates."""
    return _relationship_family_plans(
        configured_compiled_plans(apps_registry),
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
