"""Django hook for Trusts implementations.

Importable before the app registry is ready. Does not import
``trusts.backends`` (``Permission`` calls ``apps.check_apps_ready()``)
or ``trusts.inspect.checks``. ``ready()`` validates ownership.
Registration closes at ``ready()``. Peers are fixed at that sweep.
"""

import sys

from django.apps import AppConfig as DjangoAppConfig
from django.conf import settings
from django.contrib.auth import get_backends
from django.core.exceptions import ImproperlyConfigured

from trusts._meta_options import _ensure_permission_conditions_option
from trusts.errors import TrustsConfigurationError

_ensure_permission_conditions_option()

recorders = {}
catalogs = {}


def listed_backend_class(path):
    """Resolve ``path`` from an already-imported module. Does not import."""
    module_name, _, qual = path.rpartition('.')
    module = sys.modules.get(module_name)
    if module is None or qual == '':
        return None
    obj = module
    for part in qual.split('.'):
        obj = getattr(obj, part, None)
        if obj is None:
            return None
    return obj if isinstance(obj, type) else None


class TrustsImplementationConfig(DjangoAppConfig):
    """Implementation owner. Declares ``trusts_backend_paths``.

    Does not construct registries. Subclasses register on
    ``Backend().get_registry()`` before the first inquiry seals it.
    """

    default = False
    trusts_backend_paths = ()
    _authorization_family = 'relationship'

    def owned_backend_paths(self):
        return tuple(self.trusts_backend_paths)

    def _configured_trusts_paths(self):
        """Owned paths that are listed. Same class under two strings is an error."""
        owned = set(self.owned_backend_paths())
        return tuple(
            path for path in _listed_mixin_paths() if path in owned
        )

    def path_for_class(self, cls):
        matches = [
            path for path in self._configured_trusts_paths()
            if listed_backend_class(path) is cls
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

    def path_for_backend(self, backend):
        return self.path_for_class(type(backend))

    def ready(self):
        _assert_owned(self)


def implementation_configs(apps_registry=None):
    """Installed ``TrustsImplementationConfig`` instances on one Apps registry."""
    from django.apps import apps as django_apps

    registry = django_apps if apps_registry is None else apps_registry
    return tuple(
        config for config in registry.get_app_configs()
        if isinstance(config, TrustsImplementationConfig)
    )


def implementation_for_path(path, apps_registry=None):
    """Return the unique implementation that owns ``path``."""
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
    """Unique owner of ``cls``, by exact class identity of an owned path."""
    matches = []
    for config in implementation_configs(apps_registry):
        for path in config.owned_backend_paths():
            if listed_backend_class(path) is cls:
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


def _is_mixin(cls):
    return any(
        base.__name__ == 'TrustModelBackendMixin' for base in cls.__mro__
    )


def _assert_owned(config):
    owned = config.owned_backend_paths()
    if not owned:
        raise ImproperlyConfigured(
            '%s.trusts_backend_paths must be a non-empty tuple of '
            'exact AUTHENTICATION_BACKENDS paths.' % type(config).__name__
        )
    if len(set(owned)) != len(owned):
        raise ImproperlyConfigured(
            '%s.trusts_backend_paths must not repeat a path: %r'
            % (type(config).__name__, owned)
        )
    get_backends()
    listed = tuple(getattr(settings, 'AUTHENTICATION_BACKENDS', ()) or ())
    listed_set = set(listed)
    for path in owned:
        cls = listed_backend_class(path)
        if not isinstance(cls, type) or not _is_mixin(cls):
            if path not in listed_set:
                raise ImproperlyConfigured(
                    '%s owns %r but that path is not listed in '
                    'AUTHENTICATION_BACKENDS.'
                    % (type(config).__name__, path)
                )
            raise TrustsConfigurationError(
                '%s owns %r which is not a TrustModelBackendMixin.'
                % (type(config).__name__, path)
            )
        if path not in listed_set:
            raise ImproperlyConfigured(
                '%s owns %r but that path is not listed in '
                'AUTHENTICATION_BACKENDS.'
                % (type(config).__name__, path)
            )
    apps_registry = getattr(config, 'apps', None)
    for path in owned:
        others = [
            other for other in implementation_configs(apps_registry)
            if other is not config and path in other.owned_backend_paths()
        ]
        if others:
            raise TrustsConfigurationError(
                'Backend path %r has multiple implementation owners: %r'
                % (path, [config] + others)
            )


def _listed_mixin_paths():
    """Mixin paths in settings order. Two strings for one class is an error."""
    get_backends()
    listed = getattr(settings, 'AUTHENTICATION_BACKENDS', ()) or ()
    paths = []
    class_to_paths = {}
    for path in listed:
        if path in paths:
            continue
        cls = listed_backend_class(path)
        if not isinstance(cls, type) or not _is_mixin(cls):
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


def relationship_registries():
    """Built registries whose catalog family is relationship, publish order."""
    return tuple(
        catalog.registry
        for catalog in catalogs.values()
        if catalog.family == 'relationship'
    )
