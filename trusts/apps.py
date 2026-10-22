"""Each host app config owns one registry and the catalog built from it."""

import django.apps

def open_registry(config):
    """Registry for ``config``. Created on the first registration call.

    Importing the compiler at app-config construction raises
    ``AppRegistryNotReady``: ``compile/resolution.py`` imports
    ``django.contrib.contenttypes.fields`` before apps are ready.
    The first ``get_registry()`` is models import or ``ready()``.
    """
    registry = config.registry
    if registry is not None:
        return registry
    from trusts.compile.factory import Compiler

    registry = Compiler(
        path=config.catalog_path(),
        family=config.family,
        query_compiler=config.query_compiler or Compiler.default_query_compiler(),
    )
    config.registry = registry
    return registry


def catalog_of(config):
    """Catalog for ``config``, built once on the first call."""
    if config.catalog is None:
        config.catalog = open_registry(config).compile()
    return config.catalog


class TrustsConfigMixin(django.apps.AppConfig):
    """App config whose backend registers through ``get_registry()``.

    ``ready`` does not build the catalog. The compiler builds it at the
    first question. Order across apps does not matter.
    """

    family = 'relationship'
    query_compiler = None

    def __init__(self, app_name, app_module):
        super().__init__(app_name, app_module)
        self.registry = None
        self.catalog = None

    def catalog_path(self):
        """Identity stored on the catalog and in the policy lockfile."""
        return '%s.%s' % (type(self).__module__, type(self).__qualname__)

    def ready(self):
        # phase-1 import raises AppRegistryNotReady: snapshot imports
        # auth.Permission before apps are ready.
        import trusts.inspect.checks  # noqa: F401


def installed_catalogs():
    """Built catalogs of installed mixin configs, in ``INSTALLED_APPS`` order."""
    found = []
    for config in django.apps.apps.get_app_configs():
        if isinstance(config, TrustsConfigMixin):
            found.append(catalog_of(config))
    return tuple(found)
