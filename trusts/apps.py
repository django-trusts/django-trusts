"""Each host app config owns one recorder and the catalog built from it."""

from collections.abc import Callable
from typing import TypeVar

import django.apps
from django.db.models import Model
from django.db.models import options as model_options

from trusts.errors import TrustsConfigurationError

T = TypeVar('T', bound=Model)

# Populate imports this module before any models. The option has to be
# registered before Django imports models that declare it.
if 'permission_conditions' not in model_options.DEFAULT_NAMES:
    _names = model_options.DEFAULT_NAMES
    if isinstance(_names, tuple):
        model_options.DEFAULT_NAMES = _names + ('permission_conditions',)
    else:
        _names.append('permission_conditions')


class Recorder(object):
    """Ordered log of registration calls for one app config.

    The log stores the call arguments. ``ready`` freezes the log and
    is the only build.
    """

    def __init__(self):
        self._rows = []
        self.frozen = False

    @property
    def rows(self):
        """Recorded calls, in registration order."""
        return self._rows

    def register(
        self, *,
        trust: type[T],
        user: str | Callable[[T], object] | None = None,
        permission: str | Callable[[T], object] | None = None,
        content: str | Callable[[T], object],
        group: str | Callable[[T], object] | None = None,
        delegate: str | Callable[[T], object] | None = None,
        sponsor: str | Callable[[T], object] | None = None,
        condition: (
            Callable[[T], object] | Callable[[T, object], object] | None
        ) = None,
        along=None,
    ):
        self._open()
        self._rows.append(('register', {
            'trust': trust,
            'user': user,
            'permission': permission,
            'content': content,
            'group': group,
            'delegate': delegate,
            'sponsor': sponsor,
            'condition': condition,
            'along': along,
        }))

    def add_named_filter(self, model, code, predicate):
        """Record a named-filter builder for ``ready``."""
        self._open()
        self._rows.append(('filter', model, code, predicate))

    def set_user_condition(self, name, expr, on='*'):
        self._open()
        self._rows.append(('condition', name, expr, on))

    def set_user_override(self, name, expr, on='user'):
        self._open()
        self._rows.append(('override', name, expr, on))

    def freeze(self):
        self.frozen = True

    def _open(self):
        if self.frozen:
            raise TrustsConfigurationError(
                'register refused: this recorder is frozen. The catalog was already built by TrustsConfigMixin.ready().'
            )


class TrustsConfigMixin(django.apps.AppConfig):
    """Host apps subclass this and own one recorder and one catalog.

    Register on ``self.recorder``, then call ``super().ready()``.
    ``ready`` freezes the recorder and builds the catalog. Order across
    apps does not matter.
    """

    family = 'relationship'
    query_compiler = None
    recorder: Recorder

    def __init__(self, app_name, app_module):
        super().__init__(app_name, app_module)
        self.recorder = Recorder()
        self.catalog = None

    def get_catalog(self):
        """Catalog built by ``ready``. Raises before that build."""
        if self.catalog is None:
            raise TrustsConfigurationError('catalog not built yet')
        return self.catalog

    def catalog_path(self):
        """Identity stored on the catalog and in the policy lockfile."""
        return '%s.%s' % (type(self).__module__, type(self).__qualname__)

    def ready(self):
        # A second ``ready()`` on this config finds the recorder already
        # frozen and leaves the catalog in place. ``register()`` on that
        # recorder still raises.
        if self.recorder.frozen:
            return
        # ``get_user_model()`` and the catalog build touch the app
        # registry. ``Apps.populate`` phase 1 imports this module before
        # models are ready, so these imports stay in ``ready``.
        #
        # ``install_policy_commands`` and ``trusts.inspect.checks`` import
        # ``django.contrib.auth.models.Permission``. That import raises
        # ``AppRegistryNotReady`` at module level during phase 1, so they
        # stay here as well. ``install_policy_commands`` is idempotent.
        from django.contrib.auth import get_user_model
        from trusts.compile.catalogs import Catalog
        from trusts.compile.factory import compile_recorder
        from trusts.inspect.commands import install_policy_commands
        import trusts.inspect.checks  # noqa: F401

        install_policy_commands()
        user_model = get_user_model()
        shape = compile_recorder(
            self.recorder,
            path=self.catalog_path(),
            family=self.family,
            compiler=self.query_compiler,
            user_model=user_model,
        )
        self.catalog = Catalog(shape, user_model=user_model)


def installed_user_model():
    """Auth user model once the app registry is ready, else ``None``."""
    if not django.apps.apps.ready:
        return None
    from django.contrib.auth import get_user_model
    return get_user_model()


def installed_catalogs():
    """Built catalogs of installed mixin configs, in ``INSTALLED_APPS`` order."""
    found = []
    for config in django.apps.apps.get_app_configs():
        if isinstance(config, TrustsConfigMixin):
            found.append(config.get_catalog())
    return tuple(found)


def catalog_for_model(model):
    """Catalog owned by the app that contains ``model``, or ``None``."""
    config = django.apps.apps.get_containing_app_config(model.__module__)
    if not isinstance(config, TrustsConfigMixin):
        return None
    return config.get_catalog()
