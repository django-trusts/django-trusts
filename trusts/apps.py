"""Each host app config owns one recorder and the catalog built from it."""

from collections.abc import Callable
from typing import TypeVar

import django.apps
from django.contrib.auth import get_user_model
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

    ``play`` replays each call, in order, as the same method on
    ``target``. The recorder must already be frozen. A later ``play``
    replays those same calls onto the new target.
    """

    def __init__(self):
        self._rows = []
        self.frozen = False

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
        self._rows.append(('register', (), {
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
        self._rows.append((
            'add_named_filter', (model, code, predicate), {},
        ))

    def set_user_condition(self, name, expr, on='*'):
        self._open()
        self._rows.append(('set_user_condition', (name, expr), {'on': on}))

    def set_user_override(self, name, expr, on='user'):
        self._open()
        self._rows.append(('set_user_override', (name, expr), {'on': on}))

    def freeze(self):
        self.frozen = True

    def play(self, target):
        """Replay this log on ``target``.

        An unfrozen recorder raises. A second play replays the same
        calls onto that target.
        """
        if not self.frozen:
            raise TrustsConfigurationError(
                'play refused: this recorder is not frozen.'
            )
        for name, args, kwargs in self._rows:
            getattr(target, name)(*args, **kwargs)

    def _open(self):
        if self.frozen:
            raise TrustsConfigurationError(
                'register refused: this recorder is frozen. '
                'The catalog was already built by TrustsConfigMixin.ready().'
            )


class TrustsConfigMixin(django.apps.AppConfig):
    """Records every registration call through ``self.recorder``.

    ``ready`` freezes that recorder; the compiler builds the catalog.
    Order across apps does not matter.
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
        # phase-1 import raises AppRegistryNotReady: compile/resolution.py
        # imports django.contrib.contenttypes.fields before apps are ready.
        from trusts.compile.factory import Compiler

        user_model = get_user_model()
        compiler = Compiler(
            user_model=user_model,
            path=self.catalog_path(),
            family=self.family,
            query_compiler=self.query_compiler or Compiler.default_query_compiler(),
        )
        self.recorder.freeze()
        self.recorder.play(compiler.get_recorder_target())
        self.catalog = compiler.compile()
        # phase-1 import raises AppRegistryNotReady: snapshot imports
        # auth.Permission before apps are ready.
        import trusts.inspect.checks  # noqa: F401


def installed_catalogs():
    """Built catalogs of installed mixin configs, in ``INSTALLED_APPS`` order."""
    found = []
    for config in django.apps.apps.get_app_configs():
        if isinstance(config, TrustsConfigMixin):
            found.append(config.get_catalog())
    return tuple(found)

