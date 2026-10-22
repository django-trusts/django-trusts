"""Each host app config owns one registration log and the catalog built from it."""

from collections.abc import Callable
from typing import TypeVar

import django.apps
from django.db.models import Model

from trusts.errors import PermissionConditionError, TrustsConfigurationError

T = TypeVar('T', bound=Model)


class Recorder(object):
    """Ordered log of registration calls for one app config.

    ``play`` replays each call, in order, as the same method on
    ``target``. The log must already be frozen. A later ``play``
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
        self._open('register')
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
        """Record a named-filter builder. The compiler parses it at build."""
        self._open('add_named_filter')
        self._reject_duplicate_filter(model, code)
        self._rows.append((
            'add_named_filter', (model, code, predicate), {},
        ))

    def set_user_condition(self, name, expr, on='*'):
        self._open('set_user_condition')
        self._rows.append(('set_user_condition', (name, expr), {'on': on}))

    def set_user_override(self, name, expr, on='user'):
        self._open('set_user_override')
        self._rows.append(('set_user_override', (name, expr), {'on': on}))

    def freeze(self):
        self.frozen = True

    def play(self, target):
        """Replay this log on ``target``.

        An unfrozen log raises. A second play replays the same calls
        onto that target.
        """
        if not self.frozen:
            raise TrustsConfigurationError(
                'play refused: this registry is not frozen.'
            )
        for name, args, kwargs in self._rows:
            getattr(target, name)(*args, **kwargs)

    def _reject_duplicate_filter(self, model, code):
        meta = getattr(model, '_meta', None)
        if meta is None:
            return
        label = meta.label
        for name, args, _kwargs in self._rows:
            if name != 'add_named_filter':
                continue
            prior, prior_code = args[0], args[1]
            prior_meta = getattr(prior, '_meta', None)
            if prior_meta is None or prior_code != code:
                continue
            if prior_meta.label == label:
                raise PermissionConditionError(
                    'Named filter %r is already registered on %s.'
                    % (code, label)
                )

    def _open(self, method):
        if self.frozen:
            raise TrustsConfigurationError(
                '%s refused: this registry is frozen. '
                'The catalog is already built.' % method
            )


class TrustsConfigMixin(django.apps.AppConfig):
    """App config whose backend registers through ``get_registry()``.

    ``ready`` does not build the catalog. The first question builds it
    from this config's registration log. Order across apps does not matter.
    """

    family = 'relationship'
    query_compiler = None
    recorder: Recorder

    def __init__(self, app_name, app_module):
        super().__init__(app_name, app_module)
        self.recorder = Recorder()
        self.catalog = None

    def catalog_path(self):
        """Identity stored on the catalog and in the policy lockfile."""
        return '%s.%s' % (type(self).__module__, type(self).__qualname__)

    def ready(self):
        # phase-1 import raises AppRegistryNotReady: snapshot imports
        # auth.Permission before apps are ready.
        import trusts.inspect.checks  # noqa: F401


def catalog_of(config):
    """Catalog for ``config``, built once on the first call.

    The compiler is constructed here, when the user model is known,
    and the registration log is replayed onto it.
    """
    if config.catalog is not None:
        return config.catalog
    from django.contrib.auth import get_user_model
    from trusts.compile.factory import Compiler

    compiler = Compiler(
        user_model=get_user_model(),
        path=config.catalog_path(),
        family=config.family,
        query_compiler=(
            config.query_compiler or Compiler.default_query_compiler()
        ),
    )
    config.recorder.freeze()
    config.recorder.play(compiler)
    config.catalog = compiler.compile()
    return config.catalog


def installed_catalogs():
    """Built catalogs of installed mixin configs, in ``INSTALLED_APPS`` order."""
    found = []
    for config in django.apps.apps.get_app_configs():
        if isinstance(config, TrustsConfigMixin):
            found.append(catalog_of(config))
    return tuple(found)
