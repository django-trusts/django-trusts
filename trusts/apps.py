"""Each host app config owns one registration log and the catalog built from it."""

from collections.abc import Callable
from typing import TypeVar

import django.apps
from django.db.models import Model

from trusts.errors import TrustsConfigurationError

T = TypeVar('T', bound=Model)


class Recorder(object):
    """Ordered log of registration calls for one app config.

    ``play`` replays each call, in order, as the same method on
    ``target``. The log must already be frozen. A later ``play``
    replays those same calls onto the new target.
    """

    def __init__(self, listener):
        self._rows = []
        self.frozen = False
        self._listener = listener

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
        self._accept('register', (), {
            'trust': trust,
            'user': user,
            'permission': permission,
            'content': content,
            'group': group,
            'delegate': delegate,
            'sponsor': sponsor,
            'condition': condition,
            'along': along,
        })

    def add_named_filter(self, model, code, predicate):
        """Record a named-filter builder. The compiler parses it at build."""
        self._accept('add_named_filter', (model, code, predicate), {})

    def set_user_condition(self, name, expr, on='*'):
        self._accept('set_user_condition', (name, expr), {'on': on})

    def set_user_override(self, name, expr, on='user'):
        self._accept('set_user_override', (name, expr), {'on': on})

    def _accept(self, name, args, kwargs):
        self._open(name)
        getattr(self._listener, name)(*args, **kwargs)
        self._rows.append((name, args, kwargs))

    def freeze(self):
        self.frozen = True

    def play(self, target):
        """Replay this log on ``target``.

        The caller freezes the log first. A second play replays the
        same calls onto that target.
        """
        for name, args, kwargs in self._rows:
            getattr(target, name)(*args, **kwargs)

    def _open(self, method):
        if self.frozen:
            raise TrustsConfigurationError(
                '%s refused: this registry is frozen. '
                'The catalog is already built.' % method
            )


class TrustsConfigMixin(django.apps.AppConfig):
    """App config whose backend registers through ``get_registry()``.

    ``ready`` freezes this config's registration log, replays it, and
    builds the catalog. A catalog with registrations and no listed
    backend raises ``TrustsConfigurationError``. A later registration
    raises. Order across apps does not matter. Request time does not
    build the catalog.
    """

    family = 'relationship'
    query_compiler = None
    recorder: Recorder

    def __init__(self, app_name, app_module):
        super().__init__(app_name, app_module)
        from trusts.compile.listener import RegistrationListener
        self.recorder = Recorder(RegistrationListener())
        self.catalog = None

    def catalog_path(self):
        """Identity stored on the catalog and in the policy lockfile."""
        return '%s.%s' % (type(self).__module__, type(self).__qualname__)

    def ready(self):
        # phase-1 import raises AppRegistryNotReady: snapshot imports
        # auth.Permission before apps are ready.
        import trusts.inspect.checks  # noqa: F401
        if self.catalog is not None: return
        from django.contrib.auth import get_user_model
        from trusts.compile.factory import Compiler

        compiler = Compiler(
            user_model=get_user_model(),
            path=self.catalog_path(),
            family=self.family,
            query_compiler=(
                self.query_compiler or Compiler.default_query_compiler()
            ),
        )
        self.recorder.freeze()
        self.recorder.play(compiler)
        self.catalog = compiler.compile()
        if self.catalog.records or self.catalog.delegations:
            from django.conf import settings
            if not any(
                django.apps.apps.get_containing_app_config(
                    path.rpartition('.')[0]) is self
                for path in settings.AUTHENTICATION_BACKENDS
            ):
                raise TrustsConfigurationError(
                    'Trusts app %s has registrations but no AUTHENTICATION_BACKENDS '
                    'entry resolves to it. List a backend whose module lives in this app.'
                    % self.label)
