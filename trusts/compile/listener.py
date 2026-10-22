"""Per-call checks for one app config's registration log.

Importing this module loads no models and does not touch the grammar.
The compiler is imported on the first recorded call, during model
import, after app configs exist.
"""

from django.core.exceptions import AppRegistryNotReady

from trusts.errors import TrustsConfigurationError


class RegistrationListener(object):
    """Checks one registration call, then lets the log record it.

    A missing field, a reverse relation, or a model that is not loaded
    yet is left for ``ready``. Anything else raises at this call.
    """

    def __init__(self):
        self._inner, self._saw_register = None, False

    def register(self, **kwargs):
        self._run('register', (), kwargs)

    def add_named_filter(self, model, code, predicate):
        self._run('add_named_filter', (model, code, predicate), {})

    def set_user_condition(self, name, expr, on='*'):
        self._run('set_user_condition', (name, expr), {'on': on})

    def set_user_override(self, name, expr, on='user'):
        self._run('set_user_override', (name, expr), {'on': on})

    def _run(self, name, args, kwargs):
        if name in ('set_user_condition', 'set_user_override') and self._saw_register:
            raise TrustsConfigurationError(
                'Record user conditions and the override before register().'
            )
        try:
            inner = self._compiler()
            if inner is None and name == 'register':
                from trusts.compile.factory import Compiler
                Compiler.build_public_registration(**kwargs)
            elif inner is not None:
                getattr(inner, name)(*args, **kwargs)
        except (TrustsConfigurationError, AppRegistryNotReady) as exc:
            if not _deferrable(exc): raise
        if name == 'register':
            self._saw_register = True

    def _compiler(self):
        if self._inner is not None: return self._inner
        user = _loaded_user_model()
        if user is None: return None
        from trusts.compile.factory import Compiler
        self._inner = Compiler(
            user_model=user, path='trusts.compile.listener',
            family='relationship',
            query_compiler=Compiler.default_query_compiler(),
        )
        return self._inner


def _deferrable(exc):
    text = str(exc)
    return isinstance(exc, AppRegistryNotReady) or any(
        piece in text for piece in (
            'missing field', 'reverse', 'does not terminate on a model',
        ))


def _loaded_user_model():
    from django.apps import apps
    from django.conf import settings
    try: return apps.get_model(
        *settings.AUTH_USER_MODEL.split('.'), require_ready=False)
    except (LookupError, ValueError): return None
