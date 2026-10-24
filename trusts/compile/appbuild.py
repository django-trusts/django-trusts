"""Build one backend state's catalog when its app config is ready."""

import django.apps
from django.conf import settings
from django.contrib.auth import get_user_model

from trusts.compile.factory import Compiler
from trusts.errors import TrustsConfigurationError

# Register system checks once this module loads. App configs do not.
import trusts.inspect.checks  # noqa: F401


def build_app_catalog(state, app_config):
    """Freeze ``state.recorder``, replay it, and store the catalog.

    A second call keeps the catalog already stored. Registrations with
    no listed backend whose module resolves to ``app_config`` raise.
    """
    if state.catalog is not None:
        return
    compiler = Compiler(
        user_model=get_user_model(),
        path='%s.%s' % (
            type(app_config).__module__, type(app_config).__qualname__,
        ),
        family=state.family,
        query_compiler=(
            state.query_compiler or Compiler.default_query_compiler()
        ),
    )
    state.recorder.freeze()
    state.recorder.play(compiler)
    state.catalog = compiler.compile()
    if state.catalog.records or state.catalog.delegations:
        if not any(
            django.apps.apps.get_containing_app_config(
                path.rpartition('.')[0]) is app_config
            for path in settings.AUTHENTICATION_BACKENDS
        ):
            raise TrustsConfigurationError(
                'Trusts app %s has registrations but no AUTHENTICATION_BACKENDS '
                'entry resolves to it. List a backend whose module lives in this app.'
                % app_config.label)
