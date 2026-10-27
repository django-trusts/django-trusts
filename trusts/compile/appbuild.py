"""Build one backend state's catalog when its app config is ready."""

import django.apps
from django.conf import settings
from django.contrib.auth import get_user_model

from trusts.compile.compilers import Compiler
from trusts.errors import TrustsConfigurationError

# Register system checks once this module loads. App configs do not.
import trusts.inspect.checks  # noqa: F401


def build_app_catalog(config, state):
    """Freeze ``state.recorder``, replay it, and store the catalog.

    A second call keeps the catalog already stored. Registrations with
    no listed backend whose module resolves to ``config`` raise.
    """
    if state.catalog is not None:
        return
    compiler = Compiler(
        user_model=get_user_model(),
        path='%s.%s' % (
            type(config).__module__, type(config).__qualname__,
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
                path.rpartition('.')[0]) is config
            for path in settings.AUTHENTICATION_BACKENDS
        ):
            raise TrustsConfigurationError(
                'Trusts app %s has registrations but no AUTHENTICATION_BACKENDS '
                'entry resolves to it. List a backend whose module lives in this app.'
                % config.label)
