"""Isolated AppConfig for the #201 populate-window readiness proof.

Imported only as an INSTALLED_APPS entry in a subprocess. Module-level
imports stay free of Django models so ``Apps.populate()`` can load this
config before auth/contenttypes are ready.
"""

from django.apps import AppConfig


class _ProbePrincipal(object):
    """Duck-typed principal for the populate-window probe only."""

    def __init__(self, *, superuser=False):
        self.is_active = True
        self.is_superuser = superuser
        self.is_anonymous = False
        self.is_authenticated = True


class NotReadyPopulateProbeConfig(AppConfig):
    """``ready()`` runs during ``Apps.populate()`` while ``apps.ready`` is false."""

    name = 'tests.core'
    label = 'issue201_not_ready'

    def ready(self):
        from django.apps import apps as django_apps
        from django.db import connection
        from django.http import HttpRequest
        from django.test.utils import CaptureQueriesContext

        from tests.myapp.models import Document
        from trusts.core import TrustsConfigurationError
        from trusts.decorators import authorization_required

        if django_apps.ready:
            raise RuntimeError(
                'issue201 not-ready probe ran after Apps.ready'
            )

        @authorization_required(Document, 'myapp.change_document')
        def _edit(request, pk):
            return 'ok'

        def _probe_request(user):
            request = HttpRequest()
            request.user = user
            request.META['SERVER_NAME'] = 'testserver'
            request.META['SERVER_PORT'] = '80'
            return request

        for user in (_ProbePrincipal(), _ProbePrincipal(superuser=True)):
            with CaptureQueriesContext(connection) as captured:
                try:
                    _edit(_probe_request(user), pk=1)
                except TrustsConfigurationError as exc:
                    if 'before Django apps' not in str(exc):
                        raise
                else:
                    raise RuntimeError('expected TrustsConfigurationError')
            if captured.captured_queries:
                raise RuntimeError(
                    'not-ready probe issued SQL: %r'
                    % captured.captured_queries
                )
        print('not-ready-populate-ok')
