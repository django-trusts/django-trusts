"""Test-only Trusts-derived backends for multi-path S3a/S3b cases."""

from django.contrib.auth.backends import ModelBackend

from trusts.backends import TrustModelBackendMixin
from trusts.plan.relations import PlanQueryCompiler


class TestsTrustBackend(TrustModelBackendMixin, ModelBackend):
    """Listed backend for registrations donated onto ``tests.apps.TestsConfig``.

    Pair settings install Zero, and that app config records the
    Category, Ticket, and Group rows. A registration needs a backend
    whose module lives in the same app.
    """


class MixinOnlyBackend(TrustModelBackendMixin, ModelBackend):
    """Listed mixin-only path: plan compiler, no package Trust-as-content."""


class MissingCompilerBackend(TrustModelBackendMixin, ModelBackend):
    query_compiler = None


class MalformedCompilerBackend(TrustModelBackendMixin, ModelBackend):
    query_compiler = object()


class _RaisingQueryCompiler(PlanQueryCompiler):
    def complete_exists(self, plan, candidates, user, permission):
        raise RuntimeError('compiler exploded')

    def group_exists(self, plan, candidates, user, permission):
        raise RuntimeError('compiler exploded')


class RaisingCompilerBackend(TrustModelBackendMixin, ModelBackend):
    query_compiler = _RaisingQueryCompiler()
