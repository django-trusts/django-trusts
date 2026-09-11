"""Test-only Trusts-derived backends for multi-path S3a/S3b cases."""

from django.contrib.auth.backends import ModelBackend
from django.db.models import Q

from trusts.backends import TrustModelBackendMixin
from trusts.query import group_local_grant_exists


class GroupOnlyQueryCompiler(object):
    """Concrete route that does not include trustee ``content_exists``.

    Used to prove split coverage: this path can grant via historical
    TrustGroup without also matching another path's TUP rows.
    """

    def complete_exists(self, plan, candidates, user, permission):
        if not plan.records:
            return None
        return Q(group_local_grant_exists(user, permission, 'trust_id'))

    def group_exists(self, plan, candidates, user, permission):
        if not plan.records:
            return None
        return Q(group_local_grant_exists(user, permission, 'trust_id'))


class MixinOnlyBackend(TrustModelBackendMixin, ModelBackend):
    """Listed mixin-only path: plan compiler, no package Trust-as-content."""


class HostTrustModelBackend(TrustModelBackendMixin, ModelBackend):
    """Kernel-only host backend. Pair historical SQL lives on Zero."""


class GroupOnlyBackend(TrustModelBackendMixin, ModelBackend):
    """Mixin host whose complete proof is historical group only."""

    query_compiler = GroupOnlyQueryCompiler()


# Same class under a second import path (alias-ambiguity tests).
AliasedTrustModelBackend = HostTrustModelBackend


class MissingCompilerBackend(TrustModelBackendMixin, ModelBackend):
    query_compiler = None


class MalformedCompilerBackend(TrustModelBackendMixin, ModelBackend):
    query_compiler = object()


class _RaisingQueryCompiler(object):
    def complete_exists(self, plan, candidates, user, permission):
        raise RuntimeError('compiler exploded')

    def group_exists(self, plan, candidates, user, permission):
        raise RuntimeError('compiler exploded')


class RaisingCompilerBackend(TrustModelBackendMixin, ModelBackend):
    query_compiler = _RaisingQueryCompiler()
