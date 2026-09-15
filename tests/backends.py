"""Test-only Trusts-derived backends for multi-path S3a/S3b cases."""

from django.contrib.auth.backends import ModelBackend

from trusts.backends import TrustModelBackendMixin


class MixinOnlyBackend(TrustModelBackendMixin, ModelBackend):
    """Listed mixin-only path: plan compiler, no package Trust-as-content."""


class HostTrustModelBackend(TrustModelBackendMixin, ModelBackend):
    """Kernel-only host backend. Pair historical SQL lives on Zero."""


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
