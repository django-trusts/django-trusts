"""Test-only Trusts-derived backends for multi-path S3a cases."""

from django.contrib.auth.backends import ModelBackend

from trusts.backends import TrustModelBackend, TrustModelBackendMixin


class MixinOnlyBackend(TrustModelBackendMixin, ModelBackend):
    """Listed mixin-only path: plan compiler, no package Trust-as-content."""


class HostTrustModelBackend(TrustModelBackend):
    """Concrete subclass: historical group compiler and T2 Trust-as-content."""


# Same class under a second import path (alias-ambiguity tests).
AliasedTrustModelBackend = TrustModelBackend


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
