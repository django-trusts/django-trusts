"""Kernel host backend. It lives in the kernel host app."""

from django.contrib.auth.backends import ModelBackend

from trusts.backends import TrustModelBackendMixin


class HostTrustModelBackend(TrustModelBackendMixin, ModelBackend):
    """Kernel-only host backend. Pair historical SQL lives on Zero."""
