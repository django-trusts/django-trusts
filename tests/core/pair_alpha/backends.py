from django.contrib.auth.backends import ModelBackend

from trusts.backends import TrustModelBackendMixin


class PairAlphaBackend(TrustModelBackendMixin, ModelBackend):
    """Trusts backend for pair_alpha. The catalog is this app's."""
