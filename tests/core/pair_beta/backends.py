from django.contrib.auth.backends import ModelBackend

from trusts.backends import TrustModelBackendMixin


class PairBetaBackend(TrustModelBackendMixin, ModelBackend):
    """Trusts backend for pair_beta. The catalog is this app's."""
