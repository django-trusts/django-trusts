"""A backend whose app config is not a ``TrustsConfigMixin``."""

from django.contrib.auth.backends import ModelBackend

from trusts.backends import TrustModelBackendMixin


class OutsideBackend(TrustModelBackendMixin, ModelBackend):
    """Construction raises. This app does not own a catalog."""
