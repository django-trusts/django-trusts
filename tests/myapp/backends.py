from django.contrib.auth.backends import ModelBackend

from trusts.backends import TrustModelBackendMixin


class DocumentBackend(TrustModelBackendMixin, ModelBackend):
    pass
