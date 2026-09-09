"""Object-only Django authentication backend (issue #47 S2).

``ObjectAuthorizationBackend`` is a ``BaseBackend``, not a
``ModelBackend``. It does not grant global or model permissions and
does not assume Django User or ``auth.Permission`` models. ``perm`` is
an operation instance or ``operation_lookup`` string, compiled by the
S1 runtime. There is no Django permission-string parser.

* ``authenticate()`` abstains (returns ``None``).
* ``obj is None`` returns ``False``.
* A supplied object routes through ``is_authorized``.
* ``AuthorizationConfigError`` becomes denial (``False``) at this
  security boundary. Direct runtime APIs still raise.

``ObjectAuthorizationModelBackend`` is an optional convenience that
composes Django ``ModelBackend`` for ``obj is None`` only. Object
checks stay on the generic path. It is not the advertised default and
is not required for GH.
"""

from django.contrib.auth.backends import BaseBackend, ModelBackend

from trusts.runtime import AuthorizationConfigError, is_authorized


class ObjectAuthorizationBackend(BaseBackend):
    """Object-only authorization. No Django user or model-permission default."""

    def __init__(self, context=None, trustee=None, names=None):
        self.context = context
        self.trustee = trustee
        self.names = names

    def authenticate(self, request, **credentials):
        return None

    def has_perm(self, user_obj, perm, obj=None):
        if obj is None:
            return False
        try:
            return bool(is_authorized(
                user_obj, perm, obj,
                context=self.context,
                trustee=self.trustee,
                names=self.names,
            ))
        except AuthorizationConfigError:
            return False


class ObjectAuthorizationModelBackend(ObjectAuthorizationBackend, ModelBackend):
    """Optional: ``obj is None`` uses Django model permissions.

    Object decisions still go through ``ObjectAuthorizationBackend``.
    An active superuser is not granted object access by this class.
    Not required for GH.
    """

    def authenticate(self, request, **credentials):
        return ModelBackend.authenticate(self, request, **credentials)

    def has_perm(self, user_obj, perm, obj=None):
        if obj is None:
            return ModelBackend.has_perm(self, user_obj, perm, obj=None)
        return ObjectAuthorizationBackend.has_perm(self, user_obj, perm, obj)


__all__ = [
    'ObjectAuthorizationBackend',
    'ObjectAuthorizationModelBackend',
]
