"""Generic authorized queryset/manager. No Zero-noun grant helpers."""

from django.db.models import Manager, Model, QuerySet


def is_active_principal(user):
    """Match ``User.has_perm``: anonymous and inactive principals are denied.

    Superuser short-circuit on ``has_perm`` is a Django ``ModelBackend``
    behavior and is not duplicated in SQL list filters.
    """
    if user is None:
        return False
    if getattr(user, 'is_anonymous', False):
        return False
    if not getattr(user, 'is_authenticated', True):
        return False
    if not getattr(user, 'is_active', False):
        return False
    return True


class AuthorizedQuerySet(QuerySet):
    """Instance-only authorized-row filter. No Django permission codec.

    ``permission`` must be a model instance. Strings and auth.Permission
    *codenames* raise ``TrustsConfigurationError`` with zero SQL. This
    method does not parse ``:condition``, does not call
    ``is_active_principal``, and does not call ``get_permission``.

    Callers that need Django inactivity checks or string permissions wrap
    this; they do not belong on this class. There is no ``.permitted`` and
    no ``.get_permission``. Core ``.authorized`` includes
    relationship-family handles only; it is not Django's object-level
    backend OR.
    """

    def authorized(self, user, permission, extra_q=None):
        from trusts.apps import _relationship_implementation_handles
        from trusts.core import TrustsConfigurationError, granted

        if not isinstance(permission, Model):
            raise TrustsConfigurationError(
                'permission must be a model instance, not %r.' % (permission,)
            )
        granted_q = granted(
            _relationship_implementation_handles(),
            self, user, permission, kind='complete',
        )
        if granted_q is None:
            return self.none()
        if extra_q is not None:
            granted_q = granted_q & extra_q
        return self.filter(granted_q).distinct()


class AuthorizedManagerMixin:
    """Add ``authorized()`` without replacing an application's manager."""

    def authorized(self, user, permission, extra_q=None):
        return AuthorizedQuerySet.authorized(
            self.get_queryset(), user, permission, extra_q=extra_q,
        )


class PermittedUsersMixin:
    """Content-instance adapter for the reverse permission inquiry.

    ``content.get_permitted_users(perm)`` is the path that exists on
    every protected model that mixes this in. It is not a content-manager
    method: ``Content.objects`` keeps returning content rows.
    """

    def get_permitted_users(self, perm):
        from trusts.reverse import compile_permitted_users

        return compile_permitted_users(self, perm)


class PermittedUsersManagerMixin:
    """Optional adapter on an application's existing user manager.

    Does not replace that manager or its queryset class. Stock
    ``auth.User`` does not acquire this method. The content adapter
    remains the path that does not require a user-manager change.
    """

    def get_permitted_users(self, content, perm):
        from trusts.reverse import compile_permitted_users

        return compile_permitted_users(
            content, perm, user_queryset=self.get_queryset(),
        )


AuthorizedManager = Manager.from_queryset(AuthorizedQuerySet)
