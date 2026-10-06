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

    The public content-list inquiry is
    ``PermittedQuerySet.permitted(permission, user, conditions=())``.
    ``.authorized`` stays this lower-level projection: it does not use
    that principal check or that input validation. Core ``.authorized``
    includes relationship-family handles only; it is not Django's
    object-level backend OR.
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


class PermittedQuerySetMixin:
    """Add ``permitted()`` to an application queryset.

    Mix this into the queryset, then expose that queryset with
    ``as_manager()`` or ``Manager.from_queryset``. A manager-only mixin
    cannot serve ``filter(...).permitted(...)``.
    """

    def permitted(self, permission, user, conditions=()):
        """Rows in this queryset ``user`` may access for ``permission``.

        ``permission`` is one full ``app_label.codename`` string or one
        saved ``auth.Permission`` instance. The protected model is
        ``self.model``. The codename is not parsed to guess a model.
        ``conditions`` is an exact tuple of queryable names, ANDed.
        Anonymous and inactive principals receive an empty queryset.
        Malformed input and incomplete configuration raise before that
        shortcut and before SQL.

        A relationship-family backend participates only when it has an
        applicable ``auth.Permission`` plan and owns every selected
        name. This is the same semantic inquiry as object ``has_perm``,
        not that method's current string codec. There is no
        active-superuser shortcut.
        """
        from trusts._permitted import permitted_queryset
        from trusts.apps import _relationship_implementation_handles

        return permitted_queryset(
            self,
            permission,
            user,
            conditions,
            handles=_relationship_implementation_handles(),
        )


class PermittedQuerySet(PermittedQuerySetMixin, QuerySet):
    """Concrete queryset for ``permitted(permission, user, conditions=())``."""


PermittedManager = Manager.from_queryset(PermittedQuerySet)


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

    ``User.objects.permitted(content, perm)`` returns a lazy user
    queryset. The name is ``permitted`` because the manager already
    identifies the user model, and Django's ``get`` convention implies
    one row. Does not replace that manager or its queryset class. Stock
    ``auth.User`` does not acquire this method. The content adapter
    ``get_permitted_users`` remains the path that does not require a
    user-manager change.
    """

    def permitted(self, content, perm):
        from trusts.reverse import compile_permitted_users

        return compile_permitted_users(
            content, perm, user_queryset=self.get_queryset(),
        )


AuthorizedManager = Manager.from_queryset(AuthorizedQuerySet)
