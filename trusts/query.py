"""Generic authorized queryset/manager. No Zero-noun grant helpers."""

from django.db.models import Manager, Model, QuerySet

from trusts._bind_once import bind_once


def is_active_principal(user, *, skip_is_active=False):
    """Match ``User.has_perm``: anonymous and inactive users are denied.

    Superuser short-circuit on ``has_perm`` is a Django ``ModelBackend``
    behavior and is not duplicated in SQL list filters. ``skip_is_active``
    skips only the built-in ``is_active`` check.
    """
    if user is None:
        return False
    if getattr(user, 'is_anonymous', False):
        return False
    if not getattr(user, 'is_authenticated', True):
        return False
    if not skip_is_active and not getattr(user, 'is_active', False):
        return False
    return True


def require_mode_flag(value, name):
    """``skip_is_active`` must be a real boolean."""
    if not isinstance(value, bool):
        raise TypeError('%s must be a bool, not %r.' % (name, value))
    return value


def stored_user_is_inactive(user, *, skip_is_active=False):
    """Whether a stored user's built-in ``is_active`` rejects the inquiry.

    ``skip_is_active=True`` skips the check. ``None`` is not inactive so
    ``authorized(None)`` still fails at grant binding. A model with no
    ``is_active`` is not inactive: a schema-neutral terminal keeps its
    result, and permission SQL reports that model separately. A non-model
    that presents as a user (``is_authenticated`` or ``is_anonymous``) and
    has no ``is_active`` is denied, the same default as ``has_perm``.
    Any other non-model is not inactive, so grant binding still raises.
    Anonymous and unauthenticated denial stays with the caller. A user
    object that is not a model instance is not a SQL principal; permission
    SQL is compiled against the user model.
    """
    if skip_is_active or user is None:
        return False
    if isinstance(user, Model) and not hasattr(user, 'is_active'):
        return False
    if (
        not isinstance(user, Model)
        and not hasattr(user, 'is_active')
        and not hasattr(user, 'is_authenticated')
        and not hasattr(user, 'is_anonymous')
    ):
        return False
    return not bool(getattr(user, 'is_active', False))


def user_identity_denied(user):
    """Anonymous and unauthenticated users are denied even when
    ``skip_is_active`` is true.

    Missing attributes keep the same defaults as ``is_active_principal``:
    not anonymous, and authenticated. ``None`` is not this denial; callers
    that require an instance still raise.
    """
    if getattr(user, 'is_anonymous', False):
        return True
    if not getattr(user, 'is_authenticated', True):
        return True
    return False


class AuthorizedQuerySet(QuerySet):
    """Instance-only authorized-row filter. No Django permission codec.

    ``permission`` must be a model instance. Strings and auth.Permission
    *codenames* raise ``TrustsConfigurationError`` with zero SQL. This
    method does not parse ``:condition``, does not call
    ``is_active_principal``, and does not call ``get_permission``.

    An authenticated user whose ``is_active`` is false receives an empty
    queryset unless ``skip_is_active`` is true. Anonymous and
    unauthenticated users receive an empty queryset even when
    ``skip_is_active`` is true, before ``granted()``. ``None`` still
    fails at the grant binding, which is not a positive result. The public
    content-list inquiry is
    ``PermittedQuerySet.permitted(permission, user, conditions=())``.
    ``.authorized`` stays this lower-level projection: it does not use
    that permitted-input validation. Core ``.authorized`` includes
    relationship-family handles only; it is not Django's object-level
    backend OR.
    """

    def authorized(self, user, permission, extra_q=None, *,
                   skip_is_active=False, **skip_flags):
        from trusts.apps import _relationship_implementation_handles
        from trusts.core import (
            TrustsConfigurationError,
            _handles_enforce_is_active,
            _inquiry_skipped,
            granted,
        )

        if not isinstance(permission, Model):
            raise TrustsConfigurationError(
                'permission must be a model instance, not %r.' % (permission,)
            )
        skipped = _inquiry_skipped(skip_is_active, **skip_flags)
        handles = _relationship_implementation_handles()
        if user_identity_denied(user):
            return self.none()
        if (
            stored_user_is_inactive(user)
            and _handles_enforce_is_active(handles, skipped)
        ):
            return self.none()
        granted_q = granted(
            handles,
            self, user, permission, kind='complete',
            skip_is_active=skip_is_active,
            skipped=skipped,
        )
        if granted_q is None:
            return self.none()
        if extra_q is not None:
            granted_q = granted_q & extra_q
        return bind_once(self.filter(granted_q).distinct())


class AuthorizedManagerMixin:
    """Add ``authorized()`` without replacing an application's manager."""

    def authorized(self, user, permission, extra_q=None, *,
                   skip_is_active=False, **skip_flags):
        return AuthorizedQuerySet.authorized(
            self.get_queryset(), user, permission, extra_q=extra_q,
            skip_is_active=skip_is_active, **skip_flags,
        )


class PermittedQuerySetMixin:
    """Add ``permitted()`` to an application queryset.

    Mix this into the queryset, then expose that queryset with
    ``as_manager()`` or ``Manager.from_queryset``. A manager-only mixin
    cannot serve ``filter(...).permitted(...)``.
    """

    def permitted(self, permission, user, conditions=(), *,
                  skip_is_active=False, **skip_flags):
        """Rows in this queryset ``user`` may access for ``permission``.

        ``permission`` is one full ``app_label.codename`` string or one
        saved ``auth.Permission`` instance. The protected model is
        ``self.model``. The codename is not parsed to guess a model.
        ``conditions`` is an exact tuple of queryable names, ANDed.
        Anonymous users, and inactive users unless ``skip_is_active``,
        receive an empty queryset. Malformed input and incomplete
        configuration raise before that shortcut and before SQL.

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
            skip_is_active=skip_is_active,
            **skip_flags,
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

    def get_permitted_users(self, perm, *, skip_is_active=False, **skip_flags):
        from trusts.reverse import compile_permitted_users

        return compile_permitted_users(
            self, perm, skip_is_active=skip_is_active, **skip_flags,
        )


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

    def permitted(self, content, perm, *, skip_is_active=False, **skip_flags):
        from trusts.reverse import compile_permitted_users

        return compile_permitted_users(
            content, perm, user_queryset=self.get_queryset(),
            skip_is_active=skip_is_active, **skip_flags,
        )


AuthorizedManager = Manager.from_queryset(AuthorizedQuerySet)
