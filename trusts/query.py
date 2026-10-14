"""Generic authorized queryset/manager. No Zero-noun grant helpers."""

from django.db.models import Manager, Model, QuerySet

from trusts._bind_once import bind_once


def is_active_principal(user, *, skipped=()):
    """Match ``User.has_perm``: anonymous and inactive users are denied.

    Superuser short-circuit on ``has_perm`` is a Django ``ModelBackend``
    behavior and is not duplicated in SQL list filters. An ``is_active``
    name in ``skipped`` skips only that built-in check.
    """
    if user is None:
        return False
    if getattr(user, 'is_anonymous', False):
        return False
    if not getattr(user, 'is_authenticated', True):
        return False
    if (
        'is_active' not in frozenset(skipped or ())
        and not getattr(user, 'is_active', False)
    ):
        return False
    return True


def require_mode_flag(value, name):
    """A skip keyword must be a real boolean."""
    if not isinstance(value, bool):
        raise TypeError('%s must be a bool, not %r.' % (name, value))
    return value


def stored_user_is_inactive(user, *, skipped=()):
    """Whether a stored user's built-in ``is_active`` rejects the inquiry.

    An ``is_active`` name in ``skipped`` skips the check. ``None`` is not
    inactive so ``authorized(None)`` still fails at grant binding. A model
    with no ``is_active`` is not inactive: a schema-neutral terminal keeps
    its result, and permission SQL reports that model separately. A
    non-model that presents as a user (``is_authenticated`` or
    ``is_anonymous``) and has no ``is_active`` is denied, the same default
    as ``has_perm``. Any other non-model is not inactive, so grant binding
    still raises. Anonymous and unauthenticated denial stays with the
    caller. A user object that is not a model instance is not a SQL
    principal; permission SQL is compiled against the user model.
    """
    if 'is_active' in frozenset(skipped or ()) or user is None:
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


def single_field_condition_denied(user, conditions, skipped, *, role='user'):
    """True when one single-field condition for ``role`` fails on ``user``.

    A model missing the field is not a denial, matching checked-user SQL
    that omits a missing column. A user-like non-model missing the field
    uses ``False``. Any other non-model missing the field is not a denial.
    ``&`` stays in SQL. A false checked-user override is not a denial:
    conditions are AND-ed outside ``override OR ordinary OR delegation``,
    so a false override must not hide an ordinary grant.
    """
    from trusts.user_rules import (
        BUILTIN_USER_CONDITIONS,
        FieldRef,
        NotExpr,
        condition_targets,
    )

    rules = BUILTIN_USER_CONDITIONS if conditions is None else conditions
    skipped = frozenset(skipped or ())
    for rule in rules:
        if rule.name in skipped or role not in condition_targets(rule.on):
            continue
        expr = rule.expr
        negated = False
        if isinstance(expr, NotExpr) and isinstance(expr.inner, FieldRef):
            negated = True
            expr = expr.inner
        if not isinstance(expr, FieldRef):
            continue
        if _field_value_denies(user, expr.name, negated=negated):
            return True
    return False


def _field_value_denies(user, field_name, *, negated):
    if user is None:
        return False
    present = hasattr(user, field_name)
    if isinstance(user, Model) and not present:
        return False
    if (
        not isinstance(user, Model)
        and not present
        and not hasattr(user, 'is_authenticated')
        and not hasattr(user, 'is_anonymous')
    ):
        return False
    value = bool(getattr(user, field_name, False))
    if negated:
        return value
    return not value


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

    An authenticated user who fails a registered user condition receives
    an empty queryset unless that condition's ``skip_<name>`` keyword is
    true. ``skip_is_active`` is the keyword for the built-in ``is_active``
    condition. Anonymous and unauthenticated users receive an empty
    queryset even when a skip keyword is true, before ``granted()``.
    ``None`` still
    fails at the grant binding, which is not a positive result. The public
    content-list inquiry is
    ``PermittedQuerySet.permitted(permission, user, conditions=())``.
    ``.authorized`` stays this lower-level projection: it does not use
    that permitted-input validation. Core ``.authorized`` includes
    relationship-family handles only; it is not Django's object-level
    backend OR.
    """

    def authorized(self, user, permission, extra_q=None, **skip_flags):
        from trusts.apps import _relationship_implementation_handles
        from trusts.core import (
            TrustsConfigurationError,
            _handles_condition_denied,
            _skipped_for_handles,
            granted,
        )

        if not isinstance(permission, Model):
            raise TrustsConfigurationError(
                'permission must be a model instance, not %r.' % (permission,)
            )
        handles = _relationship_implementation_handles()
        skipped = _skipped_for_handles(handles, skip_flags, user)
        if user_identity_denied(user):
            return self.none()
        if _handles_condition_denied(handles, user, skipped):
            return self.none()
        granted_q = granted(
            handles,
            self, user, permission, kind='complete',
            skipped=skipped,
        )
        if granted_q is None:
            return self.none()
        if extra_q is not None:
            granted_q = granted_q & extra_q
        return bind_once(self.filter(granted_q).distinct())


class AuthorizedManagerMixin:
    """Add ``authorized()`` without replacing an application's manager."""

    def authorized(self, user, permission, extra_q=None, **skip_flags):
        return AuthorizedQuerySet.authorized(
            self.get_queryset(), user, permission, extra_q=extra_q,
            **skip_flags,
        )


class PermittedQuerySetMixin:
    """Add ``permitted()`` to an application queryset.

    Mix this into the queryset, then expose that queryset with
    ``as_manager()`` or ``Manager.from_queryset``. A manager-only mixin
    cannot serve ``filter(...).permitted(...)``.
    """

    def permitted(self, permission, user, conditions=(), **skip_flags):
        """Rows in this queryset ``user`` may access for ``permission``.

        ``permission`` is one full ``app_label.codename`` string or one
        saved ``auth.Permission`` instance. The protected model is
        ``self.model``. The codename is not parsed to guess a model.
        ``conditions`` is an exact tuple of queryable names, ANDed.
        Anonymous users, and users who fail a registered condition unless
        that condition's ``skip_<name>`` keyword is true, receive an empty
        queryset. ``skip_is_active`` is the keyword for the built-in
        ``is_active`` condition. Malformed input and incomplete
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

    def get_permitted_users(self, perm, **skip_flags):
        from trusts.reverse import compile_permitted_users

        return compile_permitted_users(self, perm, **skip_flags)


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

    def permitted(self, content, perm, **skip_flags):
        from trusts.reverse import compile_permitted_users

        return compile_permitted_users(
            content, perm, user_queryset=self.get_queryset(), **skip_flags,
        )


AuthorizedManager = Manager.from_queryset(AuthorizedQuerySet)
