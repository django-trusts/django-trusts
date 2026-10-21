# Inert library module. Do not list 'trusts' in INSTALLED_APPS.
# This file defines no Model subclasses. Canonical models live in Zero.

from django.contrib.auth.models import Permission
from django.db.models import Manager, Model, QuerySet

from trusts.backends import (
    compile_permitted_users, filter_listed, grant_authorized, grant_permitted)
from trusts.compile.catalogs import (
    codename_binding,
    guard_conditions,
    guard_permission_string,
)
from trusts.errors import TrustsConfigurationError


class AuthorizedQuerySet(QuerySet):
    """Instance-only authorized-row filter. No Django permission codec.

    ``permission`` must be a model instance. Strings and auth.Permission
    *codenames* raise ``TrustsConfigurationError`` with zero SQL. This
    method does not parse ``:condition`` and does not call
    ``get_permission``.

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
    that permitted-input validation. It asks the listed backends, in
    order, and ORs each catalog's grant.
    """

    def authorized(self, user, permission, extra_q=None, backend=None,
                   **skip_flags):
        if not isinstance(permission, Model):
            raise TrustsConfigurationError(
                'permission must be a model instance, not %r.' % (permission,))
        if user is None:
            raise TrustsConfigurationError('user must be a model instance, not None.')
        return filter_listed(
            self, self, user,
            ask=lambda item, skipped: grant_authorized(
                item, skipped, self, user, permission),
            backend=backend, skip_flags=skip_flags, extra_q=extra_q)


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

    def permitted(self, permission, user, conditions=(), backend=None,
                  **skip_flags):
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

        Each listed backend answers from its own catalog, in
        ``AUTHENTICATION_BACKENDS`` order. A catalog that did not
        register this model contributes an empty grant and does not
        raise. Grants are OR'd. ``backend`` is one dotted path.
        There is no active-superuser shortcut.
        """
        model = self.model
        normalized = _normalize_permitted_permission(permission, api='permitted')
        conditions = guard_conditions(conditions, api='permitted')
        label = _condition_permission_label(model, normalized)
        binding = _permitted_binding(model, normalized)
        return filter_listed(
            self, self, user,
            ask=lambda item, skipped: grant_permitted(
                item, skipped, self, user, label,
                conditions=conditions, binding=binding, api='permitted'),
            backend=backend, skip_flags=skip_flags, preflight=True,
            model=model, conditions=conditions, api='permitted')


class PermittedQuerySet(PermittedQuerySetMixin, QuerySet):
    """Concrete queryset for ``permitted(permission, user, conditions=())``."""


class PermittedUsersMixin:
    """Content-instance adapter for the reverse permission inquiry.

    ``content.get_permitted_users(perm)`` is the path that exists on
    every protected model that mixes this in. It is not a content-manager
    method: ``Content.objects`` keeps returning content rows.
    """

    def get_permitted_users(self, perm, backend=None, **skip_flags):
        return compile_permitted_users(self, perm, backend=backend, **skip_flags)


class PermittedUsersManagerMixin:
    """Optional adapter on an application's existing user manager.

    ``permitted`` and ``with_perm`` both call the one reverse inquiry.
    That inquiry asks each listed backend for its user predicate and
    ORs them. ``backend`` is one dotted path. Stock ``auth.User`` does
    not acquire either method. The content adapter
    ``get_permitted_users`` remains the path that does not require a
    user-manager change.
    """

    def permitted(self, content, perm, backend=None, **skip_flags):
        return compile_permitted_users(
            content, perm, user_queryset=self.get_queryset(), backend=backend,
            **skip_flags,
        )

    def with_perm(self, perm, is_active=True, include_superusers=True,
                  backend=None, obj=None, **skip_flags):
        """Users holding ``perm`` on ``obj``. No object yields no users.

        ``is_active`` and ``include_superusers`` are ignored. The
        catalog's user conditions decide. ``skip_<name>`` is forwarded.
        """
        del is_active, include_superusers
        if obj is None:
            return self.get_queryset().none()
        return compile_permitted_users(
            obj, perm, user_queryset=self.get_queryset(),
            backend=backend, **skip_flags)


PermittedManager = Manager.from_queryset(PermittedQuerySet)
AuthorizedManager = Manager.from_queryset(AuthorizedQuerySet)


def _normalize_permitted_permission(permission, *, api):
    """String or saved ``auth.Permission``. Does not read ``content_type``."""
    if isinstance(permission, str):
        app_label, codename = guard_permission_string(permission, api=api)
        return ('string', app_label, codename, permission)
    if permission.__class__ is Permission:
        if permission.pk is None:
            raise TrustsConfigurationError(
                '%s permission must be a saved auth.Permission instance.' % api)
        codename = permission.codename
        if (
            not isinstance(codename, str) or not codename
            or codename != codename.strip() or ':' in codename
        ):
            raise TrustsConfigurationError(
                '%s permission codename is malformed: %r.' % (api, codename))
        return ('instance', permission, codename)
    raise TypeError(
        '%s permission must be an app_label.codename string or a saved '
        'auth.Permission instance, not %r.'
        % (api, type(permission).__name__))


def _permitted_binding(model, normalized):
    if normalized[0] == 'string':
        return codename_binding(model, normalized[1], normalized[2])
    return normalized[1]


def _condition_permission_label(model, normalized):
    """``app_label.codename`` passed to condition ``compile_q``."""
    if normalized[0] == 'string':
        return normalized[3]
    return '%s.%s' % (model._meta.app_label, normalized[2])
