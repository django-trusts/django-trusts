"""Authorized queryset and manager."""

from django.contrib.auth.models import Permission
from django.db.models import Manager, Model, QuerySet

from trusts.apps import catalog_for_model
from trusts.compile.catalogs import (
    assert_authorization_preflight,
    authorization_grant_q,
    codename_binding,
    compile_permitted_users,
    guard_conditions,
    guard_permission_string,
)
from trusts.errors import TrustsConfigurationError
from trusts.plan.relations import bind_checked_user, known_skip_names
from trusts.plan.rewrites import bind_once


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
    that permitted-input validation. ``.authorized`` includes
    relationship-family catalogs only. It is
    not Django's object-level backend OR.
    """

    def authorized(self, user, permission, extra_q=None, **skip_flags):
        if not isinstance(permission, Model):
            raise TrustsConfigurationError(
                'permission must be a model instance, not %r.' % (permission,)
            )

        catalog = catalog_for_model(self.model)
        subjects = () if catalog is None else (catalog,)
        inquiry = bind_checked_user(
            user, skip_flags=skip_flags,
            skip_names=known_skip_names(subjects),
        )
        if user is None:
            raise TrustsConfigurationError(
                'user must be a model instance, not None.'
            )
        if catalog is None or inquiry.denied:
            return self.none()
        granted_q = catalog.complete_grant_q(
            self, user, permission, skipped=inquiry.values,
        )
        if granted_q is None:
            return self.none()
        if extra_q is not None:
            granted_q = granted_q & extra_q
        return bind_once(
            self.filter(granted_q).distinct(), user_model=catalog.user_model,
        )


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
        active-superuser shortcut. A listed backend with no catalog
        contributes nothing.
        """
        model = self.model
        normalized = _normalize_permitted_permission(permission, api='permitted')
        conditions = guard_conditions(conditions, api='permitted')
        catalog = catalog_for_model(model)
        assert_authorization_preflight(
            catalog, model, conditions, api='permitted',
        )
        inquiry = bind_checked_user(
            user, skip_flags=skip_flags,
            skip_names=known_skip_names((catalog,)),
        )
        if inquiry.denied:
            return self.none()
        granted_q = authorization_grant_q(
            catalog,
            self,
            user,
            model,
            _condition_permission_label(model, normalized),
            conditions,
            _permitted_binding(model, normalized),
            api='permitted',
            skipped=inquiry.values,
        )
        if granted_q is None:
            return self.none()
        return bind_once(
            self.filter(granted_q).distinct(), user_model=catalog.user_model,
        )


class PermittedQuerySet(PermittedQuerySetMixin, QuerySet):
    """Concrete queryset for ``permitted(permission, user, conditions=())``."""


class PermittedUsersMixin:
    """Content-instance adapter for the reverse permission inquiry.

    ``content.get_permitted_users(perm)`` is the path that exists on
    every protected model that mixes this in. It is not a content-manager
    method: ``Content.objects`` keeps returning content rows.
    """

    def get_permitted_users(self, perm, **skip_flags):
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
        return compile_permitted_users(
            content, perm, user_queryset=self.get_queryset(), **skip_flags,
        )


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
                '%s permission must be a saved auth.Permission instance.'
                % (api,)
            )
        codename = permission.codename
        if (
            not isinstance(codename, str)
            or not codename
            or codename != codename.strip()
            or ':' in codename
        ):
            raise TrustsConfigurationError(
                '%s permission codename is malformed: %r.' % (api, codename)
            )
        return ('instance', permission, codename)
    raise TypeError(
        '%s permission must be an app_label.codename string or a saved '
        'auth.Permission instance, not %r.'
        % (api, type(permission).__name__)
    )




def _permitted_binding(model, normalized):
    if normalized[0] == 'string':
        return codename_binding(model, normalized[1], normalized[2])
    return normalized[1]


def _condition_permission_label(model, normalized):
    """``app_label.codename`` passed to condition ``compile_q``."""
    if normalized[0] == 'string':
        return normalized[3]
    return '%s.%s' % (model._meta.app_label, normalized[2])
