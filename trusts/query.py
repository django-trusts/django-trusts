"""Generic authorized queryset/manager. No Zero-noun grant helpers."""

from functools import reduce
from operator import or_

from django.contrib.auth.models import Permission
from django.db.models import Manager, Model, Q, QuerySet, Subquery

from django.contrib.auth import get_backends
from django.db import router

from trusts.backends import TrustModelBackendMixin, configured_catalogs
from trusts.errors import TrustsConfigurationError
from trusts.installed import installed_object_blind_backends, user_model
from trusts.plan.contents import relationship_family
from trusts.plan.relations import bind_checked_user
from trusts.plan.rewrites import bind_once
from trusts.plan.standards import BUILTIN_USER_CONDITIONS
from trusts.plan.users import assert_persisted_principal


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

        catalogs = relationship_catalogs()
        inquiry = bind_checked_user(
            user, skip_flags=skip_flags,
            skip_names=catalog_skip_names(catalogs),
        )
        if user is None:
            raise TrustsConfigurationError(
                'user must be a model instance, not None.'
            )
        if inquiry.denied:
            return self.none()
        parts = []
        for catalog in catalogs:
            part = catalog.complete_grant_q(
                self, user, permission, skipped=inquiry.values,
            )
            if part is not None:
                parts.append(part)
        if not parts:
            return self.none()
        granted_q = parts[0] if len(parts) == 1 else reduce(or_, parts)
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
        active-superuser shortcut. A listed backend with no catalog
        contributes nothing.
        """
        model = self.model
        normalized = _normalize_permitted_permission(permission, api='permitted')
        conditions = guard_conditions(conditions, api='permitted')
        catalogs = relationship_catalogs()
        assert_authorization_preflight(
            catalogs, model, conditions, api='permitted',
        )
        inquiry = bind_checked_user(
            user, skip_flags=skip_flags,
            skip_names=catalog_skip_names(catalogs),
        )
        if inquiry.denied:
            return self.none()
        granted_q = authorization_grant_q(
            catalogs,
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
        return bind_once(self.filter(granted_q).distinct())


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


def relationship_catalogs():
    """Relationship catalogs from ``get_catalog()``, in listed-backend order."""
    return relationship_family(configured_catalogs())


def catalog_skip_names(catalogs):
    """Skip-keyword names registered on these catalogs."""
    names = set()
    saw = False
    for catalog in catalogs:
        if catalog is None:
            continue
        saw = True
        names.update(catalog.known_skip_names())
    if not saw:
        names.update(rule.name for rule in BUILTIN_USER_CONDITIONS)
    return frozenset(names)


def guard_permission_string(permission, *, api):
    """Exact ``app_label.codename`` form. Does not infer a model name."""
    if not isinstance(permission, str):
        raise TypeError(
            '%s permission must be an app_label.codename string, not %r.'
            % (api, type(permission).__name__)
        )
    if ':' in permission or permission.count('.') != 1:
        raise TrustsConfigurationError(
            '%s permission must be one base "app_label.codename" string '
            'without a colon: %r.' % (api, permission)
        )
    app_label, codename = permission.split('.')
    if not app_label or not codename:
        raise TrustsConfigurationError(
            '%s permission must be one base "app_label.codename" string, '
            'not %r.' % (api, permission)
        )
    return app_label, codename


def guard_conditions(conditions, *, api):
    if type(conditions) is not tuple:
        raise TypeError(
            '%s conditions must be an exact tuple, not %r.'
            % (api, type(conditions).__name__)
        )
    seen = set()
    for name in conditions:
        if not isinstance(name, str) or not name or name != name.strip() or ':' in name:
            raise TrustsConfigurationError(
                '%s condition name is malformed: %r.' % (api, name)
            )
        if name in seen:
            raise TrustsConfigurationError(
                '%s conditions must not contain duplicates: %r.'
                % (api, name)
            )
        seen.add(name)
    return conditions


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


def codename_binding(model, app_label, codename):
    """Unevaluated pk of the exact codename on ``model``'s content type."""
    return Subquery(
        Permission.objects.filter(
            content_type__app_label=app_label.lower(),
            content_type__model=model._meta.model_name,
            codename=codename,
        ).values('pk')[:1]
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


def assert_authorization_preflight(catalogs, model, conditions, *, api):
    """Fail closed unless one catalog has a plan and owns the names."""
    participating = False
    for catalog in catalogs:
        has_plan, owns = catalog.authorization_preflight(model, conditions)
        if not has_plan:
            continue
        participating = True
        if owns:
            return
    if not participating:
        raise TrustsConfigurationError(
            '%s has no applicable auth.Permission plan for %s.'
            % (api, model._meta.label)
        )
    raise TrustsConfigurationError(
        '%s condition %r is not registered on %s.'
        % (api, conditions[0], model._meta.label)
    )


def authorization_grant_q(catalogs, candidates, user, model, permission,
                           conditions, binding, *, api, skipped=()):
    """OR each catalog's auth.Permission grant. Order does not matter."""
    parts = []
    complete = 0
    for catalog in catalogs:
        predicate, owned = catalog.authorization_grant(
            candidates, user, model, permission, conditions, binding,
            api=api, skipped=skipped,
        )
        if owned:
            complete += 1
        if predicate is not None:
            parts.append(predicate)
    if conditions and complete == 0:
        raise TrustsConfigurationError(
            '%s condition %r is not registered on %s.'
            % (api, conditions[0], model._meta.label)
        )
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return reduce(or_, parts)


AuthorizedManager = Manager.from_queryset(AuthorizedQuerySet)

def compile_permitted_users(content, perm, *, user_queryset=None, **skip_flags):
    """Lazy user queryset for one saved content object and one permission.

    The candidate rows are ``user_queryset`` when given (the optional
    manager adapter) and otherwise the user model stored at ready.
    Each configured backend that can contribute an exact reverse predicate
    is OR-ed. A registered user override is part of the Trusts-owned
    predicate, not a separate superuser grant. The ``is_active`` check
    applies inside the Trusts-owned branch only. A custom predicate is
    not wrapped. ``skip_<name>=True`` sets that bound parameter. The
    values are forwarded only to the Trusts-owned mixin method.
    Django's ``PermissionsMixin.has_perm`` early return is
    not copied here. An unsupported object-permission backend raises
    before SQL.
    """
    _require_saved_content(content)
    _reject_permission_shape(perm)
    catalogs = relationship_catalogs()
    inquiry = bind_checked_user(
        None, skip_flags=skip_flags,
        skip_names=catalog_skip_names(catalogs),
        require_user=False,
    )
    skipped = inquiry.values
    if user_queryset is None:
        model = user_model()
        if model is None:
            raise TrustsConfigurationError(
                'get_permitted_users has no user model. '
                'TrustsImplementationConfig.ready has not stored one.'
            )
        user_queryset = model._default_manager.get_queryset()
    elif not isinstance(user_queryset, QuerySet):
        raise TrustsConfigurationError(
            'user queryset must be a QuerySet, not %r.' % (user_queryset,)
        )
    backends = tuple(get_backends())
    _reject_unaccepted_permission_instance(perm, backends)
    principal_model = user_queryset.model
    assert_persisted_principal(principal_model)
    parts = []
    involved = [principal_model, content.__class__]
    if isinstance(perm, (str, Permission)):
        involved.append(Permission)
    for backend in backends:
        predicate = _backend_predicate(
            backend, content, perm,
            skipped=skipped,
        )
        if predicate is None:
            continue
        if not isinstance(predicate, Q):
            raise TrustsConfigurationError(
                '%s permitted_users_predicate returned %s, not a Q or None.'
                % (type(backend).__name__, type(predicate).__name__)
            )
        _assert_registration_user_model(backend, content, principal_model)
        involved.extend(_registration_models(backend, content))
        parts.append(predicate)
    alias = _database_alias(content, user_queryset)
    _assert_same_database(alias, involved)
    if user_queryset.db != alias:
        user_queryset = user_queryset.using(alias)
    if not parts:
        combined = Q(pk__isnull=True)
    else:
        combined = parts[0]
        for part in parts[1:]:
            combined |= part
    return bind_once(user_queryset.filter(combined).distinct())



def _require_saved_content(content):
    if isinstance(content, QuerySet):
        raise TrustsConfigurationError(
            'get_permitted_users accepts one saved content object, '
            'not a queryset.'
        )
    if not isinstance(content, Model):
        raise TrustsConfigurationError(
            'content must be a saved model instance, not %r.' % (content,)
        )
    if content.pk is None:
        raise TrustsConfigurationError(
            'content must be a saved %s instance.' % content._meta.label
        )


def _reject_permission_shape(perm):
    if isinstance(perm, QuerySet):
        raise TrustsConfigurationError(
            'get_permitted_users accepts one permission, not a queryset.'
        )
    if isinstance(perm, (str, Model)):
        if isinstance(perm, Model) and perm.pk is None:
            raise TrustsConfigurationError(
                'permission must be a saved %s instance.' % perm._meta.label
            )
        return
    raise TrustsConfigurationError(
        'permission must be a permission string or model instance, not %r.'
        % (perm,)
    )


def _object_blind_backends():
    """Django's stock object-blind backends, stored at ready."""
    return installed_object_blind_backends()


def _trusts_owned_reverse_hook(backend):
    """True when the reverse hook is the mixin method, not an override.

    The skipped condition names are passed only through that Trusts-owned
    method. Other hooks are called as
    ``permitted_users_predicate(content, perm)``. Trusts does not require
    them to accept ``skip_<name>`` and does not raise when they do not.
    """
    if not isinstance(backend, TrustModelBackendMixin):
        return False
    return (
        type(backend).permitted_users_predicate
        is TrustModelBackendMixin.permitted_users_predicate
    )


def _backend_predicate(backend, content, perm, *,
                       skipped=()):
    if getattr(backend, 'trusts_object_permissions', None) is False:
        return None
    if _declares_reverse_hook(backend):
        if _trusts_owned_reverse_hook(backend):
            return backend.permitted_users_predicate(
                content, perm, skipped=skipped,
            )
        return backend.permitted_users_predicate(content, perm)
    if type(backend) in _object_blind_backends():
        return None
    raise TrustsConfigurationError(
        '%s may grant an object permission but cannot express an exact '
        'reverse user predicate. get_permitted_users will not return a '
        'partial result.' % type(backend).__name__
    )


def _reject_unaccepted_permission_instance(perm, backends):
    if not isinstance(perm, Model) or isinstance(perm, Permission):
        return
    for backend in backends:
        checker = getattr(backend, 'singular_permission_accepted', None)
        if callable(checker) and checker(perm):
            return
    raise TrustsConfigurationError(
        '%s is not a permission identity accepted by a configured '
        'object-permission backend.' % type(perm).__name__
    )


def _declares_reverse_hook(backend):
    for cls in type(backend).__mro__:
        if 'permitted_users_predicate' in cls.__dict__:
            return True
    return False



def _assert_registration_user_model(backend, content, candidate_model):
    if not isinstance(backend, TrustModelBackendMixin):
        return
    catalog = backend.get_catalog()
    if catalog is None:
        return
    plan = catalog.plan_for(content)
    expected = candidate_model._meta.concrete_model
    for record in plan.records:
        registered = record.user_model._meta.concrete_model
        if registered is not expected:
            raise TrustsConfigurationError(
                'Reverse permission inquiry candidate user model is %s, '
                'but %s registers %s.'
                % (
                    expected._meta.label,
                    record.root._meta.label,
                    registered._meta.label,
                )
            )
    for record in plan.delegations:
        registered = record.delegate_model._meta.concrete_model
        if registered is not expected:
            raise TrustsConfigurationError(
                'Reverse permission inquiry candidate user model is %s, '
                'but %s registers delegate %s.'
                % (
                    expected._meta.label,
                    record.root._meta.label,
                    registered._meta.label,
                )
            )


def _registration_models(backend, content):
    if not isinstance(backend, TrustModelBackendMixin):
        return []
    catalog = backend.get_catalog()
    if catalog is None:
        return []
    plan = catalog.plan_for(content)
    models = []
    for record in plan.records:
        models.extend((
            record.root,
            record.user_model,
            record.permission_model,
            record.content_model,
        ))
    for record in plan.delegations:
        models.extend((
            record.root,
            record.delegate_model,
            record.sponsor_model,
            record.content_model,
        ))
        if record.condition_permission_model is not None:
            models.append(record.condition_permission_model)
    return models


def _database_alias(content, user_queryset):
    state_db = getattr(getattr(content, '_state', None), 'db', None) or None
    if state_db:
        return state_db
    routed = router.db_for_read(user_queryset.model)
    if routed:
        return routed
    return user_queryset.db or 'default'


def _assert_same_database(alias, models):
    seen = set()
    for model in models:
        concrete = model._meta.concrete_model
        if concrete in seen:
            continue
        seen.add(concrete)
        chosen = router.db_for_read(concrete)
        if chosen is not None and chosen != alias:
            raise TrustsConfigurationError(
                'Reverse permission inquiry cannot join %s on database %r; '
                'the router selected %r. Cross-database authorization is '
                'not one SQL statement.'
                % (concrete._meta.label, alias, chosen)
            )

