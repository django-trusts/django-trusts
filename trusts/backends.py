"""Generic Trusts backend mixin.

The backend borrows the recorder and catalog of the app config that
contains its class. That config is a ``TrustsConfigMixin``. Inquiry
reads ``self.catalog``. Each listed backend answers from that catalog
only. A miss returns nothing. Callers OR the grant ``Q`` objects.
"""

from django.apps import apps
from django.contrib.auth import get_backends, load_backend
from django.contrib.auth.models import Permission
from django.db.models import Model, Q, QuerySet

from trusts.apps import TrustsConfigMixin
from trusts.compile.catalogs import (
    _assert_same_database,
    _catalog_models,
    _database_alias,
    _reject_permission_shape,
    _require_saved_content,
)
from trusts.errors import TrustsConfigurationError
from trusts.plan.contents import permitted_content_q
from trusts.plan.relations import bind_checked_user, known_skip_names
from trusts.plan.rewrites import bind_once
from trusts.plan.users import assert_persisted_principal


class TrustModelBackendMixin(object):
    """Object-permission backend. The catalog belongs to the app config."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        config = apps.get_containing_app_config(type(self).__module__)
        if not isinstance(config, TrustsConfigMixin):
            dotted = '%s.%s' % (type(self).__module__, type(self).__qualname__)
            raise TrustsConfigurationError(
                '%s must live inside an app whose config subclasses '
                'TrustsConfigMixin.' % dotted)
        self.catalog = config.get_catalog()
        self.recorder = config.recorder

    def get_catalog(self):
        """Catalog taken from the containing app config at construction."""
        return self.catalog

    def has_perm(self, user_obj, permext, obj=None, **skip_flags):
        """Object check. No object denies."""
        if obj is None or not isinstance(obj, (QuerySet, Model)):
            return False
        return self.catalog.has_perm(user_obj, permext, obj, **skip_flags)

    def get_all_permissions(self, user_obj, obj=None, **skip_flags):
        if obj is None or not isinstance(obj, (QuerySet, Model)):
            return set()
        return self.catalog.get_all_permissions(user_obj, obj, **skip_flags)

    def get_group_permissions(self, user_obj, obj=None, **skip_flags):
        if obj is None or not isinstance(obj, (QuerySet, Model)):
            return set()
        return self.catalog.get_group_permissions(user_obj, obj, **skip_flags)

    def singular_permission_accepted(self, perm):
        """``auth.Permission`` only, unless a backend overrides this."""
        return isinstance(perm, Permission)

    def permitted_users_predicate(self, content, perm, *, skipped=()):
        """``Q`` over candidate users, or ``None`` when this path does not apply."""
        return self.catalog.permitted_users_predicate(
            content, perm, skipped=skipped,
            accepts_permission=self.singular_permission_accepted,
        )

    def authorized_grant_q(self, subject, user, permission, *, skipped=()):
        return self.catalog.complete_grant_q(
            subject, user, permission, skipped=skipped)

    def permitted_grant_q(self, subject, user, permission, *, skipped=(),
                          conditions=(), binding=None, api=None):
        model = subject.model if isinstance(subject, QuerySet) else subject
        predicate, _owned = self.catalog.authorization_grant(
            subject, user, model, permission, conditions, binding,
            api=api, skipped=skipped)
        return predicate

    def content_prefix_q(self, subject, user, permission, *, skipped=(),
                         content=None):
        return permitted_content_q(
            subject.model, user, permission, content=content,
            catalog=self.catalog, skipped=skipped)


def permission_backends(backend=None):
    """Listed backends, or the one ``backend`` dotted path."""
    if backend is None:
        return get_backends()
    if not isinstance(backend, str):
        raise TypeError(
            'backend must be a dotted import path string (got %r).' % backend)
    return (load_backend(backend),)


def trusts_backends(backend=None):
    """Listed Trusts backends. Each answers from its own catalog."""
    return tuple(
        item for item in permission_backends(backend)
        if isinstance(item, TrustModelBackendMixin))


def listed_catalogs(backend=None):
    """Catalogs of those backends, in ``AUTHENTICATION_BACKENDS`` order."""
    found = {}
    for item in trusts_backends(backend):
        catalog = item.get_catalog()
        found.setdefault(id(catalog), catalog)
    return tuple(found.values())


def filter_listed(queryset, subject, user, permission, *, kind, backend=None,
                  skip_flags, require_user=True, extra_q=None, **grant_kw):
    """OR the listed grant, then filter, distinct, and bind once."""
    _inquiry, granted_q, user_model = open_grant(
        kind, subject, user, permission, backend=backend,
        skip_flags=skip_flags, require_user=require_user, **grant_kw)
    if granted_q is None:
        return queryset.none()
    if extra_q is not None:
        granted_q &= extra_q
    return bind_once(
        queryset.filter(granted_q).distinct(), user_model=user_model)


def open_grant(kind, subject, user, permission, *, backend=None, chosen=None,
               skip_flags=None, require_user=True, model=None, **grant_kw):
    """Preflight names, then OR. A denied user does not compile the grant."""
    if chosen is None:
        chosen = trusts_backends(backend)
    inquiry = bind_checked_user(
        user, skip_flags=skip_flags, require_user=require_user,
        skip_names=known_skip_names(item.get_catalog() for item in chosen))
    if kind == 'permitted':
        resolved = model if model is not None else getattr(subject, 'model', subject)
        _selected_conditions_owned(
            resolved, grant_kw.get('conditions') or (), chosen,
            grant_kw.get('api'))
    if inquiry.denied:
        return inquiry, None, None
    granted, user_model = _combine(
        kind, subject, user if require_user else None, permission,
        chosen, inquiry.values, grant_kw)
    return inquiry, granted, user_model


def compile_permitted_users(content, perm, *, user_queryset=None,
                            backend=None, **skip_flags):
    """Lazy user queryset for one saved content object and one permission.

    Listed backends are asked once, in order. Each catalog that
    registered the content contributes its user predicate, including
    that catalog's override. The predicates are OR'd. ``backend`` is
    one dotted path. ``skip_<name>`` is a bound parameter on that
    predicate. The user queryset's model is the principal that is bound.
    """
    _require_saved_content(content)
    _reject_permission_shape(perm)
    chosen = trusts_backends(backend)
    if user_queryset is None:
        user_model = next((
            item.get_catalog().user_model for item in chosen
            if item.get_catalog().user_model is not None
        ), None)
        if user_model is None:
            raise TrustsConfigurationError(
                'get_permitted_users has no user model. '
                'The catalog is not built yet.')
        user_queryset = user_model._default_manager.get_queryset()
    elif not isinstance(user_queryset, QuerySet):
        raise TrustsConfigurationError(
            'user queryset must be a QuerySet, not %r.' % (user_queryset,))
    principal_model = user_queryset.model
    assert_persisted_principal(principal_model)
    involved = [principal_model, type(content)]
    if isinstance(perm, (str, Permission)):
        involved.append(Permission)
    _inquiry, combined, _catalog_user = open_grant(
        'users', content, None, perm, chosen=chosen,
        skip_flags=skip_flags, require_user=False)
    if combined is None:
        combined = Q(pk__isnull=True)
    else:
        for item in chosen:
            involved.extend(
                _catalog_models(item.get_catalog(), content, principal_model))
    alias = _database_alias(content, user_queryset)
    _assert_same_database(alias, involved)
    if user_queryset.db != alias:
        user_queryset = user_queryset.using(alias)
    return bind_once(
        user_queryset.filter(combined).distinct(), user_model=principal_model)


def _missing_condition(api, conditions, model):
    raise TrustsConfigurationError(
        '%s condition %r is not registered on %s.'
        % (api, conditions[0], model._meta.label))


def _selected_conditions_owned(model, conditions, chosen, api):
    if not conditions:
        return
    incomplete = False
    for item in chosen:
        has_plan, owns = item.get_catalog().authorization_preflight(
            model, conditions)
        if owns:
            return
        incomplete = incomplete or has_plan
    if incomplete:
        _missing_condition(api, conditions, model)


def _combine(kind, subject, user, permission, chosen, skipped, grant_kw):
    combined = user_model = None
    seen = set()
    for item in chosen:
        catalog = item.get_catalog()
        marker = id(catalog)
        if marker in seen:
            continue
        seen.add(marker)
        part = _grant_q(item, kind, subject, user, permission, skipped, grant_kw)
        if part is None:
            continue
        combined = part if combined is None else combined | part
        if user_model is None:
            user_model = catalog.user_model
    return combined, user_model


def _grant_q(item, kind, subject, user, permission, skipped, grant_kw):
    if kind == 'users':
        return item.permitted_users_predicate(
            subject, permission, skipped=skipped)
    if kind == 'authorized':
        return item.authorized_grant_q(
            subject, user, permission, skipped=skipped)
    if kind == 'prefix':
        return item.content_prefix_q(
            subject, user, permission, skipped=skipped,
            content=grant_kw.get('content'))
    return item.permitted_grant_q(
        subject, user, permission, skipped=skipped,
        conditions=grant_kw.get('conditions') or (),
        binding=grant_kw.get('binding'), api=grant_kw.get('api'))
