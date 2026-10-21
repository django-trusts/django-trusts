"""Generic Trusts backend mixin.

The backend borrows the recorder and catalog of the app config that
contains its class. That config is a ``TrustsConfigMixin``. Inquiry
reads ``self.catalog``. Each listed backend answers from that catalog
only. A miss returns nothing. Callers OR the grant ``Q`` objects.
"""

from django.apps import apps
from django.contrib.auth import get_backends, load_backend
from django.contrib.auth.models import Permission
from django.core.exceptions import ImproperlyConfigured
from django.db.models import Model, Q, QuerySet

from trusts.apps import TrustsConfigMixin
from trusts.compile.catalogs import (
    assert_same_database,
    catalog_models,
    database_alias,
    reject_permission_shape,
    require_saved_content,
)
from trusts.errors import TrustsConfigurationError
from trusts.plan.contents import permitted_content_q
from trusts.plan.relations import bind_checked_user, known_skip_names
from trusts.plan.rewrites import bind_once
from trusts.plan.users import assert_persisted_principal


class _MixinRequired(ImproperlyConfigured): pass


def _mixin_required_message(config, backend_path):
    return (
        'Backend %s is not inside an app whose config extends '
        'TrustsConfigMixin.' % backend_path
        if config is None else
        'App %s must extend TrustsConfigMixin.' % config.label)


class TrustModelBackendMixin(object):
    """Object-permission backend. The catalog belongs to the app config."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        config = apps.get_containing_app_config(type(self).__module__)
        if not isinstance(config, TrustsConfigMixin):
            raise _MixinRequired(_mixin_required_message(
                config,
                '%s.%s' % (type(self).__module__, type(self).__qualname__),
            ))
        self.catalog = config.catalog
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
        """Permissions this catalog grants on the object."""
        if obj is None or not isinstance(obj, (QuerySet, Model)):
            return set()
        return self.catalog.get_all_permissions(user_obj, obj, **skip_flags)

    def get_group_permissions(self, user_obj, obj=None, **skip_flags):
        """Group permissions this catalog grants on the object."""
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
        """Grant for an authorized-row filter."""
        return self.catalog.complete_grant_q(
            subject, user, permission, skipped=skipped)

    def permitted_grant_q(self, subject, user, permission, *, skipped=(),
                          conditions=(), binding=None, api=None):
        """Grant for a permitted-row filter."""
        model = subject.model if isinstance(subject, QuerySet) else subject
        predicate, _owned = self.catalog.authorization_grant(
            subject, user, model, permission, conditions, binding,
            api=api, skipped=skipped)
        return predicate

    def content_prefix_q(self, subject, user, permission, *, skipped=(),
                         content=None):
        """Grant for a permitted-content prefix."""
        return permitted_content_q(
            subject.model, user, permission, content=content,
            catalog=self.catalog, skipped=skipped)


def grant_users(item, subject, user, permission, skipped, grant_kw):
    """User predicate from this backend's catalog."""
    return item.permitted_users_predicate(
        subject, permission, skipped=skipped)


def grant_authorized(item, subject, user, permission, skipped, grant_kw):
    """Authorized-row grant from this backend's catalog."""
    return item.authorized_grant_q(
        subject, user, permission, skipped=skipped)


def grant_prefix(item, subject, user, permission, skipped, grant_kw):
    """Permitted-content prefix grant from this backend's catalog."""
    return item.content_prefix_q(
        subject, user, permission, skipped=skipped,
        content=grant_kw.get('content'))


def grant_permitted(item, subject, user, permission, skipped, grant_kw):
    """Permitted-row grant from this backend's catalog."""
    return item.permitted_grant_q(
        subject, user, permission, skipped=skipped,
        conditions=grant_kw.get('conditions') or (),
        binding=grant_kw.get('binding'), api=grant_kw.get('api'))


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


def filter_listed(queryset, subject, user, permission, *, ask, backend=None,
                  skip_flags, require_user=True, preflight=False, extra_q=None,
                  **grant_kw):
    """OR the listed grant, then filter, distinct, and bind once."""
    _inquiry, granted_q, user_model, _chosen = open_grant(
        ask, subject, user, permission, backend=backend,
        skip_flags=skip_flags, require_user=require_user,
        preflight=preflight, **grant_kw)
    if granted_q is None:
        return queryset.none()
    if extra_q is not None:
        granted_q &= extra_q
    return bind_once(
        queryset.filter(granted_q).distinct(), user_model=user_model)


def open_grant(ask, subject, user, permission, *, backend=None,
               skip_flags=None, require_user=True, preflight=False,
               model=None, **grant_kw):
    """Preflight names, then OR. A denied user does not compile the grant."""
    chosen = trusts_backends(backend)
    inquiry = bind_checked_user(
        user, skip_flags=skip_flags, require_user=require_user,
        skip_names=known_skip_names(item.get_catalog() for item in chosen))
    if preflight:
        resolved = model if model is not None else getattr(subject, 'model', subject)
        _selected_conditions_owned(
            resolved, grant_kw.get('conditions') or (), chosen,
            grant_kw.get('api'))
    if inquiry.denied:
        return inquiry, None, None, chosen
    granted, user_model = _combine(
        ask, subject, user if require_user else None, permission,
        chosen, inquiry.values, grant_kw)
    return inquiry, granted, user_model, chosen


def compile_permitted_users(content, perm, *, user_queryset=None,
                            backend=None, **skip_flags):
    """Lazy user queryset for one saved content object and one permission.

    Listed backends are asked once, in order. Each catalog that
    registered the content contributes its user predicate, including
    that catalog's override. The predicates are OR'd. ``backend`` is
    one dotted path. ``skip_<name>`` is a bound parameter on that
    predicate. The user queryset's model is the principal that is bound.
    """
    require_saved_content(content)
    reject_permission_shape(perm)
    _inquiry, combined, _, chosen = open_grant(
        grant_users, content, None, perm, backend=backend,
        skip_flags=skip_flags, require_user=False)
    if user_queryset is None:
        if not chosen:
            raise TrustsConfigurationError(
                'No Trusts backend is listed in AUTHENTICATION_BACKENDS.')
        user_model = chosen[0].get_catalog().user_model
        user_queryset = user_model._default_manager.get_queryset()
    elif not isinstance(user_queryset, QuerySet):
        raise TrustsConfigurationError(
            'user queryset must be a QuerySet, not %r.' % (user_queryset,))
    principal_model = user_queryset.model
    assert_persisted_principal(principal_model)
    involved = [principal_model, type(content)]
    if isinstance(perm, (str, Permission)):
        involved.append(Permission)
    if combined is None:
        combined = Q(pk__isnull=True)
    else:
        for item in chosen:
            involved.extend(
                catalog_models(item.get_catalog(), content, principal_model))
    alias = database_alias(content, user_queryset)
    assert_same_database(alias, involved)
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


def _combine(ask, subject, user, permission, chosen, skipped, grant_kw):
    combined = user_model = None
    seen = set()
    for item in chosen:
        catalog = item.get_catalog()
        marker = id(catalog)
        if marker in seen:
            continue
        seen.add(marker)
        part = ask(item, subject, user, permission, skipped, grant_kw)
        if part is None:
            continue
        combined = part if combined is None else combined | part
        if user_model is None:
            user_model = catalog.user_model
    return combined, user_model
