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
from trusts.errors import TrustsConfigurationError
from trusts.plan.contents import permitted_content_q
from trusts.plan.relations import bind_checked_user, known_skip_names
from trusts.plan.rewrites import bind_once


_INCOMPLETE = object()


def permission_backends(backend=None):
    """Listed backends, or the one ``backend`` dotted path."""
    if backend is None:
        return get_backends()
    if not isinstance(backend, str):
        raise TypeError('backend must be a dotted import path string (got %r).' % backend)
    return (load_backend(backend),)


def trusts_backends(backend=None):
    """Listed backends that implement ``content_grant_q``."""
    return tuple(item for item in permission_backends(backend) if hasattr(item, 'content_grant_q'))


def listed_catalogs(backend=None):
    """Catalogs of those backends, in ``AUTHENTICATION_BACKENDS`` order."""
    found = {}
    for item in trusts_backends(backend):
        catalog = item.get_catalog()
        found.setdefault(id(catalog), catalog)
    return tuple(found.values())


def _missing_condition(api, conditions, model):
    raise TrustsConfigurationError(
        '%s condition %r is not registered on %s.' % (api, conditions[0], model._meta.label))


def _selected_conditions_owned(model, conditions, *, backend, api):
    """Raise when a participating catalog does not own every selected name."""
    if not conditions:
        return
    incomplete = False
    for item in trusts_backends(backend):
        has_plan, owns = item.get_catalog().authorization_preflight(model, conditions)
        if owns:
            return
        incomplete = incomplete or has_plan
    if incomplete:
        _missing_condition(api, conditions, model)


def combined_grant(kind, subject, user, permission, *, backend=None, skipped=(), **grant_kw):
    """OR each backend's grant ``Q``. ``model`` is only for the error."""
    model = grant_kw.pop('model', None)
    combined = user_model = None
    incomplete = False
    for item in trusts_backends(backend):
        part = item.content_grant_q(
            subject, user, permission, kind=kind, skipped=skipped, **grant_kw)
        if part is _INCOMPLETE:
            incomplete = True
        elif part is not None:
            combined = part if combined is None else combined | part
            user_model = user_model or item.get_catalog().user_model
    if combined is None and incomplete:
        _missing_condition(grant_kw.get('api'), grant_kw.get('conditions'), model)
    return combined, user_model


def open_grant(kind, subject, user, permission, *, backend=None, skip_flags=None,
               require_user=True, **grant_kw):
    """Preflight names, then OR. A denied user does not compile the grant."""
    chosen = trusts_backends(backend)
    inquiry = bind_checked_user(
        user, skip_flags=skip_flags, require_user=require_user,
        skip_names=known_skip_names(item.get_catalog() for item in chosen))
    if kind == 'permitted':
        model = grant_kw.get('model', getattr(subject, 'model', subject))
        _selected_conditions_owned(
            model, grant_kw.get('conditions') or (), backend=backend, api=grant_kw.get('api'))
    if inquiry.denied:
        return inquiry, None, None
    granted, user_model = combined_grant(
        kind, subject, user if require_user else None, permission,
        backend=backend, skipped=inquiry.values, **grant_kw)
    return inquiry, granted, user_model


def _filter_listed(queryset, subject, user, permission, *, kind, backend=None,
                   skip_flags, require_user=True, extra_q=None, **grant_kw):
    """OR the listed grant, then filter, distinct, and bind once."""
    _inquiry, granted_q, user_model = open_grant(
        kind, subject, user, permission, backend=backend, skip_flags=skip_flags,
        require_user=require_user, **grant_kw)
    if granted_q is None:
        return queryset.none()
    if extra_q is not None:
        granted_q &= extra_q
    return bind_once(
        queryset.filter(granted_q).distinct(), user_model=user_model or queryset.model)


def manager_with_perm(self, perm, is_active=True, include_superusers=True,
                      backend=None, obj=None):
    """OR listed backends. Trusts ignores ``is_active`` and
    ``include_superusers``; other backends keep Django's flags.
    """
    parts = []
    if obj is not None:
        granted, _user_model = combined_grant('users', obj, None, perm, backend=backend)
        if granted is not None:
            parts.append(granted)
    for candidate in permission_backends(backend):
        if hasattr(candidate, 'content_grant_q'):
            continue
        method = getattr(candidate, 'with_perm', None)
        if method is not None:
            parts.append(Q(pk__in=method(
                perm, is_active=is_active, include_superusers=include_superusers, obj=obj)))
    if not parts:
        return self.none()
    combined = parts[0]
    for part in parts[1:]:
        combined |= part
    return bind_once(self.filter(combined).distinct(), user_model=self.model)


class TrustModelBackendMixin(object):
    """Object-permission backend. The catalog belongs to the app config."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        config = apps.get_containing_app_config(type(self).__module__)
        if not isinstance(config, TrustsConfigMixin):
            dotted = '%s.%s' % (type(self).__module__, type(self).__qualname__)
            raise TrustsConfigurationError(
                '%s must live inside an app whose config subclasses TrustsConfigMixin.' % dotted)
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

    def get_permitted_users(self, content, perm, **skip_flags):
        """Users permitted on ``content``."""
        return self.catalog.permitted_users(content, perm, **skip_flags)

    def with_perm(self, perm, is_active=True, include_superusers=True, obj=None):
        """Users holding ``perm`` on ``obj``. No object yields no users."""
        del is_active, include_superusers
        if obj is None:
            return self._no_users()
        return self.catalog.permitted_users(obj, perm)

    def content_grant_q(self, subject, user, permission, *, kind, skipped=(),
                        conditions=(), content=None, api=None, binding=None):
        """This catalog's grant ``Q``, or ``None`` when it does not apply."""
        catalog = self.catalog
        if kind == 'authorized':
            return catalog.complete_grant_q(subject, user, permission, skipped=skipped)
        if kind == 'prefix':
            return permitted_content_q(
                subject.model, user, permission, content=content, catalog=catalog, skipped=skipped)
        if kind == 'users':
            return self.permitted_users_predicate(subject, permission, skipped=skipped)
        if kind != 'permitted':
            raise TrustsConfigurationError('Unknown grant kind %r.' % (kind,))
        model = subject.model if isinstance(subject, QuerySet) else subject
        has_plan, owns = catalog.authorization_preflight(model, conditions)
        if not has_plan:
            return None
        if conditions and not owns:
            return _INCOMPLETE
        predicate, _owns = catalog.authorization_grant(
            subject, user, model, permission, conditions, binding, api=api, skipped=skipped)
        return predicate

    def singular_permission_accepted(self, perm):
        """``auth.Permission`` only, unless a backend overrides this."""
        return isinstance(perm, Permission)

    def permitted_users_predicate(self, content, perm, *, skipped=()):
        """``Q`` over candidate users, or ``None`` when this path does not apply."""
        return self.catalog.permitted_users_predicate(
            content, perm, skipped=skipped,
            accepts_permission=self.singular_permission_accepted,
        )

    def _no_users(self):
        """Empty user queryset from the catalog's user model."""
        return self.catalog.user_model._default_manager.none()
