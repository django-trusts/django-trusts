from functools import wraps

from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Model
from django.http import Http404

from trusts._permitted import (
    _assert_authorization_preflight,
    _authorization_grant_q,
    _guard_conditions,
    _guard_permission_string,
    _permission_binding,
)
from trusts.core import TrustsConfigurationError
from trusts.query import is_active_principal


CHECK_ID_AUTHORIZATION_REQUIRED = 'trusts.E008'

_declared_authorization_guards = []


def _guard_model(model):
    if not isinstance(model, type) or not issubclass(model, Model):
        raise TypeError(
            'authorization_required model must be a Django model class, not %r.'
            % (model,)
        )
    return model


def _guard_permission(model, permission):
    app_label, codename = _guard_permission_string(
        permission, api='authorization_required',
    )
    if app_label.lower() != model._meta.app_label.lower():
        raise TrustsConfigurationError(
            'authorization_required permission app_label %r does not match '
            'model %s.' % (app_label, model._meta.label)
        )
    return app_label, codename


def _remember_authorization_guard(model, permission, conditions):
    entry = (model, permission, conditions)
    if entry not in _declared_authorization_guards:
        _declared_authorization_guards.append(entry)


def _coerce_pk(model, raw):
    if raw is None:
        raise Http404
    if isinstance(raw, str) and raw.strip() == '':
        raise Http404
    field = model._meta.pk
    try:
        value = field.to_python(raw)
    except (ValidationError, ValueError, TypeError):
        raise Http404
    if value is None:
        raise Http404
    try:
        field.get_prep_value(value)
    except (ValidationError, ValueError, TypeError):
        raise Http404
    return value


def _authorize_candidate(request, view_kwargs, model, permission, conditions):
    from django.apps import apps as django_apps
    from trusts.apps import _relationship_implementation_handles

    handles = _relationship_implementation_handles()

    user = getattr(request, 'user', None)
    raw_pk = view_kwargs.get('pk', None) if 'pk' in view_kwargs else None
    if 'pk' not in view_kwargs:
        raise Http404
    pk = _coerce_pk(model, raw_pk)

    is_superuser = bool(
        user is not None
        and getattr(user, 'is_active', False)
        and getattr(user, 'is_superuser', False)
        and not getattr(user, 'is_anonymous', False)
    )
    if not is_superuser and not is_active_principal(user):
        raise PermissionDenied

    if not django_apps.ready:
        raise TrustsConfigurationError(
            'authorization_required cannot authorize before Django apps '
            'are ready.'
        )
    _assert_authorization_preflight(
        handles, model, conditions, api='authorization_required',
    )

    candidates = model._default_manager.filter(pk=pk)
    if is_superuser:
        if not candidates.exists():
            raise Http404
        return

    app_label, codename = permission.split('.', 1)
    binding = _permission_binding(model, app_label, codename)
    granted_q = _authorization_grant_q(
        handles,
        candidates,
        user,
        model,
        permission,
        conditions,
        binding,
        api='authorization_required',
    )
    if granted_q is None:
        if candidates.exists():
            raise PermissionDenied
        raise Http404
    if candidates.filter(granted_q).exists():
        return
    if candidates.exists():
        raise PermissionDenied
    raise Http404


def authorization_required(model, permission, conditions=()):
    """Trusts-only view guard: explicit model, pk URL kwarg, optional names.

    Candidate identity is only ``view_kwargs["pk"]`` bound to
    ``model._meta.pk``. Structural configuration is checked with zero
    SQL before any candidate query: at least one applicable
    ``auth.Permission`` plan is required, and selected names must be
    owned together by one participating backend. Active superusers
    then take one existence query and bypass grants and conditions;
    invalid configuration never reaches that shortcut. Only applicable
    plans whose permission terminal is
    ``django.contrib.auth.models.Permission`` participate. Each of
    those backends composes its own grant with its own selected names
    before the backends are OR'd; backend order does not change the
    result. Only relationship-family implementation handles participate.
    Does not use Django backend OR, ``user.has_perm``, or the
    legacy ``permission_required`` / ``P`` / ``K`` / ``G`` / ``O``
    surface. Django's object-level ``user.has_perm`` OR across
    authentication backends is a different layer.

    ``PermittedQuerySet.permitted`` is the queryset form of this
    permission codec and condition rule. It has no HTTP status and no
    active-superuser shortcut.
    """
    model = _guard_model(model)
    _guard_permission(model, permission)
    conditions = _guard_conditions(conditions, api='authorization_required')
    _remember_authorization_guard(model, permission, conditions)

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            _authorize_candidate(request, kwargs, model, permission, conditions)
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
