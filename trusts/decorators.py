from functools import reduce, wraps
from operator import or_

from django.contrib.auth.models import Permission
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Model, Subquery
from django.http import Http404

from trusts.core import TrustsConfigurationError, granted
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
    if not isinstance(permission, str):
        raise TypeError(
            'authorization_required permission must be an app_label.codename '
            'string, not %r.' % (type(permission).__name__,)
        )
    if ':' in permission or permission.count('.') != 1:
        raise TrustsConfigurationError(
            'authorization_required permission must be one base '
            '"app_label.codename" string without a colon: %r.' % (permission,)
        )
    app_label, codename = permission.split('.')
    if not app_label or not codename:
        raise TrustsConfigurationError(
            'authorization_required permission must be one base '
            '"app_label.codename" string, not %r.' % (permission,)
        )
    if app_label.lower() != model._meta.app_label.lower():
        raise TrustsConfigurationError(
            'authorization_required permission app_label %r does not match '
            'model %s.' % (app_label, model._meta.label)
        )
    return app_label, codename


def _guard_conditions(conditions):
    if type(conditions) is not tuple:
        raise TypeError(
            'authorization_required conditions must be an exact tuple, not %r.'
            % (type(conditions).__name__,)
        )
    seen = set()
    for name in conditions:
        if not isinstance(name, str) or not name or name != name.strip() or ':' in name:
            raise TrustsConfigurationError(
                'authorization_required condition name is malformed: %r.'
                % (name,)
            )
        if name in seen:
            raise TrustsConfigurationError(
                'authorization_required conditions must not contain duplicates: %r.'
                % (name,)
            )
        seen.add(name)
    return conditions


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


def _permission_binding(model, app_label, codename):
    return Subquery(
        Permission.objects.filter(
            content_type__app_label=app_label.lower(),
            content_type__model=model._meta.model_name,
            codename=codename,
        ).values('pk')[:1]
    )


def _plan_is_auth_permission(plan):
    """True when ``plan`` is applicable and terminates on auth.Permission."""
    permission_model = getattr(plan, 'permission_model', None)
    if permission_model is None:
        return False
    if permission_model._meta.concrete_model is not Permission:
        return False
    if not plan.records and getattr(plan, 'strategy', None) is None:
        return False
    return True


def _auth_permission_plan(handle, candidates, user):
    """Applicable plan only when the permission terminal is auth.Permission.

    ``granted()`` does not pass a Subquery into ``plan_for(..., permission=)``.
    A plan whose permission model is not ``auth.Permission`` would compare
    its integer FK to ``auth_permission.pk`` and could grant on a colliding
    id. Those plans are omitted from this string-permission guard.
    """
    plan = handle.registry.plan_for(candidates, user=user)
    if not _plan_is_auth_permission(plan):
        return None
    return plan


def _auth_permission_plan_for_model(handle, model):
    """Zero-SQL applicable auth.Permission plan for this content model."""
    registry = getattr(handle, 'registry', None)
    plan_for = getattr(registry, 'plan_for', None)
    if not callable(plan_for):
        return None
    plan = plan_for(model)
    if not _plan_is_auth_permission(plan):
        return None
    return plan


def _backend_has_selected_conditions(handle, model, conditions):
    """True when this handle registers every selected name with a queryable expr."""
    if not conditions:
        return True
    lookup = getattr(getattr(handle, 'registry', None), 'condition_lookup', None)
    if lookup is None:
        return False
    record_for = getattr(lookup, 'record_for', None)
    if not callable(record_for):
        return False
    for name in conditions:
        record = record_for(model, name)
        if record is None or getattr(record, 'expr', None) is None:
            return False
    return True


def _authorization_preflight_state(handles, model, conditions):
    """Return ``(participating, complete)`` with zero SQL.

    ``participating`` is True when at least one handle has an applicable
    ``auth.Permission`` plan for ``model``. ``complete`` is True when one
    of those backends also owns every selected name as a queryable
    condition (the same rule as ``trusts.E008``). The active-superuser
    existence shortcut must not run until this returns a complete pair.
    """
    participating = False
    for handle in handles:
        if _auth_permission_plan_for_model(handle, model) is None:
            continue
        participating = True
        if _backend_has_selected_conditions(handle, model, conditions):
            return True, True
    return participating, False


def _assert_authorization_preflight(handles, model, conditions):
    """Fail closed on unsupported or incomplete guard configuration."""
    participating, complete = _authorization_preflight_state(
        handles, model, conditions,
    )
    if participating and complete:
        return
    if not participating:
        raise TrustsConfigurationError(
            'authorization_required has no applicable auth.Permission '
            'plan for %s.' % (model._meta.label,)
        )
    raise TrustsConfigurationError(
        'authorization_required condition %r is not registered on %s.'
        % (conditions[0], model._meta.label)
    )


def _overlay_for_backend(handle, model, permission, conditions, user):
    """Compose this backend's selected names, or None if any name is missing."""
    lookup = getattr(handle.registry, 'condition_lookup', None)
    if lookup is None:
        return None
    extra_q = None
    for name in conditions:
        record = lookup.record_for(model, name)
        if record is None:
            return None
        if getattr(record, 'expr', None) is None:
            raise TrustsConfigurationError(
                'authorization_required condition %r on %s is unsupported.'
                % (name, model._meta.label)
            )
        part = lookup.compile_q(model, '%s:%s' % (permission, name), user)
        extra_q = part if extra_q is None else extra_q & part
    return extra_q


def _authorization_grant_q(handles, candidates, user, model, permission,
                           conditions, binding):
    """OR each auth-Permission backend's grant composed with its own names.

    Backends that do not register every selected name are omitted; their
    unconditioned grants do not participate. Backend order does not change
    the predicate. If no backend registers the complete name set, fail
    closed instead of falling back to an unconditioned grant.
    """
    parts = []
    complete = 0
    for handle in handles:
        if _auth_permission_plan(handle, candidates, user) is None:
            continue
        if conditions:
            overlay = _overlay_for_backend(
                handle, model, permission, conditions, user,
            )
            if overlay is None:
                continue
            complete += 1
            part = granted((handle,), candidates, user, binding, kind='complete')
            if part is None:
                continue
            parts.append(part & overlay)
            continue
        part = granted((handle,), candidates, user, binding, kind='complete')
        if part is None:
            continue
        parts.append(part)
    if conditions and complete == 0:
        raise TrustsConfigurationError(
            'authorization_required condition %r is not registered on %s.'
            % (conditions[0], model._meta.label)
        )
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return reduce(or_, parts)


def _authorize_candidate(request, view_kwargs, model, permission, conditions):
    from django.apps import apps as django_apps
    from trusts.apps import _relationship_implementation_handles

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
    handles = _relationship_implementation_handles()
    _assert_authorization_preflight(handles, model, conditions)

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
    """
    model = _guard_model(model)
    _guard_permission(model, permission)
    conditions = _guard_conditions(conditions)
    _remember_authorization_guard(model, permission, conditions)

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            _authorize_candidate(request, kwargs, model, permission, conditions)
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator
