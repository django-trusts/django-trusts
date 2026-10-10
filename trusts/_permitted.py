"""HTTP-free compiler for ``permitted`` and ``authorization_required``.

The view decorator keeps pk coercion, HTTP statuses, the active-superuser
existence shortcut, and ``trusts.E008`` bookkeeping. This module is the
shared preflight and grant. ``handles`` is an explicit private input so
another package can supply its own later. Runtime ``.permitted()`` calls
are not recorded for ``trusts.E008``.
"""

from functools import reduce
from operator import or_

from django.contrib.auth.models import Permission
from django.db.models import Subquery

from trusts.core import TrustsConfigurationError, _ordinary_records, granted
from trusts.query import is_active_principal


def _guard_permission_string(permission, *, api):
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


def _guard_conditions(conditions, *, api):
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
    """Return a string or saved exact ``auth.Permission`` descriptor.

    Construction does not read ``permission.content_type``. The grant
    predicate checks that row against the queryset model.
    """
    if isinstance(permission, str):
        app_label, codename = _guard_permission_string(permission, api=api)
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


def _permission_binding(model, app_label, codename):
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
        return _permission_binding(model, normalized[1], normalized[2])
    return normalized[1]


def _condition_permission_label(model, normalized):
    """``app_label.codename`` key passed to condition ``compile_q``.

    Instance input uses the protected model's app label and the
    instance codename. It does not dereference ``content_type``.
    """
    if normalized[0] == 'string':
        return normalized[3]
    return '%s.%s' % (model._meta.app_label, normalized[2])


def _plan_is_auth_permission(plan, sponsor_records=()):
    """True when ``plan`` is applicable and terminates on auth.Permission."""
    permission_model = getattr(plan, 'permission_model', None)
    if (
        plan.records
        and permission_model is not None
        and permission_model._meta.concrete_model is Permission
    ):
        return True
    for delegation in getattr(plan, 'delegations', ()) or ():
        for ordinary in sponsor_records:
            if ordinary.content_model is not delegation.content_model:
                continue
            if ordinary.user_model is not delegation.sponsor_model:
                continue
            expected = delegation.condition_permission_model
            if expected is not None and ordinary.permission_model is not expected:
                continue
            if (
                expected is not None
                and ordinary.permission_target
                != delegation.condition_permission_target
            ):
                continue
            if ordinary.permission_model._meta.concrete_model is Permission:
                return True
    return False


def _auth_permission_plan(handle, candidates, user, handles):
    """Applicable plan only when the permission terminal is auth.Permission.

    ``granted()`` does not pass a Subquery into ``plan_for(..., permission=)``.
    A plan whose permission model is not ``auth.Permission`` would compare
    its integer FK to ``auth_permission.pk`` and could grant on a colliding
    id. Those plans are omitted from this string and instance guard.
    """
    plan = handle.registry.plan_for(candidates, user=user)
    if not _plan_is_auth_permission(
        plan, _ordinary_records(handles, candidates),
    ):
        return None
    return plan


def _auth_permission_plan_for_model(handle, model, handles):
    """Zero-SQL applicable auth.Permission plan for this content model."""
    registry = getattr(handle, 'registry', None)
    plan_for = getattr(registry, 'plan_for', None)
    if not callable(plan_for):
        return None
    plan = plan_for(model)
    if not _plan_is_auth_permission(plan, _ordinary_records(handles, model)):
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
    condition (the same rule as ``trusts.E008``). Callers that have an
    active-superuser shortcut must not run it until this returns a
    complete pair. ``trusts.E008`` itself only sees guards recorded by
    ``authorization_required``.
    """
    participating = False
    for handle in handles:
        if _auth_permission_plan_for_model(handle, model, handles) is None:
            continue
        participating = True
        if _backend_has_selected_conditions(handle, model, conditions):
            return True, True
    return participating, False


def _assert_authorization_preflight(handles, model, conditions, *, api):
    """Fail closed on unsupported or incomplete guard configuration."""
    participating, complete = _authorization_preflight_state(
        handles, model, conditions,
    )
    if participating and complete:
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


def _overlay_for_backend(handle, model, permission, conditions, user, *, api):
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
                '%s condition %r on %s is unsupported.'
                % (api, name, model._meta.label)
            )
        part = lookup.compile_q(model, '%s:%s' % (permission, name), user)
        extra_q = part if extra_q is None else extra_q & part
    return extra_q


def _authorization_grant_q(handles, candidates, user, model, permission,
                           conditions, binding, *, api):
    """OR each auth-Permission backend's grant composed with its own names.

    A backend participates only when it has an applicable exact
    ``auth.Permission`` terminal and, when names are selected, owns every
    one of them as a queryable condition. Non-owners contribute nothing,
    including an unconditioned grant. Backend order does not change the
    predicate. No complete owner raises ``TrustsConfigurationError``.
    """
    parts = []
    complete = 0
    for handle in handles:
        if _auth_permission_plan(handle, candidates, user, handles) is None:
            continue
        if conditions:
            overlay = _overlay_for_backend(
                handle, model, permission, conditions, user, api=api,
            )
            if overlay is None:
                continue
            complete += 1
            part = granted(
                (handle,), candidates, user, binding, kind='complete',
                sponsor_handles=handles,
                permission_model=Permission,
            )
            if part is None:
                continue
            parts.append(part & overlay)
            continue
        part = granted(
            (handle,), candidates, user, binding, kind='complete',
            sponsor_handles=handles,
            permission_model=Permission,
        )
        if part is None:
            continue
        parts.append(part)
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


def permitted_queryset(queryset, permission, user, conditions=(), *, handles):
    """Lazy filtered queryset of rows ``user`` may access.

    ``handles`` selects the backends. Core passes relationship-family
    implementation handles. Input and configuration are validated before
    the anonymous and inactive shortcut, and before SQL. A well-formed
    permission for another content type is an empty queryset. This call
    does not register a ``trusts.E008`` guard and does not copy Django's
    active-superuser shortcut.
    """
    model = queryset.model
    normalized = _normalize_permitted_permission(permission, api='permitted')
    conditions = _guard_conditions(conditions, api='permitted')
    _assert_authorization_preflight(
        handles, model, conditions, api='permitted',
    )
    if not is_active_principal(user):
        return queryset.none()
    granted_q = _authorization_grant_q(
        handles,
        queryset,
        user,
        model,
        _condition_permission_label(model, normalized),
        conditions,
        _permitted_binding(model, normalized),
        api='permitted',
    )
    if granted_q is None:
        return queryset.none()
    return queryset.filter(granted_q).distinct()
