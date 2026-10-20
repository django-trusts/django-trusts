"""View guard and the public permitted-content filter.

Answers come from each configured backend's catalog, in
``get_backends()`` order. A listed backend with no catalog contributes
nothing.
"""

from functools import wraps

from django.apps import apps as django_apps
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Model
from django.db.models.query import QuerySet
from django.http import Http404

from trusts.commons import _require_instance
from trusts.errors import TrustsConfigurationError
from trusts.plan.relations import bind_checked_user
from trusts.plan.rewrites import bind_once
from trusts.query import (
    _assert_authorization_preflight,
    _authorization_grant_q,
    _codename_binding,
    _guard_conditions,
    _guard_permission_string,
    _relationship_catalogs,
)


CHECK_ID_AUTHORIZATION_REQUIRED = 'trusts.E008'

_declared_authorization_guards = []


def filter_by_permitted_content(queryset, user, permission, *, content,
                                **skip_flags):
    """Filter scope-model rows that appear as a proper prefix of ``content``.

    Fail closed unless ``queryset.model`` is a proper prefix node of some
    applicable record's ``content_path`` whose content terminal is
    ``content``. Compile ``EXISTS`` of root rows correlated to
    ``OuterRef`` of that hop's resolved target field (the related
    ``attname`` from ``get_path_info()``, which need not be ``pk``) at
    that node, bind user + permission from the same record, and OR
    applicable records.

    An ``along=`` registration uses the same bounded ``WITH RECURSIVE``
    walk as the forward check. A prefix at the walk site is kept when
    its identity is in that walk. A later proper prefix is kept when it
    hangs off a walk-site row in the walk. A one-level delegation
    contributes a prefix only when the delegation and the sponsor's
    ordinary permission both reach it. A second delegation level does
    not. A delegated ``along=`` whose content suffix is longer than one
    reverse hop raises ``TrustsConfigurationError``.

    ``queryset.model`` equal to the content terminal is allowed when a
    proper prefix hop of that same model exists (self-referential
    trees). A terminal-only path has no proper prefix, so the same-model
    queryset still returns ``none()``. Unknown terminal, an empty catalog
    list, or a scope model not on the path also return ``none()``.
    ``permission`` must be a model instance. Construction of a
    fail-closed result issues zero SQL; SQL runs only when a compiled
    predicate is evaluated. Only relationship-family catalogs from the
    ready-time sweep participate, in ``get_backends()`` order. A backend
    with no catalog contributes nothing.

    Noun-blind: this builder does not import or name Zero schema models
    and does not use a compiler's historical group
    OR. Explicit ``group=`` records participate through the same prefix
    correlation. Membership shape is not a group.
    """
    if not isinstance(queryset, QuerySet):
        raise TrustsConfigurationError(
            'filter_by_permitted_content requires a QuerySet, not %r.'
            % (queryset,)
        )
    catalogs = _relationship_catalogs()
    user = _require_instance(user, 'user')
    permission = _require_instance(permission, 'permission')
    inquiry = bind_checked_user(
        user, skip_flags=skip_flags, registries=catalogs,
    )
    if not catalogs or inquiry.denied:
        return queryset.none()
    compiled = []
    for catalog in catalogs:
        part = catalog.filter_by_permitted_content(
            queryset, user, permission, content=content,
            skipped=inquiry.values,
        )
        if not part.query.is_empty():
            compiled.append(part)
    if not compiled:
        return queryset.none()
    if len(compiled) == 1:
        return compiled[0]
    combined = compiled[0]
    for part in compiled[1:]:
        combined = combined | part
    return combined


def filter_authorized_scopes(queryset, user, permission, *, content,
                             **skip_flags):
    return filter_by_permitted_content(
        queryset, user, permission, content=content, **skip_flags,
    )


def authorization_required(model, permission, conditions=(), **skip_flags):
    """Trusts-only view guard: explicit model, pk URL kwarg, optional names.

    Candidate identity is only ``view_kwargs["pk"]`` bound to
    ``model._meta.pk``. Structural configuration is checked with zero
    SQL before any candidate query: at least one applicable
    ``auth.Permission`` plan is required, and selected names must be
    owned together by one participating backend. Invalid configuration
    raises before a grant query. Only applicable plans whose permission
    terminal is ``django.contrib.auth.models.Permission`` participate.
    Each of those backends composes its own grant with its own selected
    names before the backends are OR'd; backend order does not change
    the result. Only relationship-family catalogs participate. A listed
    backend with no catalog contributes nothing. Does not use Django
    backend OR, ``user.has_perm``, or the legacy ``permission_required``
    / ``P`` / ``K`` / ``G`` / ``O`` surface. Django's object-level
    ``user.has_perm`` OR across authentication backends is a different
    layer.

    An active superuser is allowed only when a registered user override
    passes, or when an ordinary grant does. ``skip_<name>`` keywords
    are forwarded to that same inquiry. ``skip_<override>`` turns off
    the override parameter and leaves ordinary grants in place.

    ``PermittedQuerySet.permitted`` is the queryset form of this
    permission codec and condition rule. It has no HTTP status.
    """
    model = _guard_model(model)
    _guard_permission(model, permission)
    conditions = _guard_conditions(conditions, api='authorization_required')
    _remember_authorization_guard(model, permission, conditions)

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            _authorize_candidate(
                request, kwargs, model, permission, conditions, skip_flags,
            )
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


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


def _authorize_candidate(request, view_kwargs, model, permission, conditions,
                         skip_flags):
    catalogs = _relationship_catalogs()
    user = request.user
    raw_pk = view_kwargs.get('pk', None) if 'pk' in view_kwargs else None
    if 'pk' not in view_kwargs:
        raise Http404
    pk = _coerce_pk(model, raw_pk)

    if not django_apps.ready:
        raise TrustsConfigurationError(
            'authorization_required cannot authorize before Django apps '
            'are ready.'
        )
    _assert_authorization_preflight(
        catalogs, model, conditions, api='authorization_required',
    )
    inquiry = bind_checked_user(
        user, skip_flags=skip_flags, registries=catalogs,
    )
    if inquiry.denied:
        raise PermissionDenied

    candidates = model._default_manager.filter(pk=pk)
    app_label, codename = permission.split('.', 1)
    binding = _codename_binding(model, app_label, codename)
    granted_q = _authorization_grant_q(
        catalogs, candidates, user, model, permission, conditions, binding,
        api='authorization_required', skipped=inquiry.values,
    )
    if granted_q is None:
        matched = None
    else:
        matched = bind_once(candidates.filter(granted_q))
        if matched.exists():
            return
    if matched is None:
        if candidates.exists():
            raise PermissionDenied
        raise Http404
    if candidates.exists():
        raise PermissionDenied
    raise Http404
