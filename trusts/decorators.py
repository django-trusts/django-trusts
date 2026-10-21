"""View guard and the public permitted-content filter.

Each listed backend answers from its own catalog, in
``AUTHENTICATION_BACKENDS`` order. Grants are OR'd. A catalog that
did not register the model contributes nothing and does not raise.
"""

from functools import wraps

from django.apps import apps as django_apps
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Model
from django.db.models.query import QuerySet
from django.http import Http404

from trusts.plan.hops import require_instance
from trusts.errors import TrustsConfigurationError
from trusts.plan.rewrites import bind_once
from trusts.backends import filter_listed, grant_permitted, grant_prefix, open_grant
from trusts.compile.catalogs import (
    codename_binding,
    guard_conditions,
    guard_permission_string,
)


CHECK_ID_AUTHORIZATION_REQUIRED = 'trusts.E008'

_declared_authorization_guards = []


def filter_by_permitted_content(queryset, user, permission, *, content,
                                backend=None, **skip_flags):
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
    queryset still returns ``none()``. A catalog that did not register
    the model, or a scope model not on the path, returns ``none()``.
    ``permission`` must be a model instance. Construction of a
    fail-closed result issues zero SQL; SQL runs only when a compiled
    predicate is evaluated. Listed backends are asked in order and
    their grants are OR'd. ``backend`` selects one dotted path.

    """
    if not isinstance(queryset, QuerySet):
        raise TrustsConfigurationError(
            'filter_by_permitted_content requires a QuerySet, not %r.'
            % (queryset,))
    user = require_instance(user, 'user')
    permission = require_instance(permission, 'permission')
    return filter_listed(
        queryset, queryset, user, permission, ask=grant_prefix,
        backend=backend, skip_flags=skip_flags, content=content)


def authorization_required(model, permission, conditions=(), backend=None,
                           **skip_flags):
    """Trusts-only view guard: explicit model, pk URL kwarg, optional names.

    Candidate identity is only ``view_kwargs["pk"]`` bound to
    ``model._meta.pk``. Each listed backend uses its own catalog, in
    order. A catalog that did not register the model contributes
    nothing and does not raise; the guard then answers 404 or denial.
    Selected names must be owned together by one participating backend,
    and that failure raises before a grant query. Grants are OR'd.
    ``backend`` is one dotted path. Does not use ``user.has_perm``
    or the legacy ``permission_required``
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
    conditions = guard_conditions(conditions, api='authorization_required')
    _remember_authorization_guard(model, permission, conditions)

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            _authorize_candidate(
                request, kwargs, model, permission, conditions, skip_flags, backend)
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def _guard_model(model):
    if not isinstance(model, type) or not issubclass(model, Model):
        raise TypeError(
            'authorization_required model must be a Django model class, '
            'not %r.' % (model,))
    return model


def _guard_permission(model, permission):
    app_label, codename = guard_permission_string(permission, api='authorization_required')
    if app_label.lower() != model._meta.app_label.lower():
        raise TrustsConfigurationError(
            'authorization_required permission app_label %r does not match model %s.'
            % (app_label, model._meta.label))
    return app_label, codename


def _remember_authorization_guard(model, permission, conditions):
    entry = (model, permission, conditions)
    if entry not in _declared_authorization_guards:
        _declared_authorization_guards.append(entry)


def _coerce_pk(model, raw):
    if raw is None or (isinstance(raw, str) and not raw.strip()):
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
                         skip_flags, backend):
    if 'pk' not in view_kwargs:
        raise Http404
    pk = _coerce_pk(model, view_kwargs.get('pk'))
    if not django_apps.ready:
        raise TrustsConfigurationError(
            'authorization_required cannot authorize before Django apps '
            'are ready.')
    candidates = model._default_manager.filter(pk=pk)
    inquiry, granted_q, user_model, _chosen = open_grant(
        grant_permitted, candidates, request.user, permission,
        backend=backend, skip_flags=skip_flags, conditions=conditions,
        preflight=True, api='authorization_required', model=model,
        binding=codename_binding(model, *permission.split('.', 1)))
    if inquiry.denied:
        raise PermissionDenied
    if granted_q is not None and bind_once(
        candidates.filter(granted_q), user_model=user_model).exists():
        return
    if candidates.exists():
        raise PermissionDenied
    raise Http404
