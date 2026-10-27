"""View guard and the public permitted-content filter.

Each listed Trusts backend answers on its own, in
``AUTHENTICATION_BACKENDS`` order. The caller combines those answers.
A catalog that did not register the model contributes nothing.
"""

from functools import reduce, wraps

from django.apps import apps as django_apps
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Model
from django.db.models.query import QuerySet
from django.http import Http404

from trusts.errors import TrustsConfigurationError
from trusts.backends import trusts_backends
from trusts.utils import guard_conditions, guard_permission_string


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
    predicate is evaluated. Each listed backend is asked separately and
    the querysets are combined. ``backend`` selects one dotted path.

    """
    if not isinstance(queryset, QuerySet):
        model = content if isinstance(content, type) else content.__class__
        return model._default_manager.none()
    parts = [
        part for item in trusts_backends(backend)
        if not (part := item.filter_by_permitted_content(
            queryset, user, permission, content=content, **skip_flags,
        )).query.is_empty()
    ]
    if not parts:
        return queryset.none()
    return reduce(lambda left, right: left | right, parts)


def authorization_required(model, permission, conditions=(), backend=None,
                           **skip_flags):
    """Trusts-only view guard: explicit model, pk URL kwarg, optional names.

    Candidate identity is only ``view_kwargs["pk"]`` bound to
    ``model._meta.pk``. Each listed Trusts backend is asked on its own,
    in order, or only the backend named by ``backend``. The request is
    allowed when any one returns a row. A catalog that did not register
    the model, or that does not own every selected name, contributes
    an empty queryset and does not raise. Denial when no backend
    returns a row is ``PermissionDenied`` when the row exists and
    ``Http404`` when it does not. ``backend`` is one dotted path.
    Does not use ``user.has_perm`` or
    the legacy
    ``permission_required`` / ``P`` / ``K`` / ``G`` / ``O`` surface.
    Django's object-level ``user.has_perm`` OR across authentication
    backends is a different layer.

    An active superuser is allowed only when a registered user override
    passes, or when an ordinary grant does. ``skip_<name>`` keywords
    are forwarded to that same inquiry. ``skip_<override>`` turns off
    the override parameter and leaves ordinary grants in place.

    ``PermittedQuerySet.permitted`` uses the same permission codec. It
    asks each listed backend from that backend's own catalog and ORs
    those grants. It has no HTTP status.
    """
    if not isinstance(model, type) or not issubclass(model, Model):
        raise TypeError(
            'authorization_required model must be a Django model class, '
            'not %r.' % (model,))
    _guard_permission(model, permission)
    conditions = guard_conditions(conditions, api='authorization_required')

    def decorator(view_func):
        @wraps(view_func)
        def _wrapped_view(request, *args, **kwargs):
            _authorize_candidate(
                request, kwargs, model, permission, conditions,
                skip_flags, backend)
            return view_func(request, *args, **kwargs)
        return _wrapped_view
    return decorator


def _guard_permission(model, permission):
    app_label, codename = guard_permission_string(permission, api='authorization_required')
    if app_label.lower() != model._meta.app_label.lower():
        raise TrustsConfigurationError(
            'authorization_required permission app_label %r does not match model %s.'
            % (app_label, model._meta.label))
    return app_label, codename


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
    for item in trusts_backends(backend):
        if item.filter_permitted(
            candidates, request.user, permission, conditions=conditions,
            **skip_flags,
        ).exists():
            return
    if (
        request.user is None or getattr(request.user, 'is_anonymous', False)
        or not getattr(request.user, 'is_authenticated', True)
    ):
        raise PermissionDenied
    if candidates.exists():
        raise PermissionDenied
    raise Http404
