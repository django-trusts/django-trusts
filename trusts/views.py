"""Generic authorized CBV mixins and stub-template helpers (issue #47 S4).

``AuthorizedQuerySetMixin`` SQL-filters list querysets with S1
``filter_authorized`` before pagination. ``AuthorizedObjectMixin``
resolves a declared URL identity through the same predicate: missing
rows are 404, existing unauthorized rows are 403.

Source identity is established **before** authorization and must be
singular. ``resolve_authorized_object`` never uses ``.first()`` to pick
an authorized row from an ambiguous candidate set.

Application scoping (tenant, soft-delete, an explicit CBV
``queryset``) belongs on ``queryset`` or
``get_identity_base_queryset()``. That hook is unauthorized. It does
not call ``get_queryset()``, which the list mixin already filtered.

Operations and the resource model are declarative data (class
attributes / CBV ``model``). There are no getter, resolver, or policy
callbacks, and no second authorization walker. Isolated tests pass
``context`` / ``trustee`` as class attributes (process-wide maps remain
the no-arg default).

Active superuser status does not bypass registered object policy.
``AuthorizationConfigError`` becomes ``PermissionDenied`` at this
HTTP boundary.

Stub templates live under the ``trusts/`` namespace. Consumers set
``template_name`` or place an earlier ``trusts/authorized_*.html``.
This module does not ship URL patterns or product chrome.
"""

from django.core.exceptions import (
    FieldDoesNotExist,
    PermissionDenied,
    ValidationError,
)
from django.http import Http404

from trusts.runtime import (
    AuthorizationConfigError,
    filter_authorized,
    is_authorized,
    principal_is_usable,
)


class AuthorizedQuerySetMixin(object):
    """List-style CBV mixin. ``get_queryset`` is S1-filtered before pagination.

    Declarative data:

    * ``list_operation`` — operation instance or ``operation_lookup``
      string. ``operation`` is accepted as a fallback.
    * ``model`` / ``queryset`` — from the CBV; never inferred from a
      Django permission string. ``queryset`` is also the default
      application scope for ``AuthorizedObjectMixin``.
    * ``context`` / ``trustee`` / ``names`` — isolated registries.

    Default ``template_name`` is ``trusts/authorized_list.html``.
    Override it on the view or with a project/app template of the same
    name. Unusable principals receive an empty queryset (ordinary
    denial). Malformed configuration is 403.
    """

    list_operation = None
    operation = None
    context = None
    trustee = None
    names = None
    template_name = 'trusts/authorized_list.html'

    def get_authorization_runtime(self):
        return dict(context=self.context, trustee=self.trustee, names=self.names)

    def get_list_operation(self):
        operation = self.list_operation
        if operation is None:
            operation = self.operation
        if operation is None:
            raise AuthorizationConfigError(
                'AuthorizedQuerySetMixin requires list_operation or operation.'
            )
        if callable(operation) and getattr(operation, '_meta', None) is None:
            raise AuthorizationConfigError(
                'list_operation must be operation data, not a callable.'
            )
        return operation

    def get_queryset(self):
        queryset = super(AuthorizedQuerySetMixin, self).get_queryset()
        try:
            return filter_authorized(
                queryset,
                getattr(self.request, 'user', None),
                self.get_list_operation(),
                **self.get_authorization_runtime()
            )
        except AuthorizationConfigError:
            raise PermissionDenied


class AuthorizedObjectMixin(object):
    """Detail/update-style CBV mixin. Object identity is a declared URL key.

    Declarative data:

    * ``object_operation`` — operation instance or lookup string.
      ``view_operation`` then ``operation`` are fallbacks.
    * ``pk_url_kwarg`` / ``slug_url_kwarg`` / ``slug_field`` /
      ``query_pk_and_slug`` — Django CBV identity keys, not resolver
      callbacks. When ``query_pk_and_slug`` is True and both values
      are present, both constrain the row.
    * ``model`` / ``queryset`` — explicit CBV model and optional
      application scope.
    * ``context`` / ``trustee`` / ``names`` — isolated registries.

    Application filters belong on ``queryset`` or
    ``get_identity_base_queryset()``. Do not put them only in an
    override of ``get_queryset()`` after the list mixin has already
    applied ``list_operation``.

    Default ``template_name`` is ``trusts/authorized_detail.html``.
    Update-style views should set ``template_name`` to
    ``trusts/authorized_form.html`` (or a consumer override).
    """

    object_operation = None
    view_operation = None
    operation = None
    context = None
    trustee = None
    names = None
    template_name = 'trusts/authorized_detail.html'

    def get_authorization_runtime(self):
        return dict(context=self.context, trustee=self.trustee, names=self.names)

    def get_object_operation(self):
        operation = self.object_operation
        if operation is None:
            operation = self.view_operation
        if operation is None:
            operation = self.operation
        if operation is None:
            raise AuthorizationConfigError(
                'AuthorizedObjectMixin requires object_operation, '
                'view_operation, or operation.'
            )
        if callable(operation) and getattr(operation, '_meta', None) is None:
            raise AuthorizationConfigError(
                'object_operation must be operation data, not a callable.'
            )
        return operation

    def get_identity_base_queryset(self):
        """Unauthorized consumer-scoped base for object identity.

        Uses the declared CBV ``queryset`` when set, otherwise the
        model's default manager. Does **not** call ``get_queryset()``:
        the list mixin filters that with ``list_operation``, which
        would hide unauthorized-but-in-scope rows as 404.
        """
        declared = getattr(self, 'queryset', None)
        if declared is not None:
            return declared.all()
        model = getattr(self, 'model', None)
        if model is None:
            raise AuthorizationConfigError(
                'AuthorizedObjectMixin requires an explicit model or queryset.'
            )
        return model._default_manager.all()

    def get_identity_queryset(self, queryset=None):
        """Apply declared pk/slug identity to the consumer-scoped base."""
        if queryset is None:
            queryset = self.get_identity_base_queryset()
        model = queryset.model
        pk_url_kwarg = getattr(self, 'pk_url_kwarg', 'pk')
        slug_url_kwarg = getattr(self, 'slug_url_kwarg', 'slug')
        slug_field = getattr(self, 'slug_field', 'slug')
        query_pk_and_slug = getattr(self, 'query_pk_and_slug', False)
        kwargs = getattr(self, 'kwargs', None) or {}
        pk = kwargs.get(pk_url_kwarg, None)
        slug = kwargs.get(slug_url_kwarg, None)
        has_pk = pk is not None and pk != ''
        has_slug = slug is not None and slug != ''
        if has_pk:
            queryset = queryset.filter(pk=pk)
        if has_slug and (not has_pk or query_pk_and_slug):
            try:
                model._meta.get_field(slug_field)
            except FieldDoesNotExist:
                raise AuthorizationConfigError(
                    'slug_field %r is not a field on %s.' % (
                        slug_field, model._meta.label,
                    )
                )
            queryset = queryset.filter(**{slug_field: slug})
        if not has_pk and not has_slug:
            raise Http404
        return queryset

    def get_context_data(self, **kwargs):
        context = super(AuthorizedObjectMixin, self).get_context_data(**kwargs)
        context.setdefault('update_url', getattr(self, 'update_url', None))
        context.setdefault('delete_url', getattr(self, 'delete_url', None))
        return context

    def get_object(self, queryset=None):
        try:
            identity = self.get_identity_queryset(queryset)
            return resolve_authorized_object(
                identity,
                getattr(self.request, 'user', None),
                self.get_object_operation(),
                **self.get_authorization_runtime()
            )
        except AuthorizationConfigError:
            raise PermissionDenied
        except (ValidationError, ValueError, TypeError):
            raise Http404


def require_singular_identity(queryset):
    """Return the only row in ``queryset``, or fail closed.

    Source identity is checked **before** authorization. ``.first()``
    is not used.

    * 0 rows → ``Http404`` (1 SQL ``[:2]``).
    * 2+ rows → ``PermissionDenied`` (1 SQL ``[:2]``). Ambiguous
      identity is never resolved by order or by which row is granted.
    * 1 row → that instance.
    """
    matched = list(queryset[:2])
    if len(matched) > 1:
        raise PermissionDenied
    if not matched:
        raise Http404
    return matched[0]


def resolve_authorized_object(queryset, principal, operation, **runtime):
    """Authorize the singular row from a consumer-scoped identity queryset.

    ``queryset`` is the candidate set **after** application scope and
    declared identity filters, **before** Trusts authorization. It must
    already be singular.

    * 0 candidates → ``Http404``.
    * 2+ candidates → ``PermissionDenied`` (not an existential grant).
    * 1 candidate, unusable principal → ``PermissionDenied`` (the
      identity query already ran; no auth ``Exists``).
    * 1 candidate, granted → the instance (identity ``[:2]`` plus
      ``is_authorized``).
    * 1 candidate, denied / unknown operation data →
      ``PermissionDenied``.
    * ``AuthorizationConfigError`` → ``PermissionDenied``.
    """
    try:
        obj = require_singular_identity(queryset)
        if not principal_is_usable(principal):
            raise PermissionDenied
        if is_authorized(principal, operation, obj, **runtime):
            return obj
        raise PermissionDenied
    except AuthorizationConfigError:
        raise PermissionDenied


__all__ = [
    'AuthorizedObjectMixin',
    'AuthorizedQuerySetMixin',
    'require_singular_identity',
    'resolve_authorized_object',
]
