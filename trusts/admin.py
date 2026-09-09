"""Noun-independent authorized ModelAdmin (issue #47 S4).

``AuthorizedModelAdmin`` is configured by operation data. List
querysets use S1 ``filter_authorized`` as ``ChangeList.root_queryset``,
so Django paginates the authorized set. Object gates use S1
``is_authorized`` on the action-specific hook and must agree with the
list queryset when that hook's operation matches ``list_operation``.

Django hooks covered:

* ``list_operation`` → ``get_queryset``
* ``view_operation`` (fallback: ``list_operation``) →
  ``has_view_permission``
* ``change_operation`` → ``has_change_permission``
* ``delete_operation`` → ``has_delete_permission``

``get_object`` retrieves a **singular identity** from the unauthorized
consumer-scoped base (``get_identity_base_queryset``). It does **not**
apply ``view_operation``. Django's change/delete views then call
``has_change_permission`` / ``has_delete_permission`` /
``has_view_or_change_permission``, so a change-only or delete-only
grant is not blocked by an undocumented view ceiling.

Add is fail-closed (``has_add_permission`` is False). An FK/form
queryset helper is not shipped; S4 tests did not demonstrate a generic
need. Consumers who need create-under-scope override add themselves.

``AuthorizationConfigError`` is denied at this security boundary.
``has_*`` methods do not call the Django user-permission helper, so an
active superuser does not bypass registered object policy. Isolated
tests set ``context`` / ``trustee`` on the admin class.
"""

from django.contrib import admin
from django.core.exceptions import PermissionDenied, ValidationError
from django.http import Http404

from trusts.runtime import (
    AuthorizationConfigError,
    filter_authorized,
    is_authorized,
    principal_is_usable,
)
from trusts.views import require_singular_identity


class AuthorizedModelAdmin(admin.ModelAdmin):
    """ModelAdmin whose list and object gates are S1 operation data."""

    list_operation = None
    view_operation = None
    change_operation = None
    delete_operation = None
    context = None
    trustee = None
    names = None

    def get_authorization_runtime(self):
        return dict(context=self.context, trustee=self.trustee, names=self.names)

    def get_list_operation(self):
        return self._require_operation(self.list_operation, 'list_operation')

    def get_view_operation(self):
        operation = self.view_operation
        if operation is None:
            operation = self.list_operation
        return self._require_operation(operation, 'view_operation')

    def get_change_operation(self):
        return self._require_operation(self.change_operation, 'change_operation')

    def get_delete_operation(self):
        return self._require_operation(self.delete_operation, 'delete_operation')

    def _require_operation(self, operation, what):
        if operation is None:
            raise AuthorizationConfigError(
                'AuthorizedModelAdmin requires %s.' % what
            )
        if callable(operation) and getattr(operation, '_meta', None) is None:
            raise AuthorizationConfigError(
                '%s must be operation data, not a callable.' % what
            )
        return operation

    def _principal(self, request):
        return getattr(request, 'user', None)

    def _object_authorized(self, request, operation, obj):
        try:
            return bool(is_authorized(
                self._principal(request), operation, obj,
                **self.get_authorization_runtime()
            ))
        except AuthorizationConfigError:
            return False

    def _module_authorized(self, request, operation):
        if operation is None:
            return False
        if not principal_is_usable(self._principal(request)):
            return False
        try:
            self._require_operation(operation, 'operation')
        except AuthorizationConfigError:
            return False
        return True

    def get_queryset(self, request):
        queryset = super(AuthorizedModelAdmin, self).get_queryset(request)
        try:
            return filter_authorized(
                queryset,
                self._principal(request),
                self.get_list_operation(),
                **self.get_authorization_runtime()
            )
        except AuthorizationConfigError:
            raise PermissionDenied

    def get_identity_base_queryset(self, request):
        """Unauthorized consumer-scoped base for admin object identity.

        Default is the model's default manager. Does **not** use
        ``get_queryset()`` (that applies ``list_operation``). Override
        to add tenant / soft-delete filters. Application scoping
        belongs here, not in the authorization-filtered list.
        """
        return self.model._default_manager.get_queryset()

    def get_object(self, request, object_id, from_field=None):
        """Singular identity lookup. No view/change/delete ceiling.

        Missing rows stay ``None`` (admin 404). Ambiguous identity
        (2+ candidates) raises ``PermissionDenied``. Existing rows are
        returned so Django's action hook can apply
        ``view_operation`` / ``change_operation`` / ``delete_operation``
        independently.
        """
        queryset = self.get_identity_base_queryset(request)
        field = (
            self.model._meta.pk if from_field is None
            else self.model._meta.get_field(from_field)
        )
        try:
            object_id = field.to_python(object_id)
            identity = queryset.filter(**{field.name: object_id})
        except (ValidationError, ValueError):
            return None
        try:
            return require_singular_identity(identity)
        except Http404:
            return None
        except AuthorizationConfigError:
            raise PermissionDenied

    def has_view_permission(self, request, obj=None):
        try:
            operation = self.get_view_operation()
        except AuthorizationConfigError:
            return False
        if obj is None:
            return self._module_authorized(request, operation)
        return self._object_authorized(request, operation, obj)

    def has_change_permission(self, request, obj=None):
        try:
            operation = self.get_change_operation()
        except AuthorizationConfigError:
            return False
        if obj is None:
            return self._module_authorized(request, operation)
        return self._object_authorized(request, operation, obj)

    def has_delete_permission(self, request, obj=None):
        try:
            operation = self.get_delete_operation()
        except AuthorizationConfigError:
            return False
        if obj is None:
            return self._module_authorized(request, operation)
        return self._object_authorized(request, operation, obj)

    def has_add_permission(self, request):
        # Fail closed. Create-under-scope / FK form helpers are not S4.
        return False

    def has_module_permission(self, request):
        try:
            operation = self.list_operation
            if operation is None:
                operation = self.view_operation
            return self._module_authorized(request, operation)
        except AuthorizationConfigError:
            return False


__all__ = [
    'AuthorizedModelAdmin',
]
