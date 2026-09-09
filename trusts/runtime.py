"""Object and scope authorization execution (issue #47 S1).

``is_authorized`` / ``filter_authorized`` and the scope-origin siblings
compile through ``AuthorizationPath.compose`` / ``compose_scope``. Object
and list share one ``grant_q``. There is no preliminary operation
``get()`` and no public ``scope_from_row``.

Denial versus configuration:

* Explicitly unusable principals are ordinary denials, checked **before**
  requester-model identity. A principal is explicitly unusable when any of
  ``is_anonymous is True``, ``is_authenticated is False``, or
  ``is_active is False``. Django's ``AnonymousUser`` therefore denies
  instead of raising a wrong-model config error.
* Unknown operation *data* also denies (``False``, empty queryset,
  ``AuthorizationDenied``), including a string the configured
  ``operation_lookup`` field cannot prepare (for example
  ``operation_lookup='id'`` plus ``'missing'``).
* Usable principals that are the wrong requester model, raw PKs,
  unregistered resources, missing adapters, mixed/stale terminals,
  reserved slots, and incomplete ``operation_lookup`` raise
  ``AuthorizationConfigError``. Direct APIs never hide a broken install
  behind ``.none()`` for a *usable* principal.
"""

from django.core.exceptions import PermissionDenied

from trusts.context import Context, ContextRegistry
from trusts.path import (
    AuthorizationPathError,
    compose,
    compose_scope,
    empty_grant_q,
)
from trusts.trustee import (
    Trustee,
    TrusteeRegistrationError,
    TrusteeRegistry,
)


class AuthorizationDenied(PermissionDenied):
    """Ordinary authorization denial. Not a configuration error."""


class AuthorizationConfigError(ValueError):
    """Missing, malformed, or incomplete authorization configuration.

    Security boundaries (backend / decorator / admin; S2+) may catch this
    and deny. Direct runtime APIs raise so a broken install cannot look
    like an empty result set.
    """


def _as_context_registry(value):
    if value is None or value is Context:
        return Context.registry
    if isinstance(value, ContextRegistry):
        return value
    raise AuthorizationConfigError(
        'context must be a ContextRegistry, not %r.' % (value,)
    )


def _as_trustee_registry(value):
    if value is None or value is Trustee:
        return Trustee.registry
    if isinstance(value, TrusteeRegistry):
        return value
    raise AuthorizationConfigError(
        'trustee must be a TrusteeRegistry, not %r.' % (value,)
    )


def _model_label(model):
    meta = getattr(model, '_meta', None)
    if meta is not None:
        return meta.label
    return repr(model)


def _same_model(left, right):
    if not isinstance(left, type):
        left = left.__class__
    if not isinstance(right, type):
        right = right.__class__
    return left._meta.concrete_model is right._meta.concrete_model


def _require_instance(value, expected_model, what):
    if isinstance(value, type):
        raise AuthorizationConfigError(
            '%s must be a %s instance, not a model class.' % (
                what, _model_label(expected_model),
            )
        )
    meta = getattr(value, '_meta', None)
    if meta is None:
        raise AuthorizationConfigError(
            '%s must be a %s instance, not %r. Raw primary keys are '
            'not accepted.' % (what, _model_label(expected_model), value)
        )
    if not _same_model(value, expected_model):
        raise AuthorizationConfigError(
            '%s is %s, which is not the configured %s %s.' % (
                what, _model_label(value.__class__),
                what, _model_label(expected_model),
            )
        )
    return value


def principal_is_usable(principal):
    """Attribute protocol. Missing attributes are ignored.

    ``is_anonymous is True``, ``is_authenticated is False``, or
    ``is_active is False`` makes the principal unusable. Runtime entry
    points check this **before** requester-model identity so Django's
    ``AnonymousUser`` (and any other explicitly unusable object) takes
    the ordinary denial path. A model with none of those attributes
    (for example a custom account) is usable. ``None`` and raw PKs have
    no flags and are still configuration errors via
    :func:`_require_instance`.
    """
    if getattr(principal, 'is_anonymous', None) is True:
        return False
    if getattr(principal, 'is_authenticated', None) is False:
        return False
    if getattr(principal, 'is_active', None) is False:
        return False
    return True


def _wrap_path_error(exc):
    if isinstance(exc, AuthorizationConfigError):
        raise exc
    raise AuthorizationConfigError(str(exc)) from exc


def _prepare_resource(resource, context, trustee, names):
    context_registry = _as_context_registry(context)
    trustee_registry = _as_trustee_registry(trustee)
    try:
        requester_model = trustee_registry.requester_model()
    except TrusteeRegistrationError as exc:
        _wrap_path_error(exc)
    _require_instance(resource, resource.__class__, 'resource')
    try:
        path = compose(
            resource.__class__, None, context=context_registry,
            trustee=trustee_registry, names=names,
        )
    except AuthorizationPathError as exc:
        _wrap_path_error(exc)
    return path, trustee_registry, requester_model


def _prepare_scope(scope_obj, trustee, names):
    trustee_registry = _as_trustee_registry(trustee)
    try:
        requester_model = trustee_registry.requester_model()
        scope_model = trustee_registry.scope_model()
    except TrusteeRegistrationError as exc:
        _wrap_path_error(exc)
    _require_instance(scope_obj, scope_model, 'scope')
    try:
        path = compose_scope(
            scope_obj.__class__, None, trustee=trustee_registry, names=names,
        )
    except AuthorizationPathError as exc:
        _wrap_path_error(exc)
    return path, trustee_registry, requester_model


def _prepare_operation(operation, trustee_registry):
    if isinstance(operation, str):
        if not trustee_registry.operation_lookup():
            raise AuthorizationConfigError(
                'String operations require operation_lookup on the '
                'Trustee registry.'
            )
        return operation
    try:
        operation_model = trustee_registry.operation_model()
    except TrusteeRegistrationError as exc:
        _wrap_path_error(exc)
    return _require_instance(operation, operation_model, 'operation')


def _deny_empty(queryset):
    return queryset.none()


def is_authorized(principal, operation, resource, context=None, trustee=None, names=None):
    """True when ``principal`` may perform ``operation`` on ``resource``."""
    if not principal_is_usable(principal):
        return False
    path, trustee_registry, requester_model = _prepare_resource(
        resource, context, trustee, names,
    )
    _require_instance(principal, requester_model, 'requester')
    operation = _prepare_operation(operation, trustee_registry)
    try:
        return path.row_is_granted(resource, principal, operation)
    except (AuthorizationPathError, TrusteeRegistrationError) as exc:
        _wrap_path_error(exc)


def require_authorized(principal, operation, resource, context=None, trustee=None, names=None):
    """Return ``resource`` or raise ``AuthorizationDenied``."""
    if not is_authorized(
        principal, operation, resource,
        context=context, trustee=trustee, names=names,
    ):
        raise AuthorizationDenied(
            'Not authorized to perform this operation on %s.' % (
                _model_label(resource.__class__),
            )
        )
    return resource


def filter_authorized(queryset, principal, operation, context=None, trustee=None, names=None):
    """SQL-filter ``queryset`` with the composed resource-origin predicate."""
    if not principal_is_usable(principal):
        return _deny_empty(queryset)
    context_registry = _as_context_registry(context)
    trustee_registry = _as_trustee_registry(trustee)
    try:
        requester_model = trustee_registry.requester_model()
    except TrusteeRegistrationError as exc:
        _wrap_path_error(exc)
    _require_instance(principal, requester_model, 'requester')
    try:
        path = compose(
            queryset.model, None, context=context_registry,
            trustee=trustee_registry, names=names,
        )
    except AuthorizationPathError as exc:
        _wrap_path_error(exc)
    operation = _prepare_operation(operation, trustee_registry)
    try:
        return path.filter_granted(queryset, principal, operation)
    except (AuthorizationPathError, TrusteeRegistrationError) as exc:
        _wrap_path_error(exc)


def authorized_q(resource_model, principal, operation, context=None, trustee=None, names=None):
    """Shared ``Q`` for resource-origin exists and list filters."""
    if not principal_is_usable(principal):
        return empty_grant_q()
    context_registry = _as_context_registry(context)
    trustee_registry = _as_trustee_registry(trustee)
    try:
        requester_model = trustee_registry.requester_model()
    except TrusteeRegistrationError as exc:
        _wrap_path_error(exc)
    _require_instance(principal, requester_model, 'requester')
    try:
        path = compose(
            resource_model, None, context=context_registry,
            trustee=trustee_registry, names=names,
        )
    except AuthorizationPathError as exc:
        _wrap_path_error(exc)
    operation = _prepare_operation(operation, trustee_registry)
    try:
        return path.grant_q(principal, operation)
    except (AuthorizationPathError, TrusteeRegistrationError) as exc:
        _wrap_path_error(exc)


def is_scope_authorized(principal, operation, scope_obj, trustee=None, names=None):
    """True when ``principal`` may perform ``operation`` on the scope row."""
    if not principal_is_usable(principal):
        return False
    path, trustee_registry, requester_model = _prepare_scope(
        scope_obj, trustee, names,
    )
    _require_instance(principal, requester_model, 'requester')
    operation = _prepare_operation(operation, trustee_registry)
    try:
        return path.row_is_granted(scope_obj, principal, operation)
    except (AuthorizationPathError, TrusteeRegistrationError) as exc:
        _wrap_path_error(exc)


def require_scope_authorized(principal, operation, scope_obj, trustee=None, names=None):
    """Return ``scope_obj`` or raise ``AuthorizationDenied``."""
    if not is_scope_authorized(
        principal, operation, scope_obj, trustee=trustee, names=names,
    ):
        raise AuthorizationDenied(
            'Not authorized to perform this operation on %s.' % (
                _model_label(scope_obj.__class__),
            )
        )
    return scope_obj


def filter_authorized_scope(queryset, principal, operation, trustee=None, names=None):
    """SQL-filter a queryset whose model *is* the frozen Trustee scope."""
    if not principal_is_usable(principal):
        return _deny_empty(queryset)
    trustee_registry = _as_trustee_registry(trustee)
    try:
        requester_model = trustee_registry.requester_model()
    except TrusteeRegistrationError as exc:
        _wrap_path_error(exc)
    _require_instance(principal, requester_model, 'requester')
    try:
        path = compose_scope(
            queryset.model, None, trustee=trustee_registry, names=names,
        )
    except AuthorizationPathError as exc:
        _wrap_path_error(exc)
    operation = _prepare_operation(operation, trustee_registry)
    try:
        return path.filter_granted(queryset, principal, operation)
    except (AuthorizationPathError, TrusteeRegistrationError) as exc:
        _wrap_path_error(exc)


def authorized_scope_q(scope_model, principal, operation, trustee=None, names=None):
    """Shared ``Q`` for scope-origin exists and list filters."""
    if not principal_is_usable(principal):
        return empty_grant_q()
    trustee_registry = _as_trustee_registry(trustee)
    try:
        requester_model = trustee_registry.requester_model()
    except TrusteeRegistrationError as exc:
        _wrap_path_error(exc)
    _require_instance(principal, requester_model, 'requester')
    try:
        path = compose_scope(
            scope_model, None, trustee=trustee_registry, names=names,
        )
    except AuthorizationPathError as exc:
        _wrap_path_error(exc)
    operation = _prepare_operation(operation, trustee_registry)
    try:
        return path.grant_q(principal, operation)
    except (AuthorizationPathError, TrusteeRegistrationError) as exc:
        _wrap_path_error(exc)


__all__ = [
    'AuthorizationConfigError',
    'AuthorizationDenied',
    'authorized_q',
    'authorized_scope_q',
    'filter_authorized',
    'filter_authorized_scope',
    'is_authorized',
    'is_scope_authorized',
    'principal_is_usable',
    'require_authorized',
    'require_scope_authorized',
]
