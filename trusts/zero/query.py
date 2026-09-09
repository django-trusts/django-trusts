"""Zero evaluation helpers on the composed AuthorizationPath seam.

``direct`` / ``group`` adapter gating, Django user flags, and
``auth.Permission`` resolution stay here as concrete-policy concerns.
Kernel ``compose`` does not know those nouns.

Resource-origin list and object checks (``ContentQuerySet.permitted``,
``TrustModelBackend`` object permissions) go through ``compose``.
Create-under-trust still uses ``Trustee.grant_q`` with an empty
``scope_from_row`` because ``Trust`` as Content is registered with the
parent hop (``resource_to_scope='trust'``), not identity.
"""

from django.db.models import Q, QuerySet

from trusts.path import AuthorizationPathError, compose


def is_active_principal(user):
    """Match ``User.has_perm``: anonymous and inactive principals are denied.

    Django ``PermissionsMixin.has_perm`` still short-circuits active
    superusers before backends run (including ``obj=None``). Object-level
    ``TrustModelBackend.has_perm`` and ``.permitted()`` evaluate the
    composed grant instead; they do not treat superuser as return-all.
    """
    if user is None:
        return False
    if getattr(user, 'is_anonymous', False):
        return False
    if not getattr(user, 'is_authenticated', True):
        return False
    if not getattr(user, 'is_active', False):
        return False
    return True


def _group_permission_queries_allowed():
    from trusts.zero import (
        supported_entity_contract,
        supported_group_contract,
        supported_permission_contract,
    )

    return (
        supported_entity_contract()
        and supported_group_contract()
        and supported_permission_contract()
    )


def enabled_trustee_adapter_names():
    """Installed adapter names after settings-based gating of built-ins.

    The frozen registry is the complete query-building source. Built-in
    ``direct`` / ``group`` adapters are omitted when their auth-model
    contract fails. Additional installed adapters stay in the set.
    """
    from trusts.zero import supported_entity_contract, supported_permission_contract
    from trusts.zero.models import DIRECT_TRUSTEE, GROUP_TRUSTEE, prepare_trustee_registry
    from trusts.trustee import Trustee

    prepare_trustee_registry()
    skip = set()
    if not (supported_entity_contract() and supported_permission_contract()):
        skip.add(DIRECT_TRUSTEE)
    if not _group_permission_queries_allowed():
        skip.add(GROUP_TRUSTEE)
    return tuple(
        adapter.name for adapter in Trustee.adapters()
        if adapter.name not in skip
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


def _require_terminal_instance(value, expected_model, what):
    """Reject raw PKs and wrong models so Django cannot coerce a colliding PK."""
    if isinstance(value, type):
        raise AuthorizationPathError(
            '%s must be a %s instance, not a model class.' % (
                what, _model_label(expected_model),
            )
        )
    meta = getattr(value, '_meta', None)
    if meta is None:
        raise AuthorizationPathError(
            '%s must be a %s instance, not %r. Raw primary keys are '
            'not accepted.' % (what, _model_label(expected_model), value)
        )
    if not _same_model(value, expected_model):
        raise AuthorizationPathError(
            '%s is %s, which is not the configured %s %s.' % (
                what, _model_label(value.__class__),
                what, _model_label(expected_model),
            )
        )
    return value


def require_configured_requester(user):
    """Fail closed unless ``user`` is an instance of the configured requester."""
    from trusts.zero.models import prepare_trustee_registry
    from trusts.trustee import Trustee

    prepare_trustee_registry()
    return _require_terminal_instance(
        user, Trustee.registry.requester_model(), 'requester',
    )


def require_configured_operation(operation):
    """Fail closed unless ``operation`` is an instance of the configured operation."""
    from trusts.zero.models import prepare_trustee_registry
    from trusts.trustee import Trustee

    prepare_trustee_registry()
    return _require_terminal_instance(
        operation, Trustee.registry.operation_model(), 'operation',
    )


def compose_zero_path(resource_model, operation):
    """Compose process-wide maps with Zero-enabled adapter names.

    Returns ``None`` when no adapters remain after auth-model gating.
    Unregistered resources and mismatched terminals raise
    ``AuthorizationPathError``.
    """
    from trusts.zero.models import prepare_context_registry, prepare_trustee_registry

    prepare_context_registry()
    prepare_trustee_registry()
    names = enabled_trustee_adapter_names()
    if not names:
        return None
    return compose(resource_model, operation, names=names)


def filter_zero_granted(queryset, requester, operation):
    """SQL-filter ``queryset`` through the composed Zero path (one query)."""
    path = compose_zero_path(queryset.model, operation)
    if path is None:
        return queryset.none()
    return path.filter_granted(queryset, requester, operation)


def row_is_zero_granted(obj, requester, operation):
    """One-query exists check through the composed Zero path."""
    path = compose_zero_path(obj.__class__, operation)
    if path is None:
        return False
    return path.row_is_granted(obj, requester, operation)


def queryset_is_zero_granted(queryset, requester, operation):
    """True when ``queryset`` is non-empty and every row is granted.

    Empty querysets deny (same as ``get_all_permissions`` on an empty
    content queryset). The ungranted remainder uses the same ``grant_q``
    as ``filter_zero_granted``.
    """
    if not isinstance(queryset, QuerySet):
        raise AuthorizationPathError(
            'queryset must be a QuerySet, not %r.' % (queryset,)
        )
    if not queryset.exists():
        return False
    path = compose_zero_path(queryset.model, operation)
    if path is None:
        return False
    granted = path.grant_q(requester, operation)
    return not queryset.exclude(granted).exists()


def scope_pks_from_resource(obj, path):
    """Primary keys of scopes reached by ``path.resource_to_scope``.

    Resource-origin lookup (the composed Context hop), not a Trust-origin
    reverse. Used by ``get_all_permissions`` enumeration only.
    """
    lookup = path.resource_to_scope
    if isinstance(obj, QuerySet):
        return tuple(
            pk for pk in obj.values_list(lookup, flat=True).distinct()
            if pk is not None
        )
    model = obj.__class__
    pk = model._default_manager.filter(pk=obj.pk).values_list(
        lookup, flat=True,
    ).first()
    if pk is None:
        return ()
    return (pk,)


def trust_grant_q(user, permission, trust_fk=''):
    """Q matching grants when the filtered row *is* the scope.

    ``trust_fk`` is the lookup prefix to the scope row: ``''`` filters
    ``Trust`` rows themselves (create-under-trust / ``has_trust_row_perm``).
    Resource-origin Content filters must use ``compose_zero_path`` /
    ``filter_zero_granted`` instead of passing ``Context.scope_path``.

    Requester and operation must be instances of the configured
    terminals; raw PKs and same-PK collisions of the wrong model fail
    closed.
    """
    from trusts.zero.models import prepare_trustee_registry
    from trusts.trustee import Trustee

    require_configured_requester(user)
    require_configured_operation(permission)
    prepare_trustee_registry()
    names = enabled_trustee_adapter_names()
    if not names:
        return Q(pk__in=[])
    return Trustee.grant_q(
        user, permission, scope_from_row=trust_fk, names=names,
    )
