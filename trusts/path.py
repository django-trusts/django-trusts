"""Composed AuthorizationPath IR.

The reusable question:

    Given a resource model and an operation, what frozen Context plus
    Trustee records compile into one authorization decision?

A completed authorization path is data, then a fixed compiler. This
module names the join that Context and Trustee already compute:

    Trustee.grant_q(
        requester,
        operation,
        scope_from_row=Context.scope_path(resource_model),
    )

It does not invent a parallel walker. Evaluation reuses the frozen
adapter maps. Isolated tests construct ``ContextRegistry()`` /
``TrusteeRegistry()`` and pass them in. Process-wide ``Context`` /
``Trustee`` remain the default instances.

Kernel positions are requester / subject / resource / scope / grant /
operation. This module must not name a concrete authorization product's
resource, scope, principal, collective, bundle, or grant tables.

Recursive and ordered remaining-bits helpers are reserved slots only.
They are not compiled in this slice.
"""

from django.db.models import Q

from trusts.context import Context, ContextNotRegistered, ContextRegistry
from trusts.trustee import Trustee, TrusteeNotRegistered, TrusteeRegistry


class AuthorizationPathError(ValueError):
    """A composed authorization path is missing, mismatched, incomplete,
    or uses a reserved slot that is not implemented.
    """


class RecursiveEdge(object):
    """Reserved bounded recursive-edge declaration.

    Later work may attach a declared relation, finite ``max_depth``, and
    fail-closed cycle / dangling / overflow policy. This slice rejects
    construction so callers cannot pretend traversal is implemented.
    """

    __slots__ = (
        'from_model', 'edge_path', 'max_depth', 'on_cycle',
        'on_dangling', 'on_overflow',
    )

    def __init__(self, *args, **kwargs):
        raise AuthorizationPathError(
            'RecursiveEdge is reserved; bounded recursive traversal '
            'is not implemented.'
        )


class OrderedContribution(object):
    """Reserved ordered remaining-bits helper.

    Later work may declare a sequence of path/grant contributions and a
    remaining-bits / first-match combine. This slice rejects construction
    so callers cannot encode ordered-deny semantics here.
    """

    __slots__ = ('sequence', 'combine')

    def __init__(self, *args, **kwargs):
        raise AuthorizationPathError(
            'OrderedContribution is reserved; ordered remaining-bits '
            'combination is not implemented.'
        )


def _model_label(model):
    meta = getattr(model, '_meta', None)
    if meta is not None:
        return meta.label
    return repr(model)


def _model_key(model):
    if not isinstance(model, type):
        model = model.__class__
    return model._meta.concrete_model


def _as_model(value, what):
    if isinstance(value, type) and hasattr(value, '_meta'):
        return value
    cls = getattr(value, '__class__', None)
    if cls is not None and hasattr(cls, '_meta'):
        return cls
    raise AuthorizationPathError(
        '%s must be a model class or instance, not %r.' % (what, value)
    )


def _as_context_registry(value):
    if value is None or value is Context:
        return Context.registry
    if isinstance(value, ContextRegistry):
        return value
    raise AuthorizationPathError(
        'context must be a ContextRegistry, not %r.' % (value,)
    )


def _as_trustee_registry(value):
    if value is None or value is Trustee:
        return Trustee.registry
    if isinstance(value, TrusteeRegistry):
        return value
    raise AuthorizationPathError(
        'trustee must be a TrusteeRegistry, not %r.' % (value,)
    )


def _enabled_adapters(registry, names):
    if names is None:
        return registry.adapters()
    return tuple(registry.get(name) for name in names)


def _same_model(left, right):
    return _model_key(left) is _model_key(right)


def _scalar_or_tuple(values):
    if len(values) == 1:
        return values[0]
    return values


class AuthorizationPath(object):
    """Frozen join of one Context resource adapter and enabled grant adapters.

    Shared terminals (requester, resource, scope, operation) are always
    scalars. Adapter-specific fields (subject, grant, membership,
    constraint paths) are a scalar when exactly one grant adapter is
    enabled and a tuple when several adapters OR-compose.
    """

    __slots__ = (
        'requester_model',
        'requester_from_grant',
        'subject_model',
        'subject_from_grant',
        'membership_path',
        'resource_model',
        'resource_to_scope',
        'scope_model',
        'grant_model',
        'grant_to_scope',
        'grant_to_operation',
        'operation_model',
        'constraint_paths',
        'condition',
        'recursive_edge',
        'ordered_contribution',
        '_context_adapter',
        '_trustee_adapters',
        '_context_registry',
        '_trustee_registry',
    )

    def __init__(
        self,
        context_adapter,
        trustee_adapters,
        context_registry,
        trustee_registry,
        condition=None,
        recursive_edge=None,
        ordered_contribution=None,
    ):
        trustee_adapters = tuple(trustee_adapters)
        if not trustee_adapters:
            raise AuthorizationPathError(
                'No grant adapters are enabled for this authorization path.'
            )
        self._context_adapter = context_adapter
        self._trustee_adapters = trustee_adapters
        self._context_registry = context_registry
        self._trustee_registry = trustee_registry
        self.condition = condition
        self.recursive_edge = recursive_edge
        self.ordered_contribution = ordered_contribution

        self.resource_model = context_adapter.model
        self.resource_to_scope = context_adapter.scope_path()
        self.scope_model = context_adapter.scope_model()
        self.requester_model = trustee_registry.requester_model()
        self.operation_model = trustee_adapters[0].operation_model()

        self.requester_from_grant = _scalar_or_tuple(tuple(
            adapter.requester_from_grant_path() for adapter in trustee_adapters
        ))
        self.subject_model = _scalar_or_tuple(tuple(
            adapter.trustee_model for adapter in trustee_adapters
        ))
        self.subject_from_grant = _scalar_or_tuple(tuple(
            adapter.trustee_path for adapter in trustee_adapters
        ))
        self.membership_path = _scalar_or_tuple(tuple(
            adapter.membership_path for adapter in trustee_adapters
        ))
        self.grant_model = _scalar_or_tuple(tuple(
            adapter.grant_model for adapter in trustee_adapters
        ))
        self.grant_to_scope = _scalar_or_tuple(tuple(
            adapter.scope_path for adapter in trustee_adapters
        ))
        self.grant_to_operation = _scalar_or_tuple(tuple(
            adapter.operation_path for adapter in trustee_adapters
        ))
        self.constraint_paths = _scalar_or_tuple(tuple(
            adapter.constraint_paths for adapter in trustee_adapters
        ))

    def __repr__(self):
        names = ', '.join(adapter.name for adapter in self._trustee_adapters)
        return 'AuthorizationPath(%s, [%s])' % (
            _model_label(self.resource_model), names,
        )

    @property
    def adapter_names(self):
        return tuple(adapter.name for adapter in self._trustee_adapters)

    @classmethod
    def compose(
        cls, resource_model, operation, context=None, trustee=None,
        names=None, condition=None, recursive_edge=None,
        ordered_contribution=None,
    ):
        """Freeze both maps and return the composed path.

        Fail closed when the resource is unregistered, no grant adapters
        are enabled, terminals mismatch, or a reserved slot is used.
        """
        if condition is not None:
            raise AuthorizationPathError(
                'Resource-row conditions are reserved; this slice compiles '
                'the grant join only.'
            )
        if recursive_edge is not None:
            raise AuthorizationPathError(
                'RecursiveEdge is reserved; bounded recursive traversal '
                'is not implemented.'
            )
        if ordered_contribution is not None:
            raise AuthorizationPathError(
                'OrderedContribution is reserved; ordered remaining-bits '
                'combination is not implemented.'
            )

        resource_model = _as_model(resource_model, 'resource_model')
        context_registry = _as_context_registry(context)
        trustee_registry = _as_trustee_registry(trustee)
        context_registry.ensure_frozen()
        trustee_registry.ensure_frozen()

        try:
            context_adapter = context_registry.get(resource_model)
        except ContextNotRegistered as exc:
            raise AuthorizationPathError(str(exc))

        try:
            adapters = _enabled_adapters(trustee_registry, names)
        except TrusteeNotRegistered as exc:
            raise AuthorizationPathError(str(exc))

        if not adapters:
            raise AuthorizationPathError(
                'No grant adapters are enabled for %s.' % (
                    _model_label(resource_model),
                )
            )

        resource_scope = context_adapter.scope_model()
        operation_cls = None
        if operation is not None:
            operation_cls = _as_model(operation, 'operation')

        for adapter in adapters:
            grant_scope = adapter.scope_model()
            if not _same_model(grant_scope, resource_scope):
                raise AuthorizationPathError(
                    'Resource %s resolves to scope %s, which does not match '
                    'grant adapter %r scope %s.' % (
                        _model_label(resource_model),
                        _model_label(resource_scope),
                        adapter.name,
                        _model_label(grant_scope),
                    )
                )
            grant_operation = adapter.operation_model()
            if operation_cls is not None and not _same_model(
                operation_cls, grant_operation,
            ):
                raise AuthorizationPathError(
                    'Operation %s does not match grant adapter %r '
                    'operation %s.' % (
                        _model_label(operation_cls),
                        adapter.name,
                        _model_label(grant_operation),
                    )
                )
            if not _same_model(adapter.scope_model(), adapters[0].scope_model()):
                raise AuthorizationPathError(
                    'Grant adapters mix scope terminals; refusing to compose.'
                )
            if not _same_model(
                adapter.operation_model(), adapters[0].operation_model(),
            ):
                raise AuthorizationPathError(
                    'Grant adapters mix operation terminals; refusing to compose.'
                )

        return cls(
            context_adapter, adapters, context_registry, trustee_registry,
        )

    def grant_q(self, requester, operation):
        """Compiled grant predicate for this resource's scope path."""
        return self._trustee_registry.grant_q(
            requester,
            operation,
            scope_from_row=self.resource_to_scope,
            names=self.adapter_names,
        )

    def filter_granted(self, queryset, requester, operation):
        """SQL-filter ``queryset`` with the composed predicate (one query)."""
        if not _same_model(queryset.model, self.resource_model):
            raise AuthorizationPathError(
                'Queryset model %s is not this path resource %s.' % (
                    _model_label(queryset.model),
                    _model_label(self.resource_model),
                )
            )
        return self._trustee_registry.filter_granted(
            queryset,
            requester,
            operation,
            scope_from_row=self.resource_to_scope,
            names=self.adapter_names,
        )

    def row_is_granted(self, obj, requester, operation):
        """One-query exists check using the same predicate as ``filter_granted``."""
        if not _same_model(obj, self.resource_model):
            raise AuthorizationPathError(
                'Object %s is not this path resource %s.' % (
                    _model_label(obj.__class__),
                    _model_label(self.resource_model),
                )
            )
        return self._trustee_registry.row_is_granted(
            obj,
            requester,
            operation,
            scope_from_row=self.resource_to_scope,
            names=self.adapter_names,
        )


def compose(
    resource_model, operation, context=None, trustee=None, names=None,
    condition=None, recursive_edge=None, ordered_contribution=None,
):
    """Freeze both maps and return an ``AuthorizationPath``.

    Fail closed if the resource is unregistered or terminals mismatch.
    """
    return AuthorizationPath.compose(
        resource_model,
        operation,
        context=context,
        trustee=trustee,
        names=names,
        condition=condition,
        recursive_edge=recursive_edge,
        ordered_contribution=ordered_contribution,
    )


def filter_granted(
    queryset, requester, operation, context=None, trustee=None, names=None,
    condition=None,
):
    """SQL-filter ``queryset`` through a composed ``AuthorizationPath``."""
    path = compose(
        queryset.model,
        operation,
        context=context,
        trustee=trustee,
        names=names,
        condition=condition,
    )
    return path.filter_granted(queryset, requester, operation)


def row_is_granted(
    obj, requester, operation, context=None, trustee=None, names=None,
    condition=None,
):
    """One-query exists check through a composed ``AuthorizationPath``."""
    path = compose(
        obj.__class__,
        operation,
        context=context,
        trustee=trustee,
        names=names,
        condition=condition,
    )
    return path.row_is_granted(obj, requester, operation)


def empty_grant_q():
    """Fail-closed predicate used when no composed path can authorize."""
    return Q(pk__in=[])


__all__ = [
    'AuthorizationPath',
    'AuthorizationPathError',
    'OrderedContribution',
    'RecursiveEdge',
    'compose',
    'empty_grant_q',
    'filter_granted',
    'row_is_granted',
]
