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

Public construction is ``compose`` (resource-origin, Context hop) or
``compose_scope`` (the filtered row *is* the frozen Trustee scope).
Direct ``AuthorizationPath(...)`` is rejected. Adapter-specific data is
always a tuple of immutable ``AuthorizationBranch`` records. Evaluation
requires a requester instance of the composed terminal. Operation may be
an operation-model instance or, when ``Trustee.operation_lookup`` is
set, a string compiled into the grant predicate. Raw primary keys are
not accepted.

Recursive and ordered remaining-bits helpers are reserved slots only.
They are not compiled in this slice. An instance that carries a
non-empty reserved slot cannot evaluate.
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


def _reject_reserved(condition, recursive_edge, ordered_contribution):
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


def _require_instance(value, expected_model, what):
    """Require a model *instance* of ``expected_model``. Raw PKs are rejected."""
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


def _branch_from_adapter(adapter):
    return AuthorizationBranch(
        name=adapter.name,
        subject_model=adapter.trustee_model,
        subject_from_grant=adapter.trustee_path,
        membership_path=adapter.membership_path,
        requester_from_grant=adapter.requester_from_grant_path(),
        grant_model=adapter.grant_model,
        grant_to_scope=adapter.scope_path,
        grant_to_operation=adapter.operation_path,
        constraint_paths=adapter.constraint_paths,
        alignment_paths=adapter.alignment_paths,
    )


def _assert_adapter_terminals(context_adapter, adapters, operation_cls):
    resource_model = context_adapter.model
    resource_scope = context_adapter.scope_model()
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


class AuthorizationBranch(object):
    """Immutable per-adapter grant record on a composed path.

    ``constraint_paths`` is always a tuple of strings. One composed path
    always exposes a tuple of these records, including when there is
    only one grant adapter.
    """

    __slots__ = (
        'name',
        'subject_model',
        'subject_from_grant',
        'membership_path',
        'requester_from_grant',
        'grant_model',
        'grant_to_scope',
        'grant_to_operation',
        'constraint_paths',
        'alignment_paths',
    )

    def __init__(
        self, name, subject_model, subject_from_grant, membership_path,
        requester_from_grant, grant_model, grant_to_scope,
        grant_to_operation, constraint_paths, alignment_paths=(),
    ):
        object.__setattr__(self, 'name', name)
        object.__setattr__(self, 'subject_model', subject_model)
        object.__setattr__(self, 'subject_from_grant', subject_from_grant)
        object.__setattr__(self, 'membership_path', membership_path)
        object.__setattr__(self, 'requester_from_grant', requester_from_grant)
        object.__setattr__(self, 'grant_model', grant_model)
        object.__setattr__(self, 'grant_to_scope', grant_to_scope)
        object.__setattr__(self, 'grant_to_operation', grant_to_operation)
        object.__setattr__(self, 'constraint_paths', tuple(constraint_paths))
        object.__setattr__(self, 'alignment_paths', tuple(
            tuple(pair) for pair in alignment_paths
        ))

    def __setattr__(self, name, value):
        raise AttributeError('AuthorizationBranch is immutable.')

    def __repr__(self):
        return 'AuthorizationBranch(%r, %s)' % (
            self.name, _model_label(self.grant_model),
        )


class AuthorizationPath(object):
    """Frozen join of one Context resource adapter and enabled grant adapters.

    Shared terminals (requester, resource, scope, operation) are scalars.
    Adapter-specific data is ``branches``: a non-empty tuple of immutable
    ``AuthorizationBranch`` records, the same shape for one adapter or many.

    Construct only with ``compose``. Evaluation refuses reserved slots,
    raw primary keys, and requester/operation instances whose concrete
    model is not the composed terminal.
    """

    __slots__ = (
        'requester_model',
        'resource_model',
        'resource_to_scope',
        'scope_model',
        'operation_model',
        '_branches',
        '_condition',
        '_recursive_edge',
        '_ordered_contribution',
        '_context_adapter',
        '_trustee_adapters',
        '_context_registry',
        '_trustee_registry',
        '_scope_origin',
    )

    def __init__(self, *args, **kwargs):
        raise AuthorizationPathError(
            'AuthorizationPath must be constructed with compose(); '
            'direct construction is not part of the public contract.'
        )

    def __setattr__(self, name, value):
        raise AttributeError('AuthorizationPath is immutable.')

    def __repr__(self):
        names = ', '.join(branch.name for branch in self._branches)
        return 'AuthorizationPath(%s, [%s])' % (
            _model_label(self.resource_model), names,
        )

    @property
    def branches(self):
        return self._branches

    @property
    def adapter_names(self):
        return tuple(branch.name for branch in self._branches)

    @property
    def scope_origin(self):
        return self._scope_origin

    @property
    def condition(self):
        return self._condition

    @property
    def recursive_edge(self):
        return self._recursive_edge

    @property
    def ordered_contribution(self):
        return self._ordered_contribution

    @classmethod
    def _from_validated(
        cls, context_adapter, trustee_adapters, context_registry,
        trustee_registry, scope_origin=False, scope_model=None,
    ):
        """Install a validated, frozen join. Reserved slots are always None."""
        inst = object.__new__(cls)
        object.__setattr__(inst, '_context_adapter', context_adapter)
        object.__setattr__(inst, '_trustee_adapters', tuple(trustee_adapters))
        object.__setattr__(inst, '_context_registry', context_registry)
        object.__setattr__(inst, '_trustee_registry', trustee_registry)
        object.__setattr__(inst, '_scope_origin', bool(scope_origin))
        if scope_origin:
            object.__setattr__(inst, 'resource_model', scope_model)
            object.__setattr__(inst, 'resource_to_scope', '')
            object.__setattr__(inst, 'scope_model', scope_model)
        else:
            object.__setattr__(inst, 'resource_model', context_adapter.model)
            object.__setattr__(inst, 'resource_to_scope', context_adapter.scope_path())
            object.__setattr__(inst, 'scope_model', context_adapter.scope_model())
        object.__setattr__(inst, 'requester_model', trustee_registry.requester_model())
        object.__setattr__(
            inst, 'operation_model', trustee_adapters[0].operation_model(),
        )
        object.__setattr__(inst, '_branches', tuple(
            _branch_from_adapter(adapter) for adapter in trustee_adapters
        ))
        object.__setattr__(inst, '_condition', None)
        object.__setattr__(inst, '_recursive_edge', None)
        object.__setattr__(inst, '_ordered_contribution', None)
        return inst

    @classmethod
    def compose(
        cls, resource_model, operation, context=None, trustee=None,
        names=None, condition=None, recursive_edge=None,
        ordered_contribution=None,
    ):
        """Freeze both maps and return the composed path.

        Fail closed when the resource is unregistered, no grant adapters
        are enabled, terminals mismatch, or a reserved slot is used.
        Direct ``AuthorizationPath(...)`` construction is rejected.
        """
        _reject_reserved(condition, recursive_edge, ordered_contribution)

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

        operation_cls = None
        if isinstance(operation, str):
            if not trustee_registry.operation_lookup():
                raise AuthorizationPathError(
                    'String operations require operation_lookup on the '
                    'Trustee registry.'
                )
        elif operation is not None:
            operation_cls = _as_model(operation, 'operation')

        _assert_adapter_terminals(context_adapter, adapters, operation_cls)
        return cls._from_validated(
            context_adapter, adapters, context_registry, trustee_registry,
        )

    @classmethod
    def compose_scope(
        cls, scope_model, operation, trustee=None, names=None,
        condition=None, recursive_edge=None, ordered_contribution=None,
    ):
        """Compose a path whose filtered row *is* the frozen Trustee scope.

        No Context adapter is required. The compiled grant predicate uses
        identity scope (grant ``scope_path`` → row ``pk``). ``scope_from_row``
        is not a public argument.
        """
        _reject_reserved(condition, recursive_edge, ordered_contribution)

        scope_model = _as_model(scope_model, 'scope_model')
        trustee_registry = _as_trustee_registry(trustee)
        trustee_registry.ensure_frozen()

        try:
            configured_scope = trustee_registry.scope_model()
        except TrusteeRegistrationError as exc:
            raise AuthorizationPathError(str(exc))

        if not _same_model(scope_model, configured_scope):
            raise AuthorizationPathError(
                'Scope %s is not the configured Trustee scope %s.' % (
                    _model_label(scope_model),
                    _model_label(configured_scope),
                )
            )

        try:
            adapters = _enabled_adapters(trustee_registry, names)
        except TrusteeNotRegistered as exc:
            raise AuthorizationPathError(str(exc))

        if not adapters:
            raise AuthorizationPathError(
                'No grant adapters are enabled for scope %s.' % (
                    _model_label(scope_model),
                )
            )

        operation_cls = None
        if isinstance(operation, str):
            if not trustee_registry.operation_lookup():
                raise AuthorizationPathError(
                    'String operations require operation_lookup on the '
                    'Trustee registry.'
                )
        elif operation is not None:
            operation_cls = _as_model(operation, 'operation')

        for adapter in adapters:
            grant_scope = adapter.scope_model()
            if not _same_model(grant_scope, scope_model):
                raise AuthorizationPathError(
                    'Scope %s does not match grant adapter %r scope %s.' % (
                        _model_label(scope_model),
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

        return cls._from_validated(
            None, adapters, None, trustee_registry,
            scope_origin=True, scope_model=scope_model,
        )

    def _assert_evaluable(self, requester, operation):
        """Refuse reserved slots, raw PKs, and wrong concrete terminals."""
        if (
            self._condition is not None
            or self._recursive_edge is not None
            or self._ordered_contribution is not None
        ):
            raise AuthorizationPathError(
                'This authorization path carries an unimplemented reserved '
                'slot and cannot evaluate.'
            )
        _require_instance(requester, self.requester_model, 'requester')
        if isinstance(operation, str):
            if not self._trustee_registry.operation_lookup():
                raise AuthorizationPathError(
                    'String operations require operation_lookup on the '
                    'Trustee registry.'
                )
        else:
            _require_instance(operation, self.operation_model, 'operation')

    def grant_q(self, requester, operation):
        """Compiled grant predicate for this resource's scope path."""
        self._assert_evaluable(requester, operation)
        return self._trustee_registry.grant_q(
            requester,
            operation,
            scope_from_row=self.resource_to_scope,
            names=self.adapter_names,
        )

    def filter_granted(self, queryset, requester, operation):
        """SQL-filter ``queryset`` with the composed predicate (one query)."""
        self._assert_evaluable(requester, operation)
        expected = self.scope_model if self._scope_origin else self.resource_model
        what = 'scope' if self._scope_origin else 'path resource'
        if not _same_model(queryset.model, expected):
            raise AuthorizationPathError(
                'Queryset model %s is not this %s %s.' % (
                    _model_label(queryset.model),
                    what,
                    _model_label(expected),
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
        self._assert_evaluable(requester, operation)
        if self._scope_origin:
            _require_instance(obj, self.scope_model, 'scope')
        else:
            _require_instance(obj, self.resource_model, 'resource')
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


def compose_scope(
    scope_model, operation, trustee=None, names=None,
    condition=None, recursive_edge=None, ordered_contribution=None,
):
    """Freeze the Trustee map and return a scope-origin ``AuthorizationPath``."""
    return AuthorizationPath.compose_scope(
        scope_model,
        operation,
        trustee=trustee,
        names=names,
        condition=condition,
        recursive_edge=recursive_edge,
        ordered_contribution=ordered_contribution,
    )


def filter_granted(
    queryset, requester, operation, context=None, trustee=None, names=None,
    condition=None, recursive_edge=None, ordered_contribution=None,
):
    """SQL-filter ``queryset`` through a composed ``AuthorizationPath``."""
    path = compose(
        queryset.model,
        operation,
        context=context,
        trustee=trustee,
        names=names,
        condition=condition,
        recursive_edge=recursive_edge,
        ordered_contribution=ordered_contribution,
    )
    return path.filter_granted(queryset, requester, operation)


def row_is_granted(
    obj, requester, operation, context=None, trustee=None, names=None,
    condition=None, recursive_edge=None, ordered_contribution=None,
):
    """One-query exists check through a composed ``AuthorizationPath``."""
    path = compose(
        obj.__class__,
        operation,
        context=context,
        trustee=trustee,
        names=names,
        condition=condition,
        recursive_edge=recursive_edge,
        ordered_contribution=ordered_contribution,
    )
    return path.row_is_granted(obj, requester, operation)


def empty_grant_q():
    """Fail-closed predicate used when no composed path can authorize."""
    return Q(pk__in=[])


__all__ = [
    'AuthorizationBranch',
    'AuthorizationPath',
    'AuthorizationPathError',
    'OrderedContribution',
    'RecursiveEdge',
    'compose',
    'compose_scope',
    'empty_grant_q',
    'filter_granted',
    'row_is_granted',
]
