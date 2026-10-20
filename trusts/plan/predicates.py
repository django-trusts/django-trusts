"""One ``Q`` per record so a repeated many-to-many hop stays one join."""

__all__ = []

from django.db.models import F, Model, Q

from trusts.errors import TrustsConfigurationError
from trusts.plan.hops import (
    _auth_group_and_permission,
    _lookup_text,
    _require_instance,
)

_BINDING_FIELDS = {
    'user': 'user_field',
    'content': 'content_field',
    'permission': 'permission_field',
}


def _is_lookup_expression(value):
    """True for OuterRef / Subquery / other SQL expressions."""
    return hasattr(value, 'resolve_expression') and not isinstance(value, Model)


def _bind_terminal(value, role):
    """Accept a model instance or an unevaluated lookup expression."""
    if _is_lookup_expression(value):
        return value
    return _require_instance(value, role)


class _PredicateCompiler(object):
    """Compile one stored predicate node. The node dispatches; Q stays here."""

    def __init__(self, record, permission):
        self.record = record
        self.permission = permission

    def compile(self, node):
        if node is None:
            return None
        accept = getattr(type(node), 'accept', None)
        if accept is None:
            raise TrustsConfigurationError(
                'condition is not supported; omit it or pass None.'
            )
        return accept(node, self)

    def visit_all(self, node):
        parts = [
            self.compile(predicate) for predicate in node.predicates
        ]
        parts = [part for part in parts if part is not None]
        if not parts:
            return None
        compiled = parts[0]
        for part in parts[1:]:
            compiled &= part
        return compiled

    def visit_equal(self, node):
        return Q(**{
            _lookup_text(node.left._path): F(_lookup_text(node.right._path)),
        })

    def visit_permission_in(self, node):
        compiled = Q()
        for ref in node.refs:
            compiled &= Q(**{
                _lookup_text(ref._path): F(self.record.permission_field),
            })
        return compiled

    def visit_inquiry_permission_match(self, node):
        if self.permission is None:
            raise TrustsConfigurationError(
                'Delegated inquiry-permission condition needs the requested '
                'permission binding.'
            )
        require = getattr(type(node.ref), 'require_same_root', None)
        if require is None:
            raise TrustsConfigurationError(
                '%s must be a root-relative Ref, not %r.'
                % ('delegated inquiry permission', node.ref)
            )
        ref = require(
            node.ref, self.record.root, 'delegated inquiry permission',
        )
        return Q(**{
            _lookup_text(ref._path): _bind_terminal(
                self.permission, 'permission',
            ),
        })


def _compile_predicate(node, record, *, permission=None):
    return _PredicateCompiler(record, permission).compile(node)


def _permission_terminal_is_auth_permission(permission_model):
    """True when the terminal's concrete model is ``auth.Permission``.

    Typed content identity applies only to that model, on a direct
    foreign key or a terminal many-to-many. Any other terminal,
    including one that happens to have a ``content_type`` foreign key,
    stays primary-key identity. Metadata only (zero SQL). This is an
    exact model-identity check, not a field-name scan and not a
    codename parse.
    """
    _group, permission = _auth_group_and_permission()
    return (
        permission_model._meta.concrete_model
        is permission._meta.concrete_model
    )


def _content_type_identity(model):
    """``(app_label, model_name)`` for ``for_concrete_model=False``.

    ``ContentType.get_for_model(model, for_concrete_model=False)`` uses
    the model's own ``app_label`` and ``model_name``. A real proxy keeps
    its own pair. No content-type row is loaded.
    """
    return model._meta.app_label.lower(), model._meta.model_name


def _permission_content_type_filters(record, content_identity):
    """Lookup kwargs that pin the permission row to one content type.

    The lookups extend ``permission_field`` so they share that join.
    A second many-to-many alias would let one group row satisfy the
    permission id and a different row satisfy the content type.
    """
    if not _permission_terminal_is_auth_permission(record.permission_model):
        return {}
    model = content_identity if content_identity is not None else record.content_model
    app_label, model_name = _content_type_identity(model)
    field = record.permission_field
    return {
        '%s__content_type__app_label' % field: app_label,
        '%s__content_type__model' % field: model_name,
    }


def _record_predicate(record, correlation=None, *, content_identity=None,
                      **bindings):
    """Bindings, condition, and correlation as one ``Q``.

    Separate ``filter()`` calls give a repeated many-to-many hop its own
    alias. ``Group.permissions`` has to stay one join so the local
    ceiling and the requested permission are the same row. Content-type
    identity is part of that same ``Q`` for the same reason.
    """
    filters = {}
    for role, value in bindings.items():
        filters[getattr(record, _BINDING_FIELDS[role])] = _bind_terminal(
            value, role,
        )
    filters.update(_permission_content_type_filters(record, content_identity))
    combined = Q(**filters)
    compiled = _compile_predicate(record.condition, record)
    if compiled is not None:
        combined &= compiled
    if correlation is not None:
        combined &= correlation
    return combined


def _bind_record_qs(record, correlation=None, *, content_identity=None, **bindings):
    """Root rows for one record. One ``filter()`` for every predicate."""
    return record.root._default_manager.filter(
        _record_predicate(
            record,
            correlation=correlation,
            content_identity=content_identity,
            **bindings,
        ),
    )
