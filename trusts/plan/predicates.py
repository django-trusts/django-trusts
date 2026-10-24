"""One ``Q`` per record so a repeated many-to-many hop stays one join."""

from django.contrib.auth.models import Permission
from django.db.models import F, Model, Q

from trusts.errors import PermissionConditionError
from trusts.plan.grammar import Tree, inquiry_partner, unsupported
from trusts.plan.hops import lookup_text, require_instance
from trusts.plan.writers import (
    boolean_q,
    negate_q,
    column_q,
    columns_q,
    contains_q,
    member_pk,
)

__all__ = [
    'bind_terminal',
    'compile_predicate',
    'permission_terminal_is_auth_permission',
    'content_type_identity',
    'bind_record_qs',
]

_BINDING_FIELDS = {
    'user': 'user_field',
    'content': 'content_field',
    'permission': 'permission_field',
}


def bind_terminal(value, role):
    """Accept a model instance or an unevaluated lookup expression."""
    if _is_lookup_expression(value):
        return value
    return require_instance(value, role)


def compile_predicate(node, record, *, permission=None):
    return _PredicateCompiler(record, permission).compile(node)


def permission_terminal_is_auth_permission(permission_model):
    """True when the terminal's concrete model is ``auth.Permission``.

    Typed content identity applies only to that model, on a direct
    foreign key or a terminal many-to-many. Any other terminal,
    including one that happens to have a ``content_type`` foreign key,
    stays primary-key identity. Metadata only (zero SQL). This is an
    exact model-identity check, not a field-name scan and not a
    codename parse.
    """
    return (
        permission_model._meta.concrete_model
        is Permission._meta.concrete_model
    )


def content_type_identity(model):
    """``(app_label, model_name)`` for ``for_concrete_model=False``.

    ``ContentType.get_for_model(model, for_concrete_model=False)`` uses
    the model's own ``app_label`` and ``model_name``. A real proxy keeps
    its own pair. No content-type row is loaded.
    """
    return model._meta.app_label.lower(), model._meta.model_name


def bind_record_qs(record, correlation=None, *, content_identity=None, **bindings):
    """Root rows for one record. One ``filter()`` for every predicate."""
    return record.root._default_manager.filter(
        _record_predicate(
            record,
            correlation=correlation,
            content_identity=content_identity,
            **bindings,
        ),
    )


def _is_lookup_expression(value):
    """True for OuterRef / Subquery / other SQL expressions."""
    return hasattr(value, 'resolve_expression') and not isinstance(value, Model)


class _PredicateCompiler(object):
    """Compile one stored predicate node. The node dispatches; Q stays here."""

    def __init__(self, record, permission):
        self.record = record
        self.permission = permission

    def compile(self, node):
        if node is None:
            return None
        if not isinstance(node, Tree):
            raise unsupported('This condition', 'a relation condition')
        if node.kind == 'and':
            return self.compile(node.left) & self.compile(node.right)
        if node.kind == 'or':
            return self.compile(node.left) | self.compile(node.right)
        if node.kind == 'not':
            return negate_q(self.record.root, self.compile(node.item))
        if node.kind == 'eq':
            return self._eq(node)
        if node.kind == 'ne':
            return self._ne(node)
        if node.kind == 'contains':
            return self._contains(node)
        if node.kind == 'bare':
            return boolean_q(lookup_text(node.item.path))
        raise unsupported(node.kind, 'a relation condition')

    def _eq(self, node):
        partner = inquiry_partner(node)
        if partner is not None:
            return self._bind_inquiry(partner.path)
        if node.left.kind == 'const' or node.right.kind == 'const':
            return self._against_constant(node, True)
        return Q(**{
            lookup_text(node.left.path): F(lookup_text(node.right.path)),
        })

    def _ne(self, node):
        column = inquiry_partner(node)
        if (
            column is not None
            and column.kind == 'field'
            and column.path
        ):
            if self.permission is None:
                raise PermissionConditionError(
                    'Delegated inquiry-permission condition needs the requested '
                    'permission binding.'
                )
            return column_q(
                lookup_text(column.path),
                bind_terminal(self.permission, 'permission'),
                False,
                field=True,
            )
        if node.left.kind == 'const' or node.right.kind == 'const':
            return self._against_constant(node, False)
        return columns_q(
            lookup_text(node.left.path),
            lookup_text(node.right.path),
            False,
        )

    def _against_constant(self, node, equal):
        if node.left.kind == 'const':
            lookup = lookup_text(node.right.path)
            value = node.left.value
        else:
            lookup = lookup_text(node.left.path)
            value = node.right.value
        return column_q(lookup, value, equal, field=False)

    def _contains(self, node):
        if inquiry_partner(node) is not None:
            return self._bind_inquiry(node.left.path)
        if node.right.kind == 'const':
            value = member_pk(node.right.value)
            if value is None:
                return Q(pk__in=())
            return contains_q(lookup_text(node.left.path), value)
        return contains_q(
            lookup_text(node.left.path),
            F(self.record.permission_field),
        )

    def _bind_inquiry(self, path):
        if self.permission is None:
            raise PermissionConditionError(
                'Delegated inquiry-permission condition needs the requested '
                'permission binding.'
            )
        return Q(**{
            lookup_text(path): bind_terminal(self.permission, 'permission'),
        })


def _permission_content_type_filters(record, content_identity):
    """Lookup kwargs that pin the permission row to one content type.

    The lookups extend ``permission_field`` so they share that join.
    A second many-to-many alias would let one group row satisfy the
    permission id and a different row satisfy the content type.
    """
    if not permission_terminal_is_auth_permission(record.permission_model):
        return {}
    model = content_identity if content_identity is not None else record.content_model
    app_label, model_name = content_type_identity(model)
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
        filters[getattr(record, _BINDING_FIELDS[role])] = bind_terminal(
            value, role,
        )
    filters.update(_permission_content_type_filters(record, content_identity))
    combined = Q(**filters)
    compiled = compile_predicate(record.condition, record)
    if compiled is not None:
        combined &= compiled
    if correlation is not None:
        combined &= correlation
    return combined
