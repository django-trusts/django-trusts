"""Named user conditions compiled once into each check.

The shared grammar builds the expression. ``Tree`` is the stored node.

Each condition is ``(skip_<name> OR condition)``. The override is
``(NOT skip_<override> AND override)``, ORed with ordinary grants and
delegation. The skip flag is a bound parameter, so one statement serves
every skip state. The lockfile records that statement.
"""

__all__ = []

import copy
from collections import namedtuple

from django.core.exceptions import FieldDoesNotExist
from django.db.models import BooleanField, F, Model, Q
from django.db.models.expressions import RawSQL

from trusts.plan.conditions import (
    ModelIdentity,
    _terminal_field,
    normalize_expression,
    validate_expression,
)
from trusts.plan.grammar import Tree, invoke, unsupported
from trusts.plan.writers import (
    _boolean_q,
    _negate_q,
    column_q,
    columns_q,
    contains_q,
    values_match,
)
from trusts.errors import PermissionConditionError, TrustsConfigurationError

# ``skip_<name>`` must not reuse an inquiry parameter. ``skip_is_active``
# is absent: it is the keyword for the ``is_active`` condition.
_RESERVED = frozenset({
    'user', 'user_obj', 'permission', 'perm', 'permext', 'content', 'obj',
    'extra_q', 'conditions', 'queryset', 'handles', 'kind', 'candidates',
    'plan', 'permission_model', 'skipped', 'skip_flags',
})

UserCondition = namedtuple('UserCondition', 'name expr on')

_IS_ACTIVE = Tree(
    'bare', item=Tree('field', root='user', path=('is_active',)),
)

BUILTIN_USER_CONDITIONS = (
    UserCondition('is_active', _IS_ACTIVE, '*'),
)


def builtin_user_conditions(model):
    """The default ``is_active`` rule, or nothing when that field is absent."""
    try:
        field = model._meta.get_field('is_active')
    except FieldDoesNotExist:
        return ()
    if (
        getattr(field, 'concrete', False)
        and field.get_internal_type() == 'BooleanField'
    ):
        return BUILTIN_USER_CONDITIONS
    return ()


def rule_applies(on, role):
    return on == '*' or on == role


def normalize_on(on):
    """Conditions accept only ``*``, ``user``, or ``sponsor``."""
    if isinstance(on, str) and on in ('*', 'user', 'sponsor'):
        return on
    raise TrustsConfigurationError(
        'User condition on= must be "*", "user", or "sponsor", not %r.' % (on,)
    )


def normalize_override_on(on):
    """Overrides accept only the checked user."""
    if on == 'user':
        return 'user'
    raise TrustsConfigurationError(
        'User override on= applies only to the checked user. '
        'Omit on= or pass on="user", not %r.' % (on,)
    )


def validate_user_rule_name(name, *, kind):
    """Fail when ``name`` cannot become the keyword ``skip_<name>``."""
    label = 'User condition' if kind == 'condition' else 'User override'
    if not isinstance(name, str) or not name.isidentifier():
        raise TrustsConfigurationError(
            '%s name must be an identifier, not %r.' % (label, name)
        )
    if name in _RESERVED or ('skip_%s' % name) in _RESERVED:
        raise TrustsConfigurationError(
            '%s name %r collides with an inquiry keyword.' % (label, name)
        )


def condition_names(conditions, override=None):
    rules = BUILTIN_USER_CONDITIONS if conditions is None else conditions
    names = {rule.name for rule in rules}
    if override is not None:
        names.add(override.name)
    return frozenset(names)


def _lower_user(node):
    """Keep the shared tree when a user rule can store it."""
    where = 'a user condition'
    if node.kind in ('and', 'or', 'eq', 'ne', 'contains'):
        _lower_user(node.left)
        _lower_user(node.right)
        return node
    if node.kind in ('not', 'bare'):
        _lower_user(node.item)
        return node
    if node.kind in ('field', 'const'):
        return node
    raise unsupported(node.kind, where)


def walk_user_lambda(expr):
    """Walk ``lambda u: ...`` once. Does not call it with a user instance."""
    if not callable(expr):
        raise TrustsConfigurationError(
            'User condition expression must be a callable or None, not %r.'
            % (expr,)
        )
    return normalize_expression(_lower_user(invoke(expr, ('user',))))


def _require_user_boolean(model, node, name):
    """The terminal of a bare user field must be a concrete boolean."""
    if node.kind != 'field' or node.root != 'user' or not node.path:
        raise PermissionConditionError(
            'User condition %r needs a boolean field on %s.'
            % (name, model._meta.label)
        )
    field = _terminal_field(model, node.path, 'principal')
    if (
        not getattr(field, 'concrete', False)
        or not isinstance(field, BooleanField)
    ):
        raise PermissionConditionError(
            'User condition %r needs %s.%s to be a concrete '
            'BooleanField.' % (
                name, model._meta.label, '__'.join(node.path),
            )
        )


def validate_user_rule(model, expr, name):
    """Check user rule ``name`` against ``model``.

    A bare field must be a concrete boolean, including one reached
    through a relation. Comparisons and ``.contains()`` use the shared
    expression checker. ``model`` is the principal model.
    """
    if expr.kind in ('and', 'or'):
        validate_user_rule(model, expr.left, name)
        validate_user_rule(model, expr.right, name)
        return
    if expr.kind == 'not':
        validate_user_rule(model, expr.item, name)
        return
    if expr.kind == 'bare':
        _require_user_boolean(model, expr.item, name)
        return
    if expr.kind in ('eq', 'ne', 'contains'):
        validate_expression(expr, model, model)
        return
    raise unsupported(expr.kind, 'a user condition')


def concrete_rule(expr, name, user_model):
    """Walk ``expr`` and check it against ``user_model``."""
    walked = walk_user_lambda(expr)
    validate_user_rule(user_model, walked, name)
    return walked


def _prefixed(path, field_path):
    """Lookup for a user field. ``path`` is the sponsor prefix, or empty."""
    parts = tuple(field_path)
    name = '__'.join(parts) if parts else 'pk'
    if path:
        return '%s__%s' % (path, name)
    return name


def _compile(path, expr, scope):
    if expr.kind == 'and':
        return (
            _compile(path, expr.left, scope)
            & _compile(path, expr.right, scope)
        )
    if expr.kind == 'or':
        return (
            _compile(path, expr.left, scope)
            | _compile(path, expr.right, scope)
        )
    if expr.kind == 'not':
        return _negate_q(scope, _compile(path, expr.item, scope))
    if expr.kind == 'bare':
        return _compile(path, expr.item, scope)
    if expr.kind == 'field':
        return _boolean_q(_prefixed(path, expr.path))
    if expr.kind in ('eq', 'ne'):
        return _compile_user_comparison(path, expr)
    if expr.kind == 'contains':
        return _compile_user_contains(path, expr)
    raise unsupported(expr.kind, 'a user condition')


def _compile_user_comparison(path, node):
    equal = node.kind == 'eq'
    left = node.left
    right = node.right
    if left.kind == 'field' and right.kind == 'field':
        return columns_q(
            _prefixed(path, left.path),
            _prefixed(path, right.path),
            equal,
        )
    if left.kind == 'const' and right.kind == 'const':
        if values_match(left.value, right.value, equal, fields=False):
            return Q()
        return Q(pk__in=())
    if left.kind == 'field':
        return column_q(
            _prefixed(path, left.path), right.value, equal, field=False,
        )
    return column_q(
        _prefixed(path, right.path), left.value, equal, field=False,
    )


def _stored_member(value):
    if isinstance(value, (Model, ModelIdentity)):
        return value.pk
    return value


def _compile_user_contains(path, node):
    lookup = _prefixed(path, node.left.path)
    member = node.right
    if member.kind == 'const':
        value = _stored_member(member.value)
        if value is None:
            return Q(pk__in=())
        return contains_q(lookup, value)
    return contains_q(lookup, F(_prefixed(path, member.path)))


class SkipFlag(RawSQL):
    """One ``skip_<name>`` placeholder. Callers change ``value`` only."""

    conditional = True

    def __init__(self, name, value):
        self.name = name
        self.value = bool(value)
        super().__init__('%s', (self.value,), output_field=BooleanField())

    def __repr__(self):
        return 'SkipFlag(%s=%s)' % (self.name, self.value)


def bind_skip_flags(fragment, values):
    """Copy a registration-time fragment and set its skip parameters."""
    if fragment is None:
        return None
    cloned = copy.deepcopy(fragment)
    _write_flags(cloned, values or {})
    return cloned


def _write_flags(node, values):
    if isinstance(node, SkipFlag):
        node.value = bool(values.get(node.name, False))
        node.params = (node.value,)
        return
    for child in getattr(node, 'children', ()) or ():
        _write_flags(child, values)


def _stored(conditions):
    if conditions is None:
        return BUILTIN_USER_CONDITIONS
    return tuple(conditions)


def compile_user_rules(model, path, conditions, *, role, values, scope=None):
    """``(skip_<name> OR condition)`` for rules that apply to ``role``.

    ``conditions is None`` is the built-in ``is_active`` rule. The registry
    passes that rule only when ``model`` has the field, and one fragment
    for every inquiry. ``scope`` is the model ``not`` is evaluated against.
    A sponsor rule is filtered on the delegation row, so ``scope`` is that
    row's model. An empty prefix uses ``model``, the principal.
    """
    values = values or {}
    if scope is None:
        scope = model
    combined = None
    for rule in _stored(conditions):
        if not rule_applies(rule.on, role):
            continue
        flag = SkipFlag(rule.name, values.get(rule.name, False))
        part = Q(flag) | _compile(path, rule.expr, scope)
        combined = part if combined is None else combined & part
    return Q() if combined is None else combined


def compile_override_q(model, path, slot, values):
    """``(NOT skip_<override> AND override)``, or ``None`` when unset."""
    if slot is None:
        return None
    flag = SkipFlag(slot.name, (values or {}).get(slot.name, False))
    return ~Q(flag) & _compile(path, slot.expr, model)
