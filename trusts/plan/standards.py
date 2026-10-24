"""Named user conditions compiled once into each check.

``Bit`` and ``Proxy`` are the tree names.

Each condition is ``(skip_<name> OR condition)``. The override is
``(NOT skip_<override> AND override)``, ORed with ordinary grants and
delegation. The skip flag is a bound parameter, so one statement serves
every skip state. The lockfile records that statement.
"""

__all__ = []

import copy
from collections import namedtuple

from django.core.exceptions import FieldDoesNotExist
from django.db.models import BooleanField, Q
from django.db.models.expressions import RawSQL

from trusts.errors import TrustsConfigurationError

_MSG = 'User conditions only support concrete boolean fields, &, and ~.'

# ``skip_<name>`` must not reuse an inquiry parameter. ``skip_is_active``
# is absent: it is the keyword for the ``is_active`` condition.
_RESERVED = frozenset({
    'user', 'user_obj', 'permission', 'perm', 'permext', 'content', 'obj',
    'extra_q', 'conditions', 'queryset', 'handles', 'kind', 'candidates',
    'plan', 'permission_model', 'skipped', 'skip_flags',
})

Node = namedtuple('Node', 'kind name left right')
UserCondition = namedtuple('UserCondition', 'name expr on')

BUILTIN_USER_CONDITIONS = (
    UserCondition('is_active', Node('field', 'is_active', None, None), '*'),
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


class Bit(object):
    def __init__(self, node):
        self.node = node

    def __and__(self, other):
        if not isinstance(other, Bit):
            raise TrustsConfigurationError(_MSG)
        return Bit(Node('and', None, self.node, other.node))

    def __invert__(self):
        return Bit(Node('not', None, self.node, None))

    def _reject(self, *args, **kwargs):
        raise TrustsConfigurationError(_MSG)

    __rand__ = __and__
    __bool__ = __eq__ = __or__ = __call__ = _reject


class Proxy(object):
    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        return Bit(Node('field', name, None, None))


def walk_user_lambda(expr):
    """Walk ``lambda u: ...`` once. Does not call it with a user instance."""
    if not callable(expr):
        raise TrustsConfigurationError(
            'User condition expression must be a callable or None, not %r.'
            % (expr,)
        )
    try:
        result = expr(Proxy())
    except TrustsConfigurationError:
        raise
    except Exception as exc:
        raise TrustsConfigurationError(_MSG) from exc
    if not isinstance(result, Bit):
        raise TrustsConfigurationError(_MSG)
    return result.node


def _fields(expr):
    if expr.kind == 'field':
        yield expr.name
        return
    if expr.left is not None:
        yield from _fields(expr.left)
    if expr.right is not None:
        yield from _fields(expr.right)


def field_state(model, expr):
    """``ok``, ``missing``, or raise when a present field is not boolean."""
    for field_name in _fields(expr):
        try:
            field = model._meta.get_field(field_name)
        except FieldDoesNotExist:
            return 'missing'
        if (
            not getattr(field, 'concrete', False)
            or field.get_internal_type() != 'BooleanField'
        ):
            raise TrustsConfigurationError(
                '%s.%s must be a concrete BooleanField.'
                % (model._meta.label, field_name)
            )
    return 'ok'


def assert_concrete_booleans(model, expr, name):
    if field_state(model, expr) != 'ok':
        raise TrustsConfigurationError(
            'User condition %r needs a concrete BooleanField on %s.'
            % (name, model._meta.label)
        )


def concrete_rule(expr, name, user_model):
    """Walk ``expr`` and require concrete booleans on ``user_model``."""
    walked = walk_user_lambda(expr)
    assert_concrete_booleans(user_model, walked, name)
    return walked


def _compile(path, expr):
    if expr.kind == 'field':
        key = '%s__%s' % (path, expr.name) if path else expr.name
        return Q(**{key: True})
    if expr.kind == 'not':
        return ~_compile(path, expr.left)
    return _compile(path, expr.left) & _compile(path, expr.right)


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


def compile_user_rules(model, path, conditions, *, role, values):
    """``(skip_<name> OR condition)`` for rules that apply to ``role``.

    ``conditions is None`` is the built-in ``is_active`` rule. The registry
    passes that rule only when ``model`` has the field, and one fragment
    for every inquiry.
    """
    values = values or {}
    combined = None
    for rule in _stored(conditions):
        if not rule_applies(rule.on, role):
            continue
        flag = SkipFlag(rule.name, values.get(rule.name, False))
        part = Q(flag) | _compile(path, rule.expr)
        combined = part if combined is None else combined & part
    return Q() if combined is None else combined


def compile_override_q(model, path, slot, values):
    """``(NOT skip_<override> AND override)``, or ``None`` when unset."""
    if slot is None:
        return None
    flag = SkipFlag(slot.name, (values or {}).get(slot.name, False))
    return ~Q(flag) & _compile(path, slot.expr)
