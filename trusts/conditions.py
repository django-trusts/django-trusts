"""Restricted declarative permission conditions (issue #4 V1).

Register an ``Expr`` tree built from ``condition_refs()`` (``u``, ``p``,
``o``). That tree is policy data: ``has_perm`` evaluates it and
``.permitted()`` compiles it to SQL. Django ``Q`` is one compiler
target, not the canonical representation.

A callable argument is the legacy object-only predicate. Registration
dispatches by type and never invokes a callable with symbolic refs.

V1 grammar: principal/object field refs and relationship traversal
(``_meta`` fields on the content model and the entity/user model; not
Python properties); literal constants; ``==`` / ``!=``; nested ``&`` /
``|``. Operand types must match without Django field coercion:
``CharField`` compares to ``str``, relations compare to model instances
(not raw primary keys). Missing attribute names fail closed; they are
not treated as ``NULL``. Python ``and`` / ``or`` / ``not`` and chained
comparisons cannot be overloaded and raise
``PermissionConditionBooleanError``.
"""

from django.core.exceptions import FieldDoesNotExist, ObjectDoesNotExist
from django.db.models import (
    F,
    Model,
    Q,
    BinaryField,
    BooleanField,
    CharField,
    DateField,
    DateTimeField,
    DecimalField,
    DurationField,
    FloatField,
    IntegerField,
    TextField,
    TimeField,
    UUIDField,
)
from django.db.models.fields import GenericIPAddressField


class PermissionConditionError(Exception):
    """Unsupported or malformed declarative permission condition.

    Fail closed: never ignore the condition and return the underlying grant.
    """


class PermissionConditionBooleanError(PermissionConditionError):
    """Raised when a symbolic condition is truth-tested (``and`` / ``or`` / ``not``)."""


class PermissionConditionUnsupported(PermissionConditionError):
    """Raised for operations outside the V1 grammar (calls, indexing, arithmetic)."""


_BOOLEAN_ERROR_MESSAGE = (
    "Python 'and'/'or'/'not' cannot be used in permission conditions "
    "because they cannot be overloaded; chained comparisons such as "
    "`0 < o.amount < 100` also truth-test a symbolic node. Use '&' and "
    "'|' for conjunction and disjunction, and '!=' instead of combining "
    "'not' with '=='."
)

_LITERAL_TYPES = (type(None), bool, int, float, str, bytes)


def _boolean_error():
    raise PermissionConditionBooleanError(_BOOLEAN_ERROR_MESSAGE)


def _unsupported(what):
    raise PermissionConditionUnsupported(
        '%s is not supported in declarative permission conditions.' % what
    )


class Expr(object):
    """Node in a permission-condition expression tree."""

    def __eq__(self, other):
        return Eq(self, as_node(other))

    def __ne__(self, other):
        return Ne(self, as_node(other))

    def __and__(self, other):
        return _bool_op(And, self, as_node(other), '&')

    def __or__(self, other):
        return _bool_op(Or, self, as_node(other), '|')

    def __rand__(self, other):
        return _bool_op(And, as_node(other), self, '&')

    def __ror__(self, other):
        return _bool_op(Or, as_node(other), self, '|')

    def __bool__(self):
        _boolean_error()

    def __call__(self, *args, **kwargs):
        _unsupported('Function or method calls')

    def __getitem__(self, key):
        _unsupported('Indexing')

    def __iter__(self):
        _unsupported('Iteration')

    def __add__(self, other):
        _unsupported('Arithmetic')

    def __radd__(self, other):
        _unsupported('Arithmetic')

    def __sub__(self, other):
        _unsupported('Arithmetic')

    def __rsub__(self, other):
        _unsupported('Arithmetic')

    def __mul__(self, other):
        _unsupported('Arithmetic')

    def __rmul__(self, other):
        _unsupported('Arithmetic')

    def __truediv__(self, other):
        _unsupported('Arithmetic')

    def __rtruediv__(self, other):
        _unsupported('Arithmetic')

    def __floordiv__(self, other):
        _unsupported('Arithmetic')

    def __mod__(self, other):
        _unsupported('Arithmetic')

    def __pow__(self, other):
        _unsupported('Arithmetic')

    def __lt__(self, other):
        return _Ordering('lt', self, as_node(other))

    def __le__(self, other):
        return _Ordering('le', self, as_node(other))

    def __gt__(self, other):
        return _Ordering('gt', self, as_node(other))

    def __ge__(self, other):
        return _Ordering('ge', self, as_node(other))

    def __setitem__(self, key, value):
        _unsupported('Item assignment')

    def __invert__(self):
        _unsupported("Unary '~' / 'not'")

    def __contains__(self, item):
        _unsupported("'in' tests")

    def __hash__(self):
        return id(self)

    def to_tuple(self):
        raise NotImplementedError


class Ref(Expr):
    """Symbolic principal, permission, or object reference, with optional path."""

    def __init__(self, source, path=()):
        if source not in ('principal', 'permission', 'object'):
            raise PermissionConditionError('Unknown reference source %r.' % (source,))
        self.source = source
        self.path = tuple(path)

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        return Ref(self.source, self.path + (name,))

    def __setattr__(self, name, value):
        if name in ('source', 'path'):
            object.__setattr__(self, name, value)
            return
        _unsupported('Assignment to symbolic fields')

    def __delattr__(self, name):
        _unsupported('Deletion of symbolic fields')

    def to_tuple(self):
        return ('ref', self.source, self.path)

    def __repr__(self):
        name = {'principal': 'u', 'permission': 'p', 'object': 'o'}[self.source]
        if not self.path:
            return name
        return '%s.%s' % (name, '.'.join(self.path))


class Const(Expr):
    def __init__(self, value):
        self.value = value

    def to_tuple(self):
        return ('const', self.value)

    def __repr__(self):
        return repr(self.value)


class Eq(Expr):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def to_tuple(self):
        return ('eq', self.left.to_tuple(), self.right.to_tuple())

    def __repr__(self):
        return '(%r == %r)' % (self.left, self.right)


class Ne(Expr):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def to_tuple(self):
        return ('ne', self.left.to_tuple(), self.right.to_tuple())

    def __repr__(self):
        return '(%r != %r)' % (self.left, self.right)


class And(Expr):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def to_tuple(self):
        return ('and', self.left.to_tuple(), self.right.to_tuple())

    def __repr__(self):
        return '(%r & %r)' % (self.left, self.right)


class Or(Expr):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def to_tuple(self):
        return ('or', self.left.to_tuple(), self.right.to_tuple())

    def __repr__(self):
        return '(%r | %r)' % (self.left, self.right)


class _Ordering(Expr):
    """Ordering comparison node so chained ``a < b < c`` hits ``__bool__``.

    Not part of the V1 grammar. Registering one as a condition is rejected.
    """

    def __init__(self, op, left, right):
        self.op = op
        self.left = left
        self.right = right

    def to_tuple(self):
        return (self.op, self.left.to_tuple(), self.right.to_tuple())

    def __repr__(self):
        symbols = {'lt': '<', 'le': '<=', 'gt': '>', 'ge': '>='}
        return '(%r %s %r)' % (self.left, symbols.get(self.op, self.op), self.right)


def is_predicate(node):
    return isinstance(node, (Eq, Ne, And, Or))


def as_node(value):
    if isinstance(value, Expr):
        return value
    if isinstance(value, _LITERAL_TYPES):
        return Const(value)
    if isinstance(value, Model):
        return Const(value)
    _unsupported('Constant of type %s' % type(value).__name__)


def _bool_op(cls, left, right, op):
    if not is_predicate(left) or not is_predicate(right):
        raise PermissionConditionUnsupported(
            "'%s' requires comparison operands (for example "
            "`(u == o.owner) %s (o.status != 'locked')`)." % (op, op)
        )
    return cls(left, right)


def principal_ref():
    return Ref('principal')


def permission_ref():
    return Ref('permission')


def object_ref():
    return Ref('object')


def condition_refs():
    """Return symbolic ``(u, p, o)`` for building a registered ``Expr``.

    Combine the refs with ``==`` / ``!=`` / ``&`` / ``|`` and pass the
    resulting tree to ``Content.register_permission_condition``. These
    objects are policy data, not live principals or content rows.
    """
    return principal_ref(), permission_ref(), object_ref()


class _QueryNamespace(object):
    """Controlled lookup namespace for declarative permission conditions.

    Not a Django ``QuerySet``. V1 equality uses ``==`` / ``!=`` on
    ``condition_refs()``. Future relational operations (Django-style
    lookup names such as ``iexact`` or ``in``) belong here so they are
    not added as ad-hoc methods on ``Ref``. V1 does not implement those
    lookups.
    """

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        raise PermissionConditionUnsupported(
            'TQ.%s is not implemented in V1 permission conditions. '
            'The implemented grammar is field refs, constants, ==, !=, '
            '& and |. Additional lookups will be added to this namespace '
            'explicitly.' % name
        )

    def __repr__(self):
        return 'TQ'


Query = _QueryNamespace()
TQ = Query


def _entity_model():
    from django.contrib.auth import get_user_model
    from trusts import get_entity_model, supported_entity_contract

    if supported_entity_contract():
        return get_entity_model()
    return get_user_model()


def resolve_field_path(model, path, ref_kind='object'):
    """Validate ``path`` against ``model`` and return the Django lookup string.

    Relationship traversal is allowed; a non-relational field may only appear
    as the last component. Missing names raise ``PermissionConditionError``
    rather than resolving to ``None``.
    """
    if not path:
        raise PermissionConditionError(
            '%s references must name a field (for example %s.owner), '
            'not the %s itself.' % (
                ref_kind.capitalize(),
                'o' if ref_kind == 'object' else 'u',
                ref_kind,
            )
        )
    current = model
    for i, name in enumerate(path):
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist:
            raise PermissionConditionError(
                'Permission condition field %r is not on model %s '
                '(path %s).' % (
                    name,
                    current._meta.label,
                    '.'.join(path[:i + 1]),
                )
            )
        if field.many_to_many or field.one_to_many:
            raise PermissionConditionError(
                'Multi-valued relation %r on %s is not supported in V1 '
                'permission conditions (path %s). ManyToManyField and '
                'reverse one-to-many membership is not defined; '
                'has_perm and permitted both reject these refs.' % (
                    name,
                    current._meta.label,
                    '.'.join(path[:i + 1]),
                )
            )
        last = i == len(path) - 1
        if not last:
            if not field.is_relation:
                raise PermissionConditionError(
                    'Cannot traverse field %r on %s in a permission '
                    'condition; relationship traversal requires a '
                    'ForeignKey or OneToOneField.' % (
                        name, current._meta.label
                    )
                )
            current = field.remote_field.model
    return '__'.join(path)


def resolve_object_field_path(model, path):
    return resolve_field_path(model, path, ref_kind='object')


def _terminal_field(model, path, ref_kind='object'):
    resolve_field_path(model, path, ref_kind=ref_kind)
    current = model
    field = None
    for i, name in enumerate(path):
        field = current._meta.get_field(name)
        if i != len(path) - 1:
            current = field.remote_field.model
    return field


def _concrete_model(model):
    meta = getattr(model, '_meta', None)
    if meta is not None:
        return meta.concrete_model
    return model


def _models_compatible(left, right):
    left = _concrete_model(left)
    right = _concrete_model(right)
    return (
        left is right or
        issubclass(left, right) or
        issubclass(right, left)
    )


def _scalar_types_for_field(field):
    if isinstance(field, BooleanField):
        return (bool,)
    if isinstance(field, IntegerField):
        return (int,)
    if isinstance(field, FloatField):
        return (float, int)
    if isinstance(field, DecimalField):
        from decimal import Decimal
        return (Decimal,)
    if isinstance(field, (CharField, TextField, GenericIPAddressField)):
        return (str,)
    if isinstance(field, UUIDField):
        from uuid import UUID
        return (UUID,)
    if isinstance(field, DateTimeField):
        from datetime import datetime
        return (datetime,)
    if isinstance(field, DateField):
        from datetime import date
        return (date,)
    if isinstance(field, TimeField):
        from datetime import time
        return (time,)
    if isinstance(field, DurationField):
        from datetime import timedelta
        return (timedelta,)
    if isinstance(field, BinaryField):
        return (bytes,)
    return ()


def _spec_from_field(field):
    if field.is_relation and not field.many_to_many and not field.one_to_many:
        related = field.related_model
        return ('instance', related, '%s %s' % (field.get_internal_type(), field.name))
    types = _scalar_types_for_field(field)
    return ('scalar', types, '%s %s' % (field.get_internal_type(), field.name))


def _spec_from_const(value):
    if value is None:
        return ('null', None, 'None')
    if isinstance(value, Model):
        return ('instance', value.__class__, value._meta.label)
    if isinstance(value, bool):
        return ('scalar', (bool,), 'bool')
    if isinstance(value, int):
        return ('scalar', (int,), 'int')
    if isinstance(value, float):
        return ('scalar', (float,), 'float')
    if isinstance(value, str):
        return ('scalar', (str,), 'str')
    if isinstance(value, bytes):
        return ('scalar', (bytes,), 'bytes')
    return ('scalar', (type(value),), type(value).__name__)


def _operand_spec(node, model):
    if isinstance(node, Const):
        return _spec_from_const(node.value)
    if isinstance(node, Ref):
        if node.source == 'object':
            return _spec_from_field(_terminal_field(model, node.path, 'object'))
        if node.source == 'principal':
            if not node.path:
                entity = _entity_model()
                return ('instance', entity, entity._meta.label)
            return _spec_from_field(
                _terminal_field(_entity_model(), node.path, 'principal')
            )
        if node.source == 'permission':
            return ('scalar', (str,), 'permission')
    raise PermissionConditionError(
        'Cannot type-check permission condition node %r.' % (node,)
    )


def _specs_compatible(left, right):
    if left[0] == 'null' or right[0] == 'null':
        return True
    if left[0] == 'instance' and right[0] == 'instance':
        return _models_compatible(left[1], right[1])
    if left[0] == 'scalar' and right[0] == 'scalar':
        return bool(set(left[1]) & set(right[1]))
    return False


def _check_comparison_types(node, model):
    left = _operand_spec(node.left, model)
    right = _operand_spec(node.right, model)
    if _specs_compatible(left, right):
        return
    raise PermissionConditionError(
        'Permission condition compares incompatible types (%s vs %s). '
        'V1 does not coerce literals through Django field preparation; '
        'CharField values are strings, and relations compare to model '
        'instances (not raw primary keys).' % (left[2], right[2])
    )


def validate_expression(node, model):
    """Resolve paths and require comparable operand types on ``Eq`` / ``Ne``.

    Object paths are validated against ``model``; principal paths against
    the entity model. Incompatible field/literal pairs (for example
    ``CharField`` vs ``int``, or a ``ForeignKey`` vs a raw PK) raise
    ``PermissionConditionError`` so Django lookup coercion cannot make
    ``has_perm`` and ``.permitted()`` diverge.
    """
    if not is_predicate(node):
        raise PermissionConditionError(
            'Permission condition did not produce a comparison expression.'
        )
    _validate_node(node, model)


def _validate_node(node, model):
    if isinstance(node, (And, Or)):
        _validate_node(node.left, model)
        _validate_node(node.right, model)
        return
    if isinstance(node, (Eq, Ne)):
        _validate_node(node.left, model)
        _validate_node(node.right, model)
        _check_comparison_types(node, model)
        return
    if isinstance(node, Const):
        return
    if isinstance(node, Ref):
        if node.source == 'object':
            resolve_field_path(model, node.path, ref_kind='object')
        elif node.source == 'principal':
            if node.path:
                resolve_field_path(_entity_model(), node.path, ref_kind='principal')
        elif node.source == 'permission':
            if node.path:
                raise PermissionConditionError(
                    'Permission references cannot traverse attributes in V1.'
                )
        return
    raise PermissionConditionError(
        'Malformed permission condition node %r.' % (node,)
    )


def _walk_model_path(instance, model, path):
    """Follow a ``_meta`` field path on ``instance``.

    A missing field name raises ``PermissionConditionError``. A legitimate
    nullable relation (or a missing reverse one-to-one) resolves to ``None``.
    Python properties are not consulted: only model fields.
    """
    current = instance
    current_model = model
    for i, name in enumerate(path):
        try:
            field = current_model._meta.get_field(name)
        except FieldDoesNotExist:
            raise PermissionConditionError(
                'Permission condition field %r is not on model %s '
                '(path %s).' % (
                    name,
                    current_model._meta.label,
                    '.'.join(path[:i + 1]),
                )
            )
        last = i == len(path) - 1
        if field.many_to_many or field.one_to_many:
            raise PermissionConditionError(
                'Multi-valued relation %r on %s is not supported in V1 '
                'permission conditions (path %s). ManyToManyField and '
                'reverse one-to-many membership is not defined; '
                'has_perm and permitted both reject these refs.' % (
                    name,
                    current_model._meta.label,
                    '.'.join(path[:i + 1]),
                )
            )
        if not last and not field.is_relation:
            raise PermissionConditionError(
                'Cannot traverse field %r on %s in a permission '
                'condition; relationship traversal requires a '
                'ForeignKey or OneToOneField.' % (
                    name, current_model._meta.label
                )
            )
        if current is None:
            return None
        if field.is_relation and not field.many_to_many and not field.one_to_many:
            try:
                current = getattr(current, field.name)
            except ObjectDoesNotExist:
                current = None
            if not last:
                current_model = field.remote_field.model
            continue
        current = getattr(current, field.attname)
    return current


def _resolve_runtime(node, user, perm, obj, model):
    if isinstance(node, Const):
        return node.value
    if isinstance(node, Ref):
        if node.source == 'principal':
            if not node.path:
                return user
            return _walk_model_path(user, _entity_model(), node.path)
        if node.source == 'permission':
            if node.path:
                raise PermissionConditionError(
                    'Permission references cannot traverse attributes in V1.'
                )
            return perm
        if node.source == 'object':
            return _walk_model_path(obj, model, node.path)
    raise PermissionConditionError(
        'Cannot evaluate permission condition node %r.' % (node,)
    )


def evaluate_expression(node, user, perm, obj, model=None):
    """Evaluate a captured expression against a real principal/permission/object."""
    if model is None:
        model = obj.__class__
    if isinstance(node, And):
        return evaluate_expression(node.left, user, perm, obj, model) and (
            evaluate_expression(node.right, user, perm, obj, model)
        )
    if isinstance(node, Or):
        return evaluate_expression(node.left, user, perm, obj, model) or (
            evaluate_expression(node.right, user, perm, obj, model)
        )
    if isinstance(node, Eq):
        return _resolve_runtime(node.left, user, perm, obj, model) == (
            _resolve_runtime(node.right, user, perm, obj, model)
        )
    if isinstance(node, Ne):
        return _resolve_runtime(node.left, user, perm, obj, model) != (
            _resolve_runtime(node.right, user, perm, obj, model)
        )
    raise PermissionConditionError(
        'Permission condition did not produce a comparison expression.'
    )


class _Bound(object):
    def __init__(self, value):
        self.value = value


class _Unbound(object):
    def __init__(self, lookup):
        self.lookup = lookup


def _classify(node, model, user, perm):
    if isinstance(node, Const):
        return _Bound(node.value)
    if isinstance(node, Ref):
        if node.source == 'object':
            return _Unbound(resolve_object_field_path(model, node.path))
        if node.source == 'principal':
            if not node.path:
                return _Bound(user)
            return _Bound(_walk_model_path(user, _entity_model(), node.path))
        if node.source == 'permission':
            if node.path:
                raise PermissionConditionError(
                    'Permission references cannot traverse attributes in V1.'
                )
            return _Bound(perm)
    raise PermissionConditionError(
        'Cannot compile permission condition node %r.' % (node,)
    )


def _always_true():
    return Q()


def _always_false():
    return Q(pk__in=())


def _q_eq_lookup(lookup, value):
    if value is None:
        return Q(**{'%s__isnull' % lookup: True})
    return Q(**{lookup: value})


def _q_ne_lookup(lookup, value):
    # Match Python: ``None != x`` is True when ``x is not None``.
    if value is None:
        return Q(**{'%s__isnull' % lookup: False})
    return Q(**{'%s__isnull' % lookup: True}) | ~Q(**{lookup: value})


def _q_eq_fields(a, b):
    # Python ``None == None`` is True; SQL ``NULL = NULL`` is not.
    return (
        (Q(**{'%s__isnull' % a: True}) & Q(**{'%s__isnull' % b: True})) |
        (
            Q(**{'%s__isnull' % a: False}) &
            Q(**{'%s__isnull' % b: False}) &
            Q(**{a: F(b)})
        )
    )


def _q_ne_fields(a, b):
    return (
        (Q(**{'%s__isnull' % a: True}) & Q(**{'%s__isnull' % b: False})) |
        (Q(**{'%s__isnull' % a: False}) & Q(**{'%s__isnull' % b: True})) |
        (
            Q(**{'%s__isnull' % a: False}) &
            Q(**{'%s__isnull' % b: False}) &
            ~Q(**{a: F(b)})
        )
    )


def _compile_comparison(node, model, user, perm):
    left = _classify(node.left, model, user, perm)
    right = _classify(node.right, model, user, perm)
    equal = isinstance(node, Eq)
    if isinstance(left, _Bound) and isinstance(right, _Bound):
        matches = (left.value == right.value) if equal else (left.value != right.value)
        return _always_true() if matches else _always_false()
    if isinstance(left, _Unbound) and isinstance(right, _Bound):
        lookup, value = left.lookup, right.value
    elif isinstance(left, _Bound) and isinstance(right, _Unbound):
        lookup, value = right.lookup, left.value
    else:
        a, b = left.lookup, right.lookup
        return _q_eq_fields(a, b) if equal else _q_ne_fields(a, b)
    return _q_eq_lookup(lookup, value) if equal else _q_ne_lookup(lookup, value)


def compile_to_q(node, model, user, perm):
    """Compile an expression tree to a Django ``Q`` for ``model`` rows."""
    if isinstance(node, And):
        return compile_to_q(node.left, model, user, perm) & compile_to_q(
            node.right, model, user, perm
        )
    if isinstance(node, Or):
        return compile_to_q(node.left, model, user, perm) | compile_to_q(
            node.right, model, user, perm
        )
    if isinstance(node, (Eq, Ne)):
        return _compile_comparison(node, model, user, perm)
    raise PermissionConditionError(
        'Permission condition did not produce a comparison expression.'
    )


def compile_expression_q(expr, model, user, perm):
    """Compile a registered ``Expr`` to ``Q``. Fail closed if invalid."""
    if not is_predicate(expr):
        raise PermissionConditionError(
            'Permission condition did not produce a V1 comparison '
            'expression (==, !=, &, | over principal and object fields).'
        )
    validate_expression(expr, model)
    return compile_to_q(expr, model, user, perm)


def evaluate_registered_expression(expr, user, perm, obj, model=None):
    """Evaluate a registered ``Expr`` against a real principal/object."""
    if not is_predicate(expr):
        raise PermissionConditionError(
            'Permission condition did not produce a V1 comparison '
            'expression (==, !=, &, | over principal and object fields).'
        )
    klass = model
    if klass is None:
        klass = obj.model if hasattr(obj, 'model') and not isinstance(obj, Model) else obj.__class__
    validate_expression(expr, klass)
    return evaluate_expression(expr, user, perm, obj, model=klass)
