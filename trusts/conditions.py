"""Restricted declarative permission conditions (issue #4 V1).

A registered condition may be a convenient Python lambda. Invoking it with
symbolic principal / permission / object references produces a
language-neutral expression tree. Django ``Q`` is one compiler target, not
the canonical representation.

V1 grammar: principal/object field refs and relationship traversal
(``_meta`` fields on the content model and the entity/user model; not
Python properties); literal constants; ``==`` / ``!=``; nested ``&`` /
``|``. Missing attribute names fail closed; they are not treated as
``NULL``. Python ``and`` / ``or`` / ``not`` cannot be overloaded and
raise ``PermissionConditionBooleanError``.
"""

from django.core.exceptions import FieldDoesNotExist, ObjectDoesNotExist
from django.db.models import F, Model, Q


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
    "because they cannot be overloaded. Use '&' and '|' for conjunction "
    "and disjunction, and '!=' instead of combining 'not' with '=='."
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
        _unsupported('Ordering comparisons')

    def __le__(self, other):
        _unsupported('Ordering comparisons')

    def __gt__(self, other):
        _unsupported('Ordering comparisons')

    def __ge__(self, other):
        _unsupported('Ordering comparisons')

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


def build_expression(func):
    """Invoke ``func`` with symbolic refs.

    Returns a predicate ``Expr`` when the callback is a V1 declarative
    condition. Returns ``None`` when the callback is genuinely arbitrary
    Python (object-only). Raises ``PermissionConditionBooleanError`` when
    the callback truth-tests a symbolic node (``and`` / ``or`` / ``not``).
    """
    try:
        result = func(principal_ref(), permission_ref(), object_ref())
    except PermissionConditionBooleanError:
        raise
    except PermissionConditionUnsupported:
        return None
    except Exception:
        return None
    if is_predicate(result):
        return result
    return None


def _entity_model():
    from trusts import get_entity_model
    return get_entity_model()


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


def validate_expression(node, model):
    """Resolve object paths against ``model`` and principal paths against the entity model."""
    if not is_predicate(node):
        raise PermissionConditionError(
            'Permission condition did not produce a comparison expression.'
        )
    _validate_node(node, model)


def _validate_node(node, model):
    if isinstance(node, (And, Or, Eq, Ne)):
        _validate_node(node.left, model)
        _validate_node(node.right, model)
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


def queryable_condition_q(func, model, user, perm):
    """Return a ``Q`` for ``func``, or raise if it is not a V1 expression.

    ``PermissionConditionBooleanError`` is left uncaught so callers see the
    ``and`` / ``or`` guidance. Genuinely arbitrary callbacks yield ``None``
    from ``build_expression``; the caller raises
    ``PermissionConditionNotQueryable``.
    """
    expr = build_expression(func)
    if expr is None:
        return None
    validate_expression(expr, model)
    return compile_to_q(expr, model, user, perm)


def evaluate_condition_func(func, user, perm, obj, model=None):
    """Evaluate ``func`` using a captured expression when possible.

    Shares the tree with queryset compilation. Falls back to calling
    ``func`` with real arguments only for genuinely arbitrary callbacks
    (no V1 tree). A captured tree that fails field validation raises
    ``PermissionConditionError`` on the object path as well as the queryset
    path; it must not fall back and must not treat a missing attribute as
    ``None``.
    """
    try:
        expr = build_expression(func)
    except PermissionConditionBooleanError:
        return func(user, perm, obj)
    if expr is None:
        return func(user, perm, obj)
    klass = model
    if klass is None:
        klass = obj.model if hasattr(obj, 'model') and not isinstance(obj, Model) else obj.__class__
    validate_expression(expr, klass)
    return evaluate_expression(expr, user, perm, obj, model=klass)
