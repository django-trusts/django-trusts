"""One condition grammar for register, named filters, and user rules.

The builder is not policy. Each entry point lowers the tree into the
nodes it stores. Those nodes hold field paths and normalized constants,
not Django expressions or application callbacks. A later function or
ordered comparison is another kind on this tree.

Roots are named roles (``row``, ``inquiry``, ``user``, ``object``,
``permission``), so a later user-side walk can name a root without a
second grammar. ``contains`` is a method, not a field hop.
"""

from trusts.errors import PermissionConditionError, TrustsConfigurationError
from trusts.plan.hops import path_text

_KIND_LABELS = {
    'eq': "'=='",
    'ne': "'!='",
    'and': "'&'",
    'or': "'|'",
    'not': "'~'",
    'contains': '.contains()',
    'bare': 'A bare boolean field',
    'const': 'A constant',
}

_RETURN_HINT = (
    'Return a comparison, .contains(), a boolean field, or a combination '
    "with '&' and '|'."
)

_PREDICATE_KINDS = frozenset((
    'eq', 'ne', 'and', 'or', 'not', 'contains', 'bare',
))

_OP_LABELS = {
    '__call__': 'A function or method call',
    '__lt__': 'Ordered comparison',
    '__le__': 'Ordered comparison',
    '__gt__': 'Ordered comparison',
    '__ge__': 'Ordered comparison',
    '__getitem__': 'Indexing',
    '__setitem__': 'Item assignment',
    '__delitem__': 'Item deletion',
    '__iter__': 'Iteration',
    '__next__': 'Iteration',
    '__contains__': "Python 'in'",
    '__add__': 'Arithmetic',
    '__radd__': 'Arithmetic',
    '__sub__': 'Arithmetic',
    '__rsub__': 'Arithmetic',
    '__mul__': 'Arithmetic',
    '__rmul__': 'Arithmetic',
    '__truediv__': 'Arithmetic',
    '__rtruediv__': 'Arithmetic',
    '__floordiv__': 'Arithmetic',
    '__rfloordiv__': 'Arithmetic',
    '__mod__': 'Arithmetic',
    '__rmod__': 'Arithmetic',
    '__pow__': 'Arithmetic',
    '__rpow__': 'Arithmetic',
    '__xor__': 'Bitwise xor',
    '__rxor__': 'Bitwise xor',
    '__lshift__': 'Bitwise shift',
    '__rlshift__': 'Bitwise shift',
    '__rshift__': 'Bitwise shift',
    '__rrshift__': 'Bitwise shift',
    '__neg__': 'Arithmetic',
    '__pos__': 'Arithmetic',
    '__abs__': 'Arithmetic',
    '__int__': 'Arithmetic',
    '__float__': 'Arithmetic',
    '__index__': 'Arithmetic',
    '__len__': 'Iteration',
    '__hash__': 'Hashing',
    '__enter__': 'Context management',
    '__exit__': 'Context management',
    '__await__': 'Awaiting',
    '__aenter__': 'Context management',
    '__aexit__': 'Context management',
}


def unsupported(what, where='a condition', hint=None):
    """The one rejection error for every condition surface.

    ``what`` is a tree kind or a plain-English label. ``where`` names
    the surface.
    """
    message = '%s is not supported in %s.' % (
        _KIND_LABELS.get(what, what), where,
    )
    if hint:
        message = '%s %s' % (message, hint)
    return PermissionConditionError(message)


def missing_field(role, path, name, model):
    """The one error for a condition or role path naming a missing field."""
    return PermissionConditionError(
        'The %s path %r refers to missing field %r on %s.'
        % (role, path_text(path), name, model._meta.label)
    )


def _boolean_rejection():
    return unsupported(
        "Python 'and', 'or', 'not', or a chained comparison",
        hint="Use '&' for conjunction and '|' for disjunction.",
    )


def _root_rejection():
    return unsupported(
        'A root without a field', hint='Name a field, for example o.owner.',
    )


def _unsupported(name):
    label = _OP_LABELS[name]

    def _op(self, *args, **kwargs):
        raise unsupported(label)

    _op.__name__ = name
    return _op


class Tree(object):
    """One condition node. Not a Django expression and not a callback."""

    __slots__ = ('kind', 'root', 'path', 'value', 'left', 'right', 'item')

    def __init__(self, kind, root=None, path=(), value=None, left=None,
                 right=None, item=None):
        object.__setattr__(self, 'kind', kind)
        object.__setattr__(self, 'root', root)
        object.__setattr__(self, 'path', tuple(path))
        object.__setattr__(self, 'value', value)
        object.__setattr__(self, 'left', left)
        object.__setattr__(self, 'right', right)
        object.__setattr__(self, 'item', item)

    def __setattr__(self, name, value):
        raise unsupported('Assignment')

    def __delattr__(self, name):
        raise unsupported('Deletion')

    def __bool__(self):
        raise _boolean_rejection()

    def __and__(self, other):
        return _join('and', self, other)

    def __rand__(self, other):
        return _join('and', other, self)

    def __or__(self, other):
        return _join('or', self, other)

    def __ror__(self, other):
        return _join('or', other, self)

    def __invert__(self):
        if _negatable(self):
            return Tree('not', item=self)
        raise unsupported(
            "'~' on a comparison", hint='Negate a boolean field.',
        )

    def __eq__(self, other):
        if not isinstance(other, Tree):
            return NotImplemented
        return (
            self.kind == other.kind
            and self.root == other.root
            and self.path == other.path
            and self.value == other.value
            and self.left == other.left
            and self.right == other.right
            and self.item == other.item
        )

    def __repr__(self):
        return 'Tree(%s)' % self.kind


class Symbol(object):
    """One symbolic root or a field path off it. Not stored.

    Slots stay private so a model field named ``root``, ``path``, or
    ``token`` is a hop, not the builder's bookkeeping.
    """

    __slots__ = ('_root', '_path', '_token')

    def __init__(self, root, path=(), token=None):
        object.__setattr__(self, '_root', root)
        object.__setattr__(self, '_path', tuple(path))
        object.__setattr__(self, '_token', token)

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        return Symbol(self._root, self._path + (name,), self._token)

    def __setattr__(self, name, value):
        raise unsupported('Assignment')

    def __delattr__(self, name):
        raise unsupported('Deletion')

    def _field(self):
        return Tree('field', root=self._root, path=self._path)

    def contains(self, member):
        right = _operand(member, self._token)
        if not self._path or (
            right.kind == 'field' and not right.path
            and right.root != 'inquiry'
        ):
            raise _root_rejection()
        return Tree('contains', left=self._field(), right=right)

    def __eq__(self, other):
        return Tree(
            'eq', left=self._field(), right=_operand(other, self._token),
        )

    def __ne__(self, other):
        return Tree(
            'ne', left=self._field(), right=_operand(other, self._token),
        )

    def __and__(self, other):
        return _join('and', self, other)

    def __rand__(self, other):
        return _join('and', other, self)

    def __or__(self, other):
        return _join('or', self, other)

    def __ror__(self, other):
        return _join('or', other, self)

    def __invert__(self):
        if not self._path:
            raise _root_rejection()
        return Tree('not', item=Tree('bare', item=self._field()))

    def __bool__(self):
        raise _boolean_rejection()

    def __contains__(self, item):
        raise unsupported(
            "Python 'in'", hint='Use collection.contains(member).',
        )

    def __repr__(self):
        if not self._path:
            return 'Symbol(%s)' % self._root
        return 'Symbol(%s).%s' % (self._root, '.'.join(self._path))


def _operand(value, token):
    if isinstance(value, Symbol):
        if value._token is not token:
            raise unsupported('A path from another builder')
        return value._field()
    if isinstance(value, Tree):
        raise unsupported('Comparing a condition')
    return Tree('const', value=value)


def _as_predicate(value, symbol):
    if isinstance(value, Tree) and value.kind in _PREDICATE_KINDS:
        return value
    if isinstance(value, Symbol) and value._path:
        return Tree('bare', item=value._field())
    raise unsupported(
        "'%s' on a value that is not a comparison, .contains(), or a "
        'boolean field' % symbol
    )


def _join(kind, left, right):
    symbol = '&' if kind == 'and' else '|'
    return Tree(
        kind,
        left=_as_predicate(left, symbol),
        right=_as_predicate(right, symbol),
    )


def _require_predicate(result):
    if isinstance(result, Symbol):
        if not result._path:
            raise _root_rejection()
        return Tree('bare', item=result._field())
    if isinstance(result, Tree) and result.kind in _PREDICATE_KINDS:
        return result
    raise unsupported(
        'Returning %s' % type(result).__name__, hint=_RETURN_HINT,
    )


def _negatable(node):
    """True when ``~`` may wrap ``node``.

    User rules at ``92141b0`` (``trusts/plan/standards.py`` ``Bit.__invert__``)
    accepted ``~`` on a boolean field and on ``&`` / nested ``~`` of those.
    A comparison, ``.contains()``, or ``|`` is outside that shape, including
    one nested inside ``&`` or ``|``.
    """
    if node.kind == 'bare':
        return True
    if node.kind == 'not':
        return _negatable(node.item)
    if node.kind == 'and':
        return _negatable(node.left) and _negatable(node.right)
    return False


def symbol_path(symbol):
    """Field path recorded on a ``Symbol``. Slots stay private."""
    return symbol._path


def symbol_token(symbol):
    """Builder token recorded on a ``Symbol``. Slots stay private."""
    return symbol._token


def is_inquiry(node):
    """True for the bare requested-permission root of a delegated condition."""
    return node.kind == 'field' and node.root == 'inquiry' and not node.path


def inquiry_partner(node):
    """The path matched against the requested permission, or ``None``.

    That is ``path`` in ``inquiry == path``, ``path == inquiry``, and
    ``path.contains(inquiry)``.
    """
    if node.kind == 'contains' and is_inquiry(node.right):
        return node.left
    if node.kind in ('eq', 'ne') and is_inquiry(node.left):
        return node.right
    if node.kind in ('eq', 'ne') and is_inquiry(node.right):
        return node.left
    return None


def is_predicate(node):
    """True when ``node`` is a condition this grammar can return."""
    return isinstance(node, Tree) and node.kind in _PREDICATE_KINDS


def invoke(fn, roots):
    """Call ``fn`` once with one symbol per root name. Return a predicate."""
    token = object()
    symbols = tuple(Symbol(root, token=token) for root in roots)
    try:
        result = fn(*symbols)
    except TrustsConfigurationError:
        raise
    except Exception as exc:
        raise PermissionConditionError(
            'Condition builder failed: %s' % exc
        ) from exc
    return _require_predicate(result)


for _name in _OP_LABELS:
    # Symbol keeps its own ``in`` message, which names ``.contains``.
    if _name != '__contains__':
        setattr(Symbol, _name, _unsupported(_name))
    # Stored nodes are data, not callbacks, so Tree has no ``__call__``.
    # ``t.team()`` is rejected on Symbol. Calling a finished tree is a
    # plain TypeError.
    if _name != '__call__':
        setattr(Tree, _name, _unsupported(_name))
