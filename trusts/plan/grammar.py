"""One condition grammar for register, named filters, and user rules.

The builder is not policy. Each entry point lowers the tree into the
nodes it stores. Those nodes hold field paths, normalized constants, and function
calls, not Django expressions or application callbacks. Ordered
comparisons are ``lt``, ``le``, ``gt``, and ``ge``. A function call is
``call``.

Roots are named roles (``row``, ``inquiry``, ``user``, ``object``,
``permission``), so a later user-side walk can name a root without a
second grammar. ``contains`` is a method, not a field hop.
"""

import copy

from trusts.errors import PermissionConditionError, TrustsConfigurationError
from trusts.plan.hops import path_text

# Public spelling of the reachability function. The class in
# ``trusts.functions`` uses this same word. The stored node kind is
# ``reachable``.
REACHABLE_KIND = 'reachable'
REACHABLE_NAME = 'Reachable'

_KIND_LABELS = {
    'eq': "'=='",
    'ne': "'!='",
    'lt': 'Ordered comparison',
    'le': 'Ordered comparison',
    'gt': 'Ordered comparison',
    'ge': 'Ordered comparison',
    'and': "'&'",
    'or': "'|'",
    'not': "'~'",
    'contains': '.contains()',
    'bare': 'A bare boolean field',
    'const': 'A constant',
    'call': 'An SQL function',
    REACHABLE_KIND: '%s()' % REACHABLE_NAME,
}

_RETURN_HINT = (
    'Return a comparison, %s(), .contains(), a boolean field, or a '
    "combination with '&' and '|'."
) % REACHABLE_NAME

ORDERED_KINDS = frozenset(('lt', 'le', 'gt', 'ge'))

_PREDICATE_KINDS = frozenset((
    'eq', 'ne', 'and', 'or', 'not', 'contains', 'bare', REACHABLE_KIND,
)) | ORDERED_KINDS

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

    def __deepcopy__(self, memo):
        cloned = Tree(
            self.kind,
            root=self.root,
            path=self.path,
            value=copy.deepcopy(self.value, memo),
            left=copy.deepcopy(self.left, memo),
            right=copy.deepcopy(self.right, memo),
            item=copy.deepcopy(self.item, memo),
        )
        memo[id(self)] = cloned
        return cloned

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
            "'~' on a comparison",
            hint='Negate a boolean field or %s().' % REACHABLE_NAME,
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

    def inquiry_partner(self):
        """The path matched against the requested permission, or ``None``.

        That is ``path`` in ``inquiry == path``, ``path == inquiry``, and
        ``path.contains(inquiry)``.
        """
        if self.kind == 'contains' and is_inquiry(self.right):
            return self.left
        if self.kind in ('eq', 'ne') and is_inquiry(self.left):
            return self.right
        if self.kind in ('eq', 'ne') and is_inquiry(self.right):
            return self.left
        return None

    def __repr__(self):
        return 'Tree(%s)' % self.kind


def _comparison(kind):
    def compare(self, other):
        return Tree(
            kind, left=self._field(), right=_operand(other, self._token),
        )

    return compare


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

    __eq__ = _comparison('eq')
    __ne__ = _comparison('ne')
    __lt__ = _comparison('lt')
    __le__ = _comparison('le')
    __gt__ = _comparison('gt')
    __ge__ = _comparison('ge')

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
    if type(result) is bool:
        raise PermissionConditionError(
            'A comparison returned a Python bool. Import Now, Lower, '
            'Coalesce, and %s from trusts.functions.' % REACHABLE_NAME
        )
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
    ``Reachable()`` negates the same way: unknown is not a value it returns.
    A comparison, ``.contains()``, or ``|`` is outside that shape, including
    one nested inside ``&`` or ``|``.
    """
    if node.kind in ('bare', REACHABLE_KIND):
        return True
    if node.kind == 'not':
        return _negatable(node.item)
    if node.kind == 'and':
        return _negatable(node.left) and _negatable(node.right)
    return False


def symbol_path(symbol):
    """Field path recorded on a ``Symbol``. Slots stay private."""
    return symbol._path


def symbol_root(symbol):
    """Root name recorded on a ``Symbol``. Slots stay private."""
    return symbol._root


def symbol_token(symbol):
    """Builder token recorded on a ``Symbol``. Slots stay private."""
    return symbol._token


def walk(node):
    """Every ``Tree`` in ``node``, operands and call arguments included."""
    if isinstance(node, tuple):
        for item in node:
            yield from walk(item)
    elif isinstance(node, Tree):
        yield node
        for child in (node.left, node.right, node.item):
            yield from walk(child)


def contains_call(node):
    """True when ``node`` or one of its operands is a function call."""
    return any(item.kind == 'call' for item in walk(node))


def needs_expression(node):
    """True for a comparison that compiles as one SQL expression."""
    return node.kind in ORDERED_KINDS or (
        node.kind in ('eq', 'ne') and contains_call(node)
    )


def is_inquiry(node):
    """True for the bare requested-permission root of a delegated condition."""
    return node.kind == 'field' and node.root == 'inquiry' and not node.path


def is_predicate(node):
    """True when ``node`` is a condition this grammar can return."""
    return isinstance(node, Tree) and node.kind in _PREDICATE_KINDS


def invoke(fn, roots, prepare=None):
    """Call ``fn`` once with one symbol per root name. Return a predicate.

    ``prepare(tree, token)`` runs after the predicate check, while the
    builder token still identifies every symbol from this call.
    """
    token = object()
    symbols = tuple(Symbol(root, token=token) for root in roots)
    try:
        result = fn(*symbols)
    except TrustsConfigurationError:
        raise
    except (TypeError, ValueError) as exc:
        raise PermissionConditionError(
            'Condition builder failed: %s. Import Now, Lower, Coalesce, '
            'and %s from trusts.functions.' % (exc, REACHABLE_NAME)
        ) from exc
    except Exception as exc:
        raise PermissionConditionError(
            'Condition builder failed: %s' % exc
        ) from exc
    result = _require_predicate(result)
    if prepare is None:
        return result
    return prepare(result, token)


for _name in _OP_LABELS:
    # Symbol keeps what it defines: ordering and its ``in`` message.
    # ``__hash__`` stays ``None`` because ``__eq__`` is defined.
    if _name not in Symbol.__dict__:
        setattr(Symbol, _name, _unsupported(_name))
    # Stored nodes are data, not callbacks, so Tree has no ``__call__``.
    # ``t.team()`` is rejected on Symbol. Calling a finished tree is a
    # plain TypeError. Ordering on a stored node stays rejected.
    if _name != '__call__':
        setattr(Tree, _name, _unsupported(_name))
