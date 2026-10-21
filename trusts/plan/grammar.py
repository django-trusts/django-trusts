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

BOOLEAN_MESSAGE = (
    "Python 'and'/'or'/'not' and chained comparisons are unsupported "
    "in a condition; use '&' for conjunction and '|' for disjunction."
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


def _unsupported(name):
    label = _OP_LABELS.get(name, name)

    def _op(self, *args, **kwargs):
        raise PermissionConditionError(
            '%s is not supported in a condition.' % label
        )

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
        raise PermissionConditionError('A condition is immutable.')

    def __delattr__(self, name):
        raise PermissionConditionError('A condition is immutable.')

    def __bool__(self):
        raise PermissionConditionError(BOOLEAN_MESSAGE)

    def __and__(self, other):
        return _join('and', self, other)

    def __rand__(self, other):
        return _join('and', other, self)

    def __or__(self, other):
        return _join('or', self, other)

    def __ror__(self, other):
        return _join('or', other, self)

    def __invert__(self):
        if self.kind in ('bare', 'and', 'or', 'not'):
            return Tree('not', item=self)
        raise PermissionConditionError(
            "'~' is not supported on a comparison. Negate a boolean field."
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
        raise PermissionConditionError(
            'Assignment is not supported in a condition.'
        )

    def __delattr__(self, name):
        raise PermissionConditionError(
            'Deletion is not supported in a condition.'
        )

    def _field(self):
        return Tree('field', root=self._root, path=self._path)

    def contains(self, member):
        if not self._path:
            raise PermissionConditionError(
                'contains collection returned an empty path.'
            )
        right = _operand(member, self._token)
        if (
            isinstance(right, Tree)
            and right.kind == 'field'
            and not right.path
            and right.root != 'inquiry'
        ):
            raise PermissionConditionError(
                'contains member returned an empty path.'
            )
        if not _is_value(right):
            raise PermissionConditionError(
                'contains member must be a path or a constant, not %r.'
                % (member,)
            )
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
            raise PermissionConditionError(
                'A condition must name a field, not the root.'
            )
        return Tree('not', item=Tree('bare', item=self._field()))

    def __bool__(self):
        raise PermissionConditionError(BOOLEAN_MESSAGE)

    def __contains__(self, item):
        raise PermissionConditionError(
            "Python 'in' is unsupported in a condition; "
            "use collection.contains(member)."
        )

    def __repr__(self):
        if not self._path:
            return 'Symbol(%s)' % self._root
        return 'Symbol(%s).%s' % (self._root, '.'.join(self._path))


def _is_value(node):
    return (
        isinstance(node, Tree)
        and node.kind in ('field', 'const')
    )


def _operand(value, token):
    if isinstance(value, Symbol):
        if value._token is not token:
            raise PermissionConditionError(
                'A condition used a path from another symbolic root.'
            )
        return value._field()
    if isinstance(value, Tree):
        if value.kind in ('field', 'const'):
            return value
        raise PermissionConditionError(
            'A condition compares field paths and constants, not %r.'
            % (value,)
        )
    return Tree('const', value=value)


def _as_predicate(value, symbol):
    if isinstance(value, Tree) and value.kind in _PREDICATE_KINDS:
        return value
    if isinstance(value, Symbol) and value._path:
        return Tree('bare', item=value._field())
    raise PermissionConditionError(
        "'%s' joins comparisons, .contains, or boolean fields, not %r."
        % (symbol, value)
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
            raise PermissionConditionError(
                'A condition must name a field, not the root.'
            )
        return Tree('bare', item=result._field())
    if isinstance(result, Tree) and result.kind in _PREDICATE_KINDS:
        return result
    if isinstance(result, bool):
        raise PermissionConditionError(
            'A condition returned a boolean. Return a comparison, '
            '.contains, a boolean field, or a combination with & and |.'
        )
    raise PermissionConditionError(
        'A condition must compare values, call .contains, combine them '
        'with & or |, or name a boolean field, not %r.' % (result,)
    )


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
