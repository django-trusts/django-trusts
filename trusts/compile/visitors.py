"""Executing proxies for public ``condition=`` builders.

These nodes are not stored policy records. ``trusts.core`` does not
re-export them. The stored
``_InquiryPermissionMatch`` stays in ``trusts.compile.nodes`` with ``All``.
"""

__all__ = []

from trusts.errors import TrustsConfigurationError


_CONDITION_ARITY_PROBE = object()

_CONDITION_BOOLEAN_MESSAGE = (
    "Python 'and'/'or'/'not' and chained comparisons are unsupported "
    "on condition=; use '&' for conjunction."
)

_CONDITION_IN_MESSAGE = (
    "Python 'in' is unsupported on condition=; use "
    "collection.contains(member)."
)


def _unsupported_condition_op(name):
    def _op(self, *args, **kwargs):
        raise TrustsConfigurationError(
            'condition builder does not support %s.' % name
        )
    _op.__name__ = name
    return _op


def _condition_boolean_error(self):
    raise TrustsConfigurationError(_CONDITION_BOOLEAN_MESSAGE)


class ConditionProxy(object):
    """Trust-rooted symbolic value for public ``condition=`` builders.

    Attribute access records a path. ``contains`` is a reserved proxy
    method, not a field hop: a model field actually named ``contains``
    cannot be walked here. Path-role builders stay on ``_PathBuilder``
    and do not grow ``contains``.
    """

    __slots__ = ('_trust', '_path', '_token')

    def __init__(self, trust, path=(), token=None):
        object.__setattr__(self, '_trust', trust)
        object.__setattr__(self, '_path', tuple(path))
        object.__setattr__(self, '_token', token)

    def __getattr__(self, name):
        return ConditionProxy(self._trust, self._path + (name,), self._token)

    def __setattr__(self, name, value):
        raise TrustsConfigurationError('Condition builder is immutable.')

    def __delattr__(self, name):
        raise TrustsConfigurationError('Condition builder is immutable.')

    def contains(self, member):
        if isinstance(member, InquiryPermissionProxy):
            if not self._path:
                raise TrustsConfigurationError(
                    'condition .contains collection returned an empty path.'
                )
            return ConditionInquiryMatch(self)
        if not isinstance(member, ConditionProxy):
            raise TrustsConfigurationError(
                'condition .contains member must be a path rooted at the '
                'supplied trust value, not %r.' % (member,)
            )
        if member._token is not self._token:
            raise TrustsConfigurationError(
                'condition .contains used a path from another symbolic root.'
            )
        if not self._path:
            raise TrustsConfigurationError(
                'condition .contains collection returned an empty path.'
            )
        if not member._path:
            raise TrustsConfigurationError(
                'condition .contains member returned an empty path.'
            )
        return ConditionIn(self, member)

    def __eq__(self, other):
        if isinstance(other, InquiryPermissionProxy):
            if not self._path:
                raise TrustsConfigurationError(
                    'condition equality returned an empty path.'
                )
            return ConditionInquiryMatch(self)
        if not isinstance(other, ConditionProxy):
            raise TrustsConfigurationError(
                'condition equality requires two trust-rooted paths, '
                'not %r.' % (other,)
            )
        if other._token is not self._token:
            raise TrustsConfigurationError(
                'condition equality used a path from another symbolic root.'
            )
        if not self._path or not other._path:
            raise TrustsConfigurationError(
                'condition equality returned an empty path.'
            )
        return ConditionEq(self, other)

    def __contains__(self, item):
        raise TrustsConfigurationError(_CONDITION_IN_MESSAGE)

    def __and__(self, other):
        raise TrustsConfigurationError(
            'condition conjunction requires equality or .contains '
            'operands, not a bare path.'
        )

    def __rand__(self, other):
        raise TrustsConfigurationError(
            'condition conjunction requires equality or .contains '
            'operands, not a bare path.'
        )

    def __repr__(self):
        root = getattr(self._trust, '__name__', self._trust)
        if not self._path:
            return 'ConditionProxy(%s)' % root
        return 'ConditionProxy(%s).%s' % (root, '.'.join(self._path))


class ConditionEq(object):
    """Private executing-proxy equality node. Not a stored policy record."""

    __slots__ = ('left', 'right')

    def __init__(self, left, right):
        object.__setattr__(self, 'left', left)
        object.__setattr__(self, 'right', right)

    def __and__(self, other):
        return _condition_and(self, other)

    def __rand__(self, other):
        return _condition_and(other, self)


class ConditionIn(object):
    """Private executing-proxy membership node. Not a stored policy record."""

    __slots__ = ('collection', 'member')

    def __init__(self, collection, member):
        object.__setattr__(self, 'collection', collection)
        object.__setattr__(self, 'member', member)

    def __and__(self, other):
        return _condition_and(self, other)

    def __rand__(self, other):
        return _condition_and(other, self)


class InquiryPermissionProxy(object):
    """Symbolic requested permission for delegated conditions."""

    __slots__ = ('_token',)

    def __init__(self, token):
        object.__setattr__(self, '_token', token)

    def __getattr__(self, name):
        raise TrustsConfigurationError(
            'requested permission is a symbolic terminal and has no '
            'traversable attributes.'
        )

    def __eq__(self, other):
        if isinstance(other, ConditionProxy) and other._path:
            return ConditionInquiryMatch(other)
        raise TrustsConfigurationError(
            'requested permission equality requires one relationship path.'
        )

    def __bool__(self):
        raise TrustsConfigurationError(_CONDITION_BOOLEAN_MESSAGE)

    def __setattr__(self, name, value):
        raise TrustsConfigurationError('Requested permission is immutable.')

    def __delattr__(self, name):
        raise TrustsConfigurationError('Requested permission is immutable.')


class ConditionInquiryMatch(object):
    """Private executing proxy for ``row_path == p`` or contains(p)."""

    __slots__ = ('path',)

    def __init__(self, path):
        object.__setattr__(self, 'path', path)

    def __and__(self, other):
        return _condition_and(self, other)

    def __rand__(self, other):
        return _condition_and(other, self)


class ConditionAnd(object):
    """Private executing-proxy conjunction. Flattened to ``All`` on store."""

    __slots__ = ('left', 'right')

    def __init__(self, left, right):
        object.__setattr__(self, 'left', left)
        object.__setattr__(self, 'right', right)

    def __and__(self, other):
        return _condition_and(self, other)

    def __rand__(self, other):
        return _condition_and(other, self)


_CONDITION_EXPR_TYPES = (
    ConditionEq, ConditionIn, ConditionInquiryMatch, ConditionAnd,
)


def _condition_and(left, right):
    if not isinstance(left, _CONDITION_EXPR_TYPES):
        raise TrustsConfigurationError(
            'condition conjunction requires equality or .contains '
            'operands, not %r.' % (left,)
        )
    if not isinstance(right, _CONDITION_EXPR_TYPES):
        raise TrustsConfigurationError(
            'condition conjunction requires equality or .contains '
            'operands, not %r.' % (right,)
        )
    return ConditionAnd(left, right)


for _name in (
    '__ne__', '__lt__', '__le__', '__gt__', '__ge__',
    '__hash__', '__len__',
    '__getitem__', '__setitem__', '__delitem__',
    '__call__', '__iter__', '__next__',
    '__add__', '__radd__', '__sub__', '__rsub__',
    '__mul__', '__rmul__', '__truediv__', '__rtruediv__',
    '__floordiv__', '__rfloordiv__', '__mod__', '__rmod__', '__pow__',
    '__or__', '__ror__',
    '__xor__', '__rxor__', '__invert__',
    '__lshift__', '__rlshift__', '__rshift__', '__rrshift__',
    '__neg__', '__pos__', '__abs__',
    '__int__', '__float__', '__index__',
    '__enter__', '__exit__',
    '__await__', '__aenter__', '__aexit__',
):
    setattr(ConditionProxy, _name, _unsupported_condition_op(_name))

ConditionProxy.__bool__ = _condition_boolean_error

for _cls in _CONDITION_EXPR_TYPES:
    for _name in (
        '__ne__', '__lt__', '__le__', '__gt__', '__ge__',
        '__hash__', '__len__', '__contains__',
        '__getitem__', '__setitem__', '__delitem__',
        '__call__', '__iter__', '__next__',
        '__add__', '__radd__', '__sub__', '__rsub__',
        '__mul__', '__rmul__', '__truediv__', '__rtruediv__',
        '__floordiv__', '__rfloordiv__', '__mod__', '__rmod__', '__pow__',
        '__or__', '__ror__',
        '__xor__', '__rxor__', '__invert__',
        '__lshift__', '__rlshift__', '__rshift__', '__rrshift__',
        '__neg__', '__pos__', '__abs__',
        '__int__', '__float__', '__index__',
        '__enter__', '__exit__',
        '__await__', '__aenter__', '__aexit__',
    ):
        setattr(_cls, _name, _unsupported_condition_op(_name))
    _cls.__bool__ = _condition_boolean_error
    _cls.__setattr__ = ConditionProxy.__setattr__
    _cls.__delattr__ = ConditionProxy.__delattr__
