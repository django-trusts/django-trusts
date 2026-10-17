"""Path recording for ``register()`` and resolved ``Along`` walks.

``_PathBuilder`` is the symbolic ``trust=`` value. ``AlongWalk`` is the
immutable walk metadata stored on a registration. ``trusts.core``
re-exports both.
"""

__all__ = []

from dataclasses import dataclass

from trusts.errors import TrustsConfigurationError


@dataclass(frozen=True, slots=True)
class AlongWalk:
    """Immutable walk metadata resolved from ``Along`` at ``register()``."""

    path: tuple
    bound: int
    shape: str
    walk_path: tuple
    walk_model: type
    walk_ident: str
    walk_field: str
    suffix_path: tuple
    suffix_field: str
    ident_family: str
    parent_attname: str | None
    edge_model: type | None
    edge_parent_attname: str | None
    edge_child_attname: str | None
    rewrite_attname: str | None


class _PathBuilder(object):
    """Symbolic attribute-recording value rooted at one ``register()`` call.

    Public typing presents this object as the ``trust=`` model. Runtime
    records attribute names only; it does not load a row or prove that
    an attribute exists.
    """

    __slots__ = ('_trust', '_path', '_token')

    def __init__(self, trust, path=(), token=None):
        object.__setattr__(self, '_trust', trust)
        object.__setattr__(self, '_path', tuple(path))
        object.__setattr__(self, '_token', token)

    def __getattr__(self, name):
        return _PathBuilder(self._trust, self._path + (name,), self._token)

    def __setattr__(self, name, value):
        raise TrustsConfigurationError('Path builder is immutable.')

    def __delattr__(self, name):
        raise TrustsConfigurationError('Path builder is immutable.')

    def __repr__(self):
        root = getattr(self._trust, '__name__', self._trust)
        if not self._path:
            return 'PathBuilder(%s)' % root
        return 'PathBuilder(%s).%s' % (root, '.'.join(self._path))


def _unsupported_path_builder_op(name):
    def _op(self, *args, **kwargs):
        raise TrustsConfigurationError(
            'Path builder does not support %s.' % name
        )
    _op.__name__ = name
    return _op


for _name in (
    '__eq__', '__ne__', '__lt__', '__le__', '__gt__', '__ge__',
    '__hash__', '__bool__', '__len__', '__contains__',
    '__getitem__', '__setitem__', '__delitem__',
    '__call__', '__iter__', '__next__',
    '__add__', '__radd__', '__sub__', '__rsub__',
    '__mul__', '__rmul__', '__truediv__', '__rtruediv__',
    '__floordiv__', '__rfloordiv__', '__mod__', '__rmod__', '__pow__',
    '__or__', '__ror__', '__and__', '__rand__',
    '__xor__', '__rxor__', '__invert__',
    '__lshift__', '__rlshift__', '__rshift__', '__rrshift__',
    '__neg__', '__pos__', '__abs__',
    '__int__', '__float__', '__index__',
    '__enter__', '__exit__',
    '__await__', '__aenter__', '__aexit__',
):
    setattr(_PathBuilder, _name, _unsupported_path_builder_op(_name))

