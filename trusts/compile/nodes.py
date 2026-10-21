"""Near-final registration nodes.

Root-relative ``Ref`` and ``Along``. Conditions are ``trusts.plan.grammar.Tree``.
"""

__all__ = []

from django.db.models.base import ModelBase

from trusts.errors import TrustsConfigurationError


def _is_model_class(value):
    return isinstance(value, ModelBase)


class Ref(object):
    """Root-relative path from one permission-bearing relation model.

    Build paths with attribute access::

        j = Ref(DocumentGrant)
        j.document  # path ('document',) on DocumentGrant

    Attribute access always builds a field ref, including names such as
    ``root`` and ``path``. Inspect the model and segments on the
    normalized ``RegisteredRelation``, not on ``Ref``.
    """

    __slots__ = ('_root', '_path')

    def __init__(self, root, path=()):
        if not _is_model_class(root):
            raise TrustsConfigurationError(
                'Ref root must be a Django model class, not %r.' % (root,)
            )
        if isinstance(path, str):
            raise TrustsConfigurationError(
                'Ref path must be a sequence of field names, not a string.'
            )
        if not isinstance(path, (tuple, list)):
            raise TrustsConfigurationError(
                'Ref path must be a sequence of field names, not %r.' % (path,)
            )
        object.__setattr__(self, '_root', root)
        object.__setattr__(self, '_path', tuple(path))

    def __getattr__(self, name):
        return Ref(self._root, self._path + (name,))

    def __setattr__(self, name, value):
        raise TrustsConfigurationError('Ref is immutable.')

    def __delattr__(self, name):
        raise TrustsConfigurationError('Ref is immutable.')

    def __eq__(self, other):
        return (
            isinstance(other, Ref)
            and self._root is other._root
            and self._path == other._path
        )

    def __hash__(self):
        return hash((self._root, self._path))

    def __repr__(self):
        if not self._path:
            return 'Ref(%s)' % self._root.__name__
        return 'Ref(%s).%s' % (self._root.__name__, '.'.join(self._path))


class Along(object):
    """Bounded directed walk that replaces equality at one walk-site.

    ``ref`` names the directed edge from the walk-site. ``bound`` is the
    maximum hop distance (1..64). Depth 0 is always included.
    """

    __slots__ = ('ref', 'bound')

    def __init__(self, ref, bound):
        object.__setattr__(self, 'ref', ref)
        object.__setattr__(self, 'bound', bound)

    def __setattr__(self, name, value):
        raise TrustsConfigurationError('Along is immutable.')

    def __delattr__(self, name):
        raise TrustsConfigurationError('Along is immutable.')

    def __eq__(self, other):
        return (
            isinstance(other, Along)
            and self.ref == other.ref
            and self.bound == other.bound
        )

    def __hash__(self):
        return hash((self.ref, self.bound))

    def __repr__(self):
        return 'Along(%r, bound=%r)' % (self.ref, self.bound)


def _require_ref(value, role):
    if not isinstance(value, Ref):
        raise TrustsConfigurationError(
            '%s must be a root-relative Ref, not %r.' % (role, value)
        )
    return value

