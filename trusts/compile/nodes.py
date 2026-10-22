"""Near-final registration nodes.

Root-relative ``Ref``, ``Along``, and the closed predicates ``Equal``,
``PermissionIn``, ``_InquiryPermissionMatch``, and ``All``. ``trusts.core``
re-exports ``Ref``, ``Equal``, ``PermissionIn``, ``All``, and
``permission_in``. The condition-IR ``Ref`` in
``trusts.plan.conditions`` is a different type and is not imported here.
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

    def require_same_root(self, root, role):
        if self._root is not root:
            raise TrustsConfigurationError(
                '%s must share the registration root %s; got %s.'
                % (role, root._meta.label, self._root._meta.label)
            )
        return self


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


def _is_condition_operand(value):
    """True for an internal ``Ref`` or a public Django ``__`` path string."""
    return isinstance(value, (str, Ref))


class Equal(object):
    """Closed equality of two root-relative single-valued refs.

    Isolated registry tests may pass ``Ref`` operands. Public
    ``register(*, trust=..., condition=...)`` does not accept a prebuilt
    ``Equal``; it lowers a trust-rooted ``==`` expression to this node.
    """

    __slots__ = ('left', 'right')

    def __init__(self, left, right):
        if not _is_condition_operand(left) or not _is_condition_operand(right):
            raise TrustsConfigurationError(
                'Equal left and right must be root-relative Refs or Django '
                'path strings, not %r and %r.' % (left, right)
            )
        object.__setattr__(self, 'left', left)
        object.__setattr__(self, 'right', right)

    def __setattr__(self, name, value):
        raise TrustsConfigurationError('Equal is immutable.')

    def __delattr__(self, name):
        raise TrustsConfigurationError('Equal is immutable.')

    def __eq__(self, other):
        return (
            isinstance(other, Equal)
            and self.left == other.left
            and self.right == other.right
        )

    def __hash__(self):
        return hash((Equal, self.left, self.right))

    def __repr__(self):
        return 'Equal(%r, %r)' % (self.left, self.right)

    def accept(self, visitor):
        return visitor.visit_equal(self)


class PermissionIn(object):
    """Closed membership of the registered permission in one or more refs."""

    __slots__ = ('refs',)

    def __init__(self, *refs):
        if not refs:
            raise TrustsConfigurationError(
                'permission_in requires one or more refs.'
            )
        for ref in refs:
            if not _is_condition_operand(ref):
                raise TrustsConfigurationError(
                    'permission_in refs must be root-relative Refs or Django '
                    'path strings, not %r.' % (ref,)
                )
        object.__setattr__(self, 'refs', refs)

    def __setattr__(self, name, value):
        raise TrustsConfigurationError('permission_in is immutable.')

    def __delattr__(self, name):
        raise TrustsConfigurationError('permission_in is immutable.')

    def __eq__(self, other):
        return isinstance(other, PermissionIn) and self.refs == other.refs

    def __hash__(self):
        return hash((PermissionIn, self.refs))

    def __repr__(self):
        return 'permission_in(%s)' % ', '.join(repr(ref) for ref in self.refs)

    def accept(self, visitor):
        return visitor.visit_permission_in(self)


permission_in = PermissionIn


class _InquiryPermissionMatch(object):
    """Closed match between one relationship path and inquiry permission.

    This node is produced only by a two-argument delegated ``condition=``
    builder. It is deliberately private: application code supplies the
    symbolic expression, never a prebuilt node.
    """

    __slots__ = ('ref',)

    def __init__(self, ref):
        if not _is_condition_operand(ref):
            raise TrustsConfigurationError(
                'inquiry permission match requires one root-relative Ref, '
                'not %r.' % (ref,)
            )
        object.__setattr__(self, 'ref', ref)

    def __setattr__(self, name, value):
        raise TrustsConfigurationError('Inquiry permission match is immutable.')

    def __delattr__(self, name):
        raise TrustsConfigurationError('Inquiry permission match is immutable.')

    def __eq__(self, other):
        return (
            isinstance(other, _InquiryPermissionMatch)
            and self.ref == other.ref
        )

    def __hash__(self):
        return hash((_InquiryPermissionMatch, self.ref))

    def __repr__(self):
        return 'inquiry_permission_match(%r)' % (self.ref,)

    def accept(self, visitor):
        return visitor.visit_inquiry_permission_match(self)


class All(object):
    """Closed AND of one or more typed predicate nodes."""

    __slots__ = ('predicates',)

    def __init__(self, *predicates):
        if not predicates:
            raise TrustsConfigurationError(
                'All requires one or more predicates.'
            )
        for predicate in predicates:
            if not isinstance(
                predicate, (All, Equal, PermissionIn, _InquiryPermissionMatch)
            ):
                raise TrustsConfigurationError(
                    'All predicates must be All, Equal, permission_in, or '
                    'an inquiry-permission match '
                    'nodes, not %r.' % (predicate,)
                )
        object.__setattr__(self, 'predicates', predicates)

    def __setattr__(self, name, value):
        raise TrustsConfigurationError('All is immutable.')

    def __delattr__(self, name):
        raise TrustsConfigurationError('All is immutable.')

    def __eq__(self, other):
        return (
            isinstance(other, All)
            and self.predicates == other.predicates
        )

    def __hash__(self):
        return hash((All, self.predicates))

    def __repr__(self):
        return 'All(%s)' % ', '.join(repr(pred) for pred in self.predicates)

    def accept(self, visitor):
        return visitor.visit_all(self)


def _require_ref(value, role):
    if not isinstance(value, Ref):
        raise TrustsConfigurationError(
            '%s must be a root-relative Ref, not %r.' % (role, value)
        )
    return value


def _require_same_root(ref, root, role):
    ref = _require_ref(ref, role)
    return ref.require_same_root(root, role)

