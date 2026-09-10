"""Isolated registration primitive for permission-bearing relations.

This module is registration only: it validates root-relative ``Ref`` paths
through Django model ``_meta`` and stores one immutable record per relation.
It does not compile queries, run SQL, or change authorization results.

Import from ``trusts.core``. This slice does not re-export a process-global
registry from ``trusts``.
"""

from dataclasses import dataclass

from django.apps import apps as django_apps
from django.core.exceptions import FieldDoesNotExist
from django.db.models.base import ModelBase

try:
    from django.contrib.contenttypes.fields import GenericForeignKey, GenericRelation
except ImportError:  # pragma: no cover - contenttypes is a Django contrib app
    GenericForeignKey = type('GenericForeignKey', (), {})
    GenericRelation = type('GenericRelation', (), {})


class TrustsConfigurationError(Exception):
    """Malformed or unsupported ``TrustsRegistry`` registration."""


def _is_model_class(value):
    return isinstance(value, ModelBase)


def _classify_field(field):
    if isinstance(field, (GenericForeignKey, GenericRelation)):
        return 'gfk'
    if not getattr(field, 'is_relation', False):
        return 'scalar'
    if getattr(field, 'many_to_many', False) or getattr(field, 'one_to_many', False):
        return 'multi'
    if getattr(field, 'auto_created', False) and not getattr(field, 'concrete', False):
        return 'reverse'
    if getattr(field, 'one_to_one', False) and not getattr(field, 'concrete', False):
        return 'reverse'
    related = getattr(field, 'related_model', None)
    if related is None:
        return 'gfk'
    return 'single'


def _path_text(path):
    return '.'.join(path)


def _terminal_model(field):
    related = getattr(field, 'related_model', None)
    if _is_model_class(related):
        return related
    if isinstance(related, str):
        try:
            return django_apps.get_model(related)
        except (LookupError, ValueError):
            return None
    return None


def _resolve_direct_path(root, path, role):
    if not path:
        raise TrustsConfigurationError(
            '%s must be a non-empty root-relative path from %s.'
            % (role, root._meta.label)
        )

    current = root
    field = None
    related = None
    for index, name in enumerate(path):
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist:
            raise TrustsConfigurationError(
                '%s path %r refers to missing field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )

        kind = _classify_field(field)
        if kind == 'scalar':
            raise TrustsConfigurationError(
                '%s path %r traverses scalar field %r on %s; only direct '
                'single-valued relations are supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind == 'multi':
            raise TrustsConfigurationError(
                '%s path %r uses multi-valued field %r on %s; multi-valued '
                'and reverse traversals are not supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind == 'reverse':
            raise TrustsConfigurationError(
                '%s path %r uses reverse relation %r on %s; multi-valued '
                'and reverse traversals are not supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind == 'gfk':
            raise TrustsConfigurationError(
                '%s path %r uses a generic foreign key %r on %s; generic '
                'foreign keys are not supported.'
                % (role, _path_text(path), name, current._meta.label)
            )

        related = _terminal_model(field)
        if not _is_model_class(related):
            raise TrustsConfigurationError(
                '%s path %r does not terminate on a model.'
                % (role, _path_text(path))
            )
        if index != len(path) - 1:
            current = related

    if len(path) != 1:
        raise TrustsConfigurationError(
            '%s path %r is not a direct single-valued relation; only '
            'direct paths are supported.'
            % (role, _path_text(path))
        )
    return tuple(path), related, field.name


def _require_ref(value, role):
    if not isinstance(value, Ref):
        raise TrustsConfigurationError(
            '%s must be a root-relative Ref, not %r.' % (role, value)
        )
    return value


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


@dataclass(frozen=True, slots=True)
class RegisteredRelation:
    """Immutable normalized record for one permission-bearing relation."""

    root: type
    content_path: tuple
    content_model: type
    content_field: str
    user_path: tuple
    user_model: type
    user_field: str
    permission_path: tuple
    permission_model: type
    permission_field: str
    condition: None = None


class TrustsRegistry(object):
    """Instantiable registry of permission-bearing relation declarations.

    Create a new instance per isolated context. There is no process-global
    singleton in this slice. ``register`` performs zero SQL.
    """

    def __init__(self):
        self._by_root = {}
        self._order = []

    @property
    def records(self):
        return tuple(self._order)

    def get(self, root):
        try:
            return self._by_root[root]
        except KeyError:
            raise TrustsConfigurationError(
                'No registration for %r.' % (getattr(root, '__name__', root),)
            )

    def register(self, *, content, user, permission, condition=None):
        """Register one permission-bearing relation from root-relative refs.

        Duplicate registration of the same root with an identical normalized
        record raises ``TrustsConfigurationError``. A second registration of
        the same root with a different normalized record is a conflict and
        also raises ``TrustsConfigurationError``. Both outcomes are
        deterministic: the first stored record is left unchanged.
        """
        if condition is not None:
            raise TrustsConfigurationError(
                'condition is not supported; omit it or pass None.'
            )

        content_ref = _require_ref(content, 'content')
        user_ref = _require_ref(user, 'user')
        permission_ref = _require_ref(permission, 'permission')

        roots = (content_ref._root, user_ref._root, permission_ref._root)
        if len(set(roots)) != 1:
            raise TrustsConfigurationError(
                'All refs in one registration must share the same root model; '
                'got %s.' % ', '.join(root._meta.label for root in roots)
            )
        root = roots[0]

        content_path, content_model, content_field = _resolve_direct_path(
            root, content_ref._path, 'content'
        )
        user_path, user_model, user_field = _resolve_direct_path(
            root, user_ref._path, 'user'
        )
        permission_path, permission_model, permission_field = _resolve_direct_path(
            root, permission_ref._path, 'permission'
        )

        record = RegisteredRelation(
            root=root,
            content_path=content_path,
            content_model=content_model,
            content_field=content_field,
            user_path=user_path,
            user_model=user_model,
            user_field=user_field,
            permission_path=permission_path,
            permission_model=permission_model,
            permission_field=permission_field,
            condition=None,
        )

        existing = self._by_root.get(root)
        if existing is not None:
            if existing == record:
                raise TrustsConfigurationError(
                    'Duplicate registration for %s.' % root._meta.label
                )
            raise TrustsConfigurationError(
                'Conflicting registration for %s: existing %r, new %r.'
                % (root._meta.label, existing, record)
            )

        self._by_root[root] = record
        self._order.append(record)
        return record
