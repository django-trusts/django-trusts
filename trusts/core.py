"""Isolated registration and common authorization-plan compiler.

``TrustsRegistry`` validates root-relative ``Ref`` paths through Django
model ``_meta`` and stores one immutable record per relation. The same
registered records compile into one correlated relation plan. Three
projections change only the terminal: permission enumeration, object
authorization (SQL ``EXISTS`` membership over that enumeration), and
authorized-content filtering.

Import from ``trusts.core``. This slice does not re-export a process-global
registry from ``trusts``.
"""

from dataclasses import dataclass
from functools import reduce
from operator import or_

from django.apps import apps as django_apps
from django.core.exceptions import FieldDoesNotExist
from django.db.models import Exists, Model, OuterRef
from django.db.models.base import ModelBase
from django.db.models.query import QuerySet

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


_BINDING_FIELDS = {
    'user': 'user_field',
    'content': 'content_field',
    'permission': 'permission_field',
}


def _concrete_model(value):
    opts = getattr(value, '_meta', None)
    if opts is None:
        raise TrustsConfigurationError(
            'Expected a model class or instance, not %r.' % (value,)
        )
    return opts.concrete_model


def _require_instance(value, role):
    if not isinstance(value, Model):
        raise TrustsConfigurationError(
            '%s must be a model instance, not %r.' % (role, value)
        )
    return value


def _outer_ref_for_relation(root, field_name):
    """Build ``OuterRef`` for the relation's actual target field.

    Direct ``ForeignKey(..., to_field=...)`` and other single-valued
    relations may target a unique field other than the related model's
    primary key. Correlation must use that field, not assumed ``pk``.
    """
    field = root._meta.get_field(field_name)
    target = getattr(field, 'target_field', None)
    if target is None:
        raise TrustsConfigurationError(
            'Cannot correlate %s.%s; relation has no target field.'
            % (root._meta.label, field_name)
        )
    return OuterRef(target.attname)


def _content_model(content):
    if isinstance(content, QuerySet):
        return content.model._meta.concrete_model
    if _is_model_class(content):
        return content._meta.concrete_model
    if isinstance(content, Model):
        return content._meta.concrete_model
    raise TrustsConfigurationError(
        'content must be a model class, instance, or QuerySet, not %r.'
        % (content,)
    )


@dataclass(frozen=True, slots=True)
class RelationPlan:
    """One correlated plan compiled from applicable ``RegisteredRelation`` rows.

    Root selection, field correlation, and ``EXISTS`` assembly live here.
    Projection methods only choose the outer terminal or wrap ``exists()``.
    """

    records: tuple
    permission_model: type | None = None

    def _bound_root_qs(self, record, **bindings):
        filters = {}
        for role, value in bindings.items():
            _require_instance(value, role)
            filters[getattr(record, _BINDING_FIELDS[role])] = value
        return record.root._default_manager.filter(**filters)

    def _correlated_exists(self, terminal_field_attr, **bindings):
        parts = []
        for record in self.records:
            terminal = getattr(record, terminal_field_attr)
            inner = self._bound_root_qs(record, **bindings).filter(
                **{terminal: _outer_ref_for_relation(record.root, terminal)}
            )
            parts.append(Exists(inner))
        if not parts:
            return None
        if len(parts) == 1:
            return parts[0]
        return reduce(or_, parts)

    def permissions(self, user, content):
        """Distinct permission rows for ``(user, content)``."""
        user = _require_instance(user, 'user')
        content = _require_instance(content, 'content')
        if not self.records or self.permission_model is None:
            return ()
        exists = self._correlated_exists(
            'permission_field', user=user, content=content,
        )
        return self.permission_model._default_manager.filter(exists).distinct()

    def has_permission(self, user, content, permission):
        """SQL ``EXISTS`` membership of ``permission`` in ``permissions()``."""
        user = _require_instance(user, 'user')
        content = _require_instance(content, 'content')
        permission = _require_instance(permission, 'permission')
        if not self.records or self.permission_model is None:
            return False
        if permission._meta.concrete_model is not self.permission_model:
            return False
        exists = self._correlated_exists(
            'permission_field', user=user, content=content,
        )
        return self.permission_model._default_manager.filter(
            pk=permission.pk,
        ).filter(exists).exists()

    def filter_content(self, queryset, user, permission):
        """Lazy queryset of candidate rows correlated to the same plan."""
        user = _require_instance(user, 'user')
        permission = _require_instance(permission, 'permission')
        if not self.records:
            return queryset.none()
        exists = self._correlated_exists(
            'content_field', user=user, permission=permission,
        )
        return queryset.filter(exists).distinct()


class TrustsRegistry(object):
    """Instantiable registry of permission-bearing relation declarations.

    Create a new instance per isolated context. There is no process-global
    singleton in this slice. ``register`` performs zero SQL. Projection
    methods compile one shared plan from stored records.
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

    def _records_for(self, content_model, user_model=None, permission_model=None):
        chosen = []
        for record in self._order:
            if record.content_model is not content_model:
                continue
            if user_model is not None and record.user_model is not user_model:
                continue
            if (
                permission_model is not None
                and record.permission_model is not permission_model
            ):
                continue
            chosen.append(record)
        return tuple(chosen)

    def plan_for(self, content, *, user=None, permission=None):
        """Build the common relation plan for these terminals.

        ``content`` may be a model class, instance, or ``QuerySet``.
        Optional ``user`` / ``permission`` instances keep only registrations
        whose inferred terminals match those models. Construction is lazy.
        """
        content_model = _content_model(content)
        user_model = None
        if user is not None:
            user_model = _concrete_model(_require_instance(user, 'user'))
        permission_model = None
        if permission is not None:
            permission_model = _concrete_model(
                _require_instance(permission, 'permission')
            )

        records = self._records_for(content_model, user_model, permission_model)
        if records:
            models = {record.permission_model for record in records}
            if len(models) != 1:
                raise TrustsConfigurationError(
                    'Applicable registrations must share one permission '
                    'model; got %s.'
                    % ', '.join(sorted(model._meta.label for model in models))
                )
            permission_model = models.pop()
        return RelationPlan(records=records, permission_model=permission_model)

    def permissions_for(self, user, content):
        """Distinct permission rows granted to ``user`` on ``content``."""
        user = _require_instance(user, 'user')
        content = _require_instance(content, 'content')
        return self.plan_for(content, user=user).permissions(user, content)

    def has_permission(self, user, content, permission):
        """Whether ``permission`` exists in the common plan for this pair."""
        user = _require_instance(user, 'user')
        content = _require_instance(content, 'content')
        permission = _require_instance(permission, 'permission')
        return self.plan_for(
            content, user=user, permission=permission,
        ).has_permission(user, content, permission)

    def filter_authorized(self, queryset, user, permission):
        """Lazy queryset of rows ``user`` holds ``permission`` on."""
        if not isinstance(queryset, QuerySet):
            raise TrustsConfigurationError(
                'filter_authorized requires a QuerySet, not %r.' % (queryset,)
            )
        user = _require_instance(user, 'user')
        permission = _require_instance(permission, 'permission')
        return self.plan_for(
            queryset, user=user, permission=permission,
        ).filter_content(queryset, user, permission)
