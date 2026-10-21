"""Private condition language (issue #4 V1 / #142 Stage B).

This module is not an application-facing import. It parses and checks
a builder. Python evaluation and the queryset ``Q`` live in
``trusts.plan.writers``. Register named conditions as builders on the
recorder's ``add_named_filter``. The stored node is
``trusts.plan.grammar.Tree``.

A callable argument to condition registration is a **builder**: Core
invokes it exactly once with symbolic ``(u, p, o)`` refs, validates the
returned predicate, normalizes constants into durable IR, and stores
only that IR. The callable is discarded from the policy record and is
never invoked during ``has_perm``, enumeration, or queryset filtering.

Builders are trusted startup/configuration code, the same class as
``AppConfig.ready()``. Core does not sandbox them. Core's own
registration path issues zero SQL (symbolic refs plus ``_meta``).

Prebuilt trees are not accepted at register.
``parse_named_filter`` is the entry point: one builder in, one checked
tree out. The caller stores that tree.

Permission-condition records live on an instantiable
``ConditionRegistry`` (also exposed on each built registry and the
recorder's ``add_named_filter``).

V1 grammar: principal/object field refs and relationship traversal
(``_meta`` fields on the content model and the entity/user model; not
Python properties); literal constants; ``==`` / ``!=``; nested ``&`` /
``|``; ``.contains()`` on a forward many-to-many; a bare boolean field;
and ``~`` on a boolean field or on ``&`` / ``|``. Operand types must
match without Django field coercion:
``CharField`` compares to ``str``, relations compare to model identity
(not raw primary keys). Missing attribute names fail closed; they are
not treated as ``NULL``. Python ``and`` / ``or`` / ``not`` and chained
comparisons cannot be overloaded and raise
``PermissionConditionError``.
"""

__all__ = []

from datetime import date, datetime, time, timedelta
from decimal import Decimal
from io import IOBase
from uuid import UUID

from django.core.exceptions import FieldDoesNotExist
from django.contrib.auth.models import Permission
from django.db.models import (
    Manager,
    Model,
    QuerySet,
    Subquery,
    BinaryField,
    BooleanField,
    CharField,
    DateField,
    DateTimeField,
    DecimalField,
    DurationField,
    FloatField,
    IntegerField,
    TextField,
    TimeField,
    UUIDField,
)
from django.apps import apps as django_apps
from django.conf import settings as django_settings
from django.db.backends.base.base import BaseDatabaseWrapper
from django.db.models.fields import GenericIPAddressField
from django.http import HttpRequest
from django.utils.functional import Promise, SimpleLazyObject

from trusts.plan.grammar import (
    Tree,
    invoke,
    is_predicate,
    missing_field,
    unsupported,
)
from trusts.errors import PermissionConditionError


def get_short_model_name_lower(klass):
    if isinstance(klass, str):
        return klass.lower()
    if issubclass(klass, Model):
        return '%s.%s' % (klass._meta.app_label.lower(), klass._meta.model_name)
    return ''


def parse_perm_code(perm):
    """Split ``app.action_model`` plus an optional ``:condition`` suffix.

    The condition is partitioned first so condition codes may contain
    underscores (``app.change_ticket:own_item``). This is a parse-order
    fix, not a new permission form.
    """
    applabel, rest = perm.split('.', 1)
    rest, _sep, cond = rest.partition(':')
    action, modelname = rest.rsplit('_', 1)
    return applabel, modelname, action, cond


def permission_binding(perm, model):
    """Unevaluated ``auth.Permission`` pk for a codename string.

    A ``Permission`` instance is returned unchanged.
    """
    if isinstance(perm, Permission):
        return perm
    applabel, modelname, action, _cond = parse_perm_code(perm)
    return Subquery(
        Permission.objects.filter(
            codename='%s_%s' % (action, modelname),
            content_type__app_label=applabel.lower(),
            content_type__model=modelname,
        ).values('pk')[:1]
    )


def permission_has_condition(perm):
    """True when ``perm`` is a string with a ``:condition`` suffix."""
    return isinstance(perm, str) and ':' in perm


def permission_condition_code(perm):
    """Return the ``:condition`` suffix, or ``''`` when absent."""
    if not isinstance(perm, str) or ':' not in perm:
        return ''
    if '.' in perm:
        try:
            return parse_perm_code(perm)[3]
        except ValueError:
            pass
    return perm.split(':', 1)[1]


def obsolete_legacy_callback_setting_enabled():
    """True when the deleted runtime-callback setting is still ``True``.

    The setting no longer enables object-only callbacks. A True value is
    a configuration error (``trusts.E007``). Missing or False is quiet.
    Read at call time so ``override_settings`` works.
    """

    return bool(getattr(
        django_settings, 'TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS', False
    ))


def _node(node, *kinds):
    return isinstance(node, Tree) and node.kind in kinds


class ModelIdentity(object):
    """Durable saved-instance constant: ``(app_label, model_name, pk)``.

    Stored instead of a live model instance so later mutation or
    ``refresh_from_db()`` cannot change policy.
    """

    __slots__ = ('app_label', 'model_name', 'pk')

    def __init__(self, app_label, model_name, pk):
        self.app_label = app_label
        self.model_name = model_name
        self.pk = pk

    def as_tuple(self):
        return (self.app_label, self.model_name, self.pk)

    def __eq__(self, other):
        if isinstance(other, Model):
            meta = other._meta.concrete_model._meta
            return (
                meta.app_label == self.app_label
                and meta.model_name == self.model_name
                and other.pk == self.pk
            )
        return NotImplemented

    def __hash__(self):
        return hash(self.as_tuple())

    def __repr__(self):
        return 'ModelIdentity(%r, %r, %r)' % (
            self.app_label, self.model_name, self.pk,
        )


_SCALAR_CONSTANT_TYPES = (
    type(None), bool, int, float, str, bytes,
    Decimal, UUID, datetime, date, time, timedelta,
)


def _is_allowed_scalar(value):
    return value is None or isinstance(value, _SCALAR_CONSTANT_TYPES)


def _reject_forbidden_constant(value):
    """Raise if ``value`` cannot be snapshotted into durable IR."""
    if isinstance(value, Model):
        state = getattr(value, '_state', None)
        adding = getattr(state, 'adding', False)
        if adding or value.pk is None:
            raise PermissionConditionError(
                'Unsaved model instances cannot be captured in a permission '
                'condition; save the instance first so it has a primary key.'
            )
        return
    if isinstance(value, QuerySet):
        raise unsupported('A QuerySet constant', 'a named filter')
    if isinstance(value, Manager):
        raise unsupported('A Manager constant', 'a named filter')
    if isinstance(value, (list, dict, set, tuple, frozenset)):
        raise unsupported(
            'A %s constant' % type(value).__name__, 'a named filter',
        )
    if isinstance(value, IOBase):
        raise unsupported('A file or stream constant', 'a named filter')
    if isinstance(value, HttpRequest):
        raise unsupported('An HttpRequest constant', 'a named filter')
    if isinstance(value, Promise):
        raise unsupported('A lazy promise constant', 'a named filter')
    if isinstance(value, SimpleLazyObject):
        raise unsupported('A SimpleLazyObject constant', 'a named filter')
    if isinstance(value, BaseDatabaseWrapper):
        raise unsupported('A database connection constant', 'a named filter')
    if callable(value) and not isinstance(value, type) and not isinstance(value, Model):
        raise unsupported('A callable constant', 'a named filter')
    if not _is_allowed_scalar(value) and not isinstance(value, (Model, ModelIdentity)):
        raise unsupported(
            'A %s constant' % type(value).__name__, 'a named filter',
        )


def normalize_constant(value):
    """Copy an allowed constant into durable IR, or reject it."""
    if isinstance(value, ModelIdentity):
        return value
    _reject_forbidden_constant(value)
    if isinstance(value, Model):
        meta = value._meta.concrete_model._meta
        return ModelIdentity(meta.app_label, meta.model_name, value.pk)
    return value


def normalize_expression(node):
    """Return a tree whose constants are durable values."""
    if _node(node, 'and', 'or', 'eq', 'ne', 'contains'):
        left = normalize_expression(node.left)
        right = normalize_expression(node.right)
        if left is node.left and right is node.right:
            return node
        return Tree(node.kind, left=left, right=right)
    if _node(node, 'not', 'bare'):
        item = normalize_expression(node.item)
        if item is node.item:
            return node
        return Tree(node.kind, item=item)
    if _node(node, 'const'):
        value = normalize_constant(node.value)
        if value is node.value:
            return node
        return Tree('const', value=value)
    return node


def _collection_terminal(field, last, collection):
    """Forward many-to-many allowed as the last hop of ``.contains()``."""
    return (
        last
        and collection
        and field.many_to_many
        and not getattr(field, 'auto_created', False)
    )


def resolve_field_path(model, path, ref_kind='object', *, collection=False):
    """Validate ``path`` against ``model`` and return the Django lookup string.

    Relationship traversal is allowed; a non-relational field may only appear
    as the last component. ``collection`` allows that last component to be a
    forward many-to-many, which is the left side of ``.contains()``. Missing
    names raise ``PermissionConditionError`` rather than resolving to ``None``.
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
            raise missing_field(ref_kind, path[:i + 1], name, current)
        last = i == len(path) - 1
        if (field.many_to_many or field.one_to_many) and not _collection_terminal(
            field, last, collection,
        ):
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


def _terminal_field(model, path, ref_kind='object', *, collection=False):
    resolve_field_path(
        model, path, ref_kind=ref_kind, collection=collection,
    )
    current = model
    field = None
    for i, name in enumerate(path):
        field = current._meta.get_field(name)
        if i != len(path) - 1:
            current = field.remote_field.model
    return field


def _concrete_model(model):
    meta = getattr(model, '_meta', None)
    if meta is not None:
        return meta.concrete_model
    return model


def _models_compatible(left, right):
    left = _concrete_model(left)
    right = _concrete_model(right)
    return (
        left is right or
        issubclass(left, right) or
        issubclass(right, left)
    )


def _scalar_types_for_field(field):
    if isinstance(field, BooleanField):
        return (bool,)
    if isinstance(field, IntegerField):
        return (int,)
    if isinstance(field, FloatField):
        return (float, int)
    if isinstance(field, DecimalField):
        return (Decimal,)
    if isinstance(field, (CharField, TextField, GenericIPAddressField)):
        return (str,)
    if isinstance(field, UUIDField):
        return (UUID,)
    if isinstance(field, DateTimeField):
        return (datetime,)
    if isinstance(field, DateField):
        return (date,)
    if isinstance(field, TimeField):
        return (time,)
    if isinstance(field, DurationField):
        return (timedelta,)
    if isinstance(field, BinaryField):
        return (bytes,)
    return ()


def _spec_from_field(field):
    if field.is_relation and not field.many_to_many and not field.one_to_many:
        related = field.related_model
        return ('instance', related, '%s %s' % (field.get_internal_type(), field.name))
    types = _scalar_types_for_field(field)
    return ('scalar', types, '%s %s' % (field.get_internal_type(), field.name))


def _model_from_identity(identity):

    return django_apps.get_model(identity.app_label, identity.model_name)


def _spec_from_const(value):
    if value is None:
        return ('null', None, 'None')
    if isinstance(value, ModelIdentity):
        model = _model_from_identity(value)
        return ('instance', model, model._meta.label)
    if isinstance(value, Model):
        return ('instance', value.__class__, value._meta.label)
    if isinstance(value, bool):
        return ('scalar', (bool,), 'bool')
    if isinstance(value, int):
        return ('scalar', (int,), 'int')
    if isinstance(value, float):
        return ('scalar', (float,), 'float')
    if isinstance(value, str):
        return ('scalar', (str,), 'str')
    if isinstance(value, bytes):
        return ('scalar', (bytes,), 'bytes')
    if isinstance(value, Decimal):
        return ('scalar', (Decimal,), 'Decimal')
    if isinstance(value, UUID):
        return ('scalar', (UUID,), 'UUID')
    if isinstance(value, datetime):
        return ('scalar', (datetime,), 'datetime')
    if isinstance(value, date):
        return ('scalar', (date,), 'date')
    if isinstance(value, time):
        return ('scalar', (time,), 'time')
    if isinstance(value, timedelta):
        return ('scalar', (timedelta,), 'timedelta')
    return ('scalar', (type(value),), type(value).__name__)


def _operand_spec(node, model, user_model):
    if _node(node, 'const'):
        return _spec_from_const(node.value)
    if _node(node, 'field'):
        if node.root == 'object':
            return _spec_from_field(_terminal_field(model, node.path, 'object'))
        if node.root == 'user':
            entity = user_model
            if not node.path:
                return ('instance', entity, entity._meta.label)
            return _spec_from_field(
                _terminal_field(entity, node.path, 'principal')
            )
        if node.root == 'permission':
            return ('scalar', (str,), 'permission')
    raise PermissionConditionError(
        'Cannot type-check permission condition node %r.' % (node,)
    )


def _specs_compatible(left, right):
    if left[0] == 'null' or right[0] == 'null':
        return True
    if left[0] == 'instance' and right[0] == 'instance':
        return _models_compatible(left[1], right[1])
    if left[0] == 'scalar' and right[0] == 'scalar':
        return bool(set(left[1]) & set(right[1]))
    return False


def _check_comparison_types(node, model, user_model):
    left = _operand_spec(node.left, model, user_model)
    right = _operand_spec(node.right, model, user_model)
    if _specs_compatible(left, right):
        return
    raise PermissionConditionError(
        'Permission condition compares incompatible types (%s vs %s). '
        'V1 does not coerce literals through Django field preparation; '
        'CharField values are strings, and relations compare to model '
        'instances (not raw primary keys).' % (left[2], right[2])
    )


def _check_member_spec(spec, related):
    if spec[0] == 'null':
        return
    if spec[0] == 'instance' and _models_compatible(spec[1], related):
        return
    if _specs_compatible(spec, _spec_from_field(related._meta.pk)):
        return
    raise PermissionConditionError(
        'Permission condition .contains() member is incompatible with '
        '%s (%s).' % (related._meta.label, spec[2])
    )


def _validate_contains(node, model, user_model):
    left = node.left
    right = node.right
    if not _node(left, 'field') or left.root not in ('object', 'user'):
        raise PermissionConditionError(
            'Malformed permission condition node %r.' % (node,)
        )
    host = model if left.root == 'object' else user_model
    ref = 'object' if left.root == 'object' else 'principal'
    collection = _terminal_field(
        host, left.path, ref, collection=True,
    )
    related = collection.remote_field.model
    if _node(right, 'const'):
        if right.value is not None:
            _check_member_spec(_spec_from_const(right.value), related)
        return
    if not _node(right, 'field'):
        raise PermissionConditionError(
            'Malformed permission condition node %r.' % (node,)
        )
    _validate_node(right, model, user_model)
    _check_member_spec(_operand_spec(right, model, user_model), related)


def _validate_bare(node, model, user_model):
    item = node.item
    if (
        not _node(item, 'field')
        or item.root not in ('object', 'user')
        or not item.path
    ):
        raise PermissionConditionError(
            'Malformed permission condition node %r.' % (node,)
        )
    host = model if item.root == 'object' else user_model
    ref = 'object' if item.root == 'object' else 'principal'
    field = _terminal_field(host, item.path, ref)
    if not isinstance(field, BooleanField):
        raise PermissionConditionError(
            'A bare field in a named filter must be a boolean, not %s.%s.'
            % (host._meta.label, field.name)
        )


def validate_expression(node, model, user_model=None):
    """Resolve paths and require comparable operand types on ``Eq`` / ``Ne``.

    Object paths are validated against ``model``; principal paths against
    the entity model. Incompatible field/literal pairs (for example
    ``CharField`` vs ``int``, or a ``ForeignKey`` vs a raw PK) raise
    ``PermissionConditionError`` so Django lookup coercion cannot make
    ``has_perm`` and ``.permitted()`` diverge.
    """
    if not is_predicate(node):
        raise PermissionConditionError(
            'Permission condition did not produce a comparison, '
            '.contains(), or boolean field.'
        )
    _validate_node(node, model, user_model)


def _validate_node(node, model, user_model):
    if _node(node, 'and', 'or'):
        _validate_node(node.left, model, user_model)
        _validate_node(node.right, model, user_model)
        return
    if _node(node, 'eq', 'ne'):
        _validate_node(node.left, model, user_model)
        _validate_node(node.right, model, user_model)
        _check_comparison_types(node, model, user_model)
        return
    if _node(node, 'contains'):
        _validate_contains(node, model, user_model)
        return
    if _node(node, 'bare'):
        _validate_bare(node, model, user_model)
        return
    if _node(node, 'not'):
        _validate_node(node.item, model, user_model)
        return
    if _node(node, 'const'):
        return
    if _node(node, 'field'):
        if node.root == 'object':
            resolve_field_path(model, node.path, ref_kind='object')
        elif node.root == 'user':
            if node.path:
                resolve_field_path(
                    user_model, node.path, ref_kind='principal',
                )
        elif node.root == 'permission':
            if node.path:
                raise PermissionConditionError(
                    'Permission references cannot traverse attributes in V1.'
                )
        return
    raise PermissionConditionError(
        'Malformed permission condition node %r.' % (node,)
    )



def _condition_model_key(model):
    meta = getattr(model, '_meta', None)
    if meta is not None:
        return meta.label
    return model


def _unknown_condition_error(model, cond_code):
    meta = getattr(model, '_meta', None)
    if meta is not None:
        return AttributeError(
            'Permission condition code "%s" is not associate with model "%s_%s"'
            % (cond_code, meta.app_label, meta.model_name)
        )
    return AttributeError(
        'Permission condition code "%s" is not associate with model "%s"'
        % (cond_code, model)
    )


def _condition_model_label(model):
    meta = getattr(model, '_meta', None)
    if meta is not None:
        return meta.label
    return repr(model)


def _lower_named(node):
    """Keep the shared tree when a named filter can store it."""
    kind = node.kind
    if kind in ('field', 'const'):
        return node
    if kind in ('eq', 'ne', 'and', 'or', 'contains'):
        _lower_named(node.left)
        _lower_named(node.right)
        return node
    if kind in ('not', 'bare'):
        _lower_named(node.item)
        return node
    raise unsupported(kind, 'a named filter')


def _invoke_condition_builder(builder, model, cond_code):
    """Invoke a trusted builder once and lower it into stored nodes."""
    result = invoke(builder, ('user', 'permission', 'object'))
    try:
        return _lower_named(result)
    except PermissionConditionError as exc:
        raise PermissionConditionError(
            'Permission condition %r on %s: %s'
            % (cond_code, _condition_model_label(model), exc)
        ) from exc


def parse_named_filter(builder, model, code, user_model):
    """Return the checked tree for one named-filter builder.

    The builder runs once. Constants are normalized into durable
    values. When ``model`` has ``_meta``, field paths and operand
    types are checked against that model and ``user_model``.
    """
    expr = normalize_expression(
        _invoke_condition_builder(builder, model, code),
    )
    if getattr(model, '_meta', None) is not None:
        validate_expression(expr, model, user_model)
    return expr


class ConditionRecord(object):
    """Registered condition: normalized declarative IR only.

    ``model`` is retained so a registration can be validated by the
    system check after all apps have loaded. This record is
    implementation-neutral: it does not name Zero nouns. The builder
    callable is never stored.
    """

    __slots__ = ('expr', 'model')

    def __init__(self, expr=None, model=None):
        self.expr = expr
        self.model = model


class ConditionRegistry(object):
    """Per-instance store of permission-condition records.

    Create a new instance per isolated context. There is no
    process-global singleton. Records are keyed by model identity plus
    condition code on *this* instance, so two registries never share or
    overwrite each other.

    A callable argument is a registration-time builder: invoked once
    with symbolic refs, then discarded. A prebuilt ``Tree`` raises
    ``TypeError`` before this store is mutated.
    """

    def __init__(self, user_model=None):
        self.user_model = user_model
        self._records = {}

    def register_permission_condition(self, model, cond_code, condition, user_model=None):
        """Register a ``:cond_code`` condition on ``model``.

        Pass a builder ``callable(u, p, o)`` that returns a V1
        comparison. Core invokes it exactly once with symbolic refs,
        normalizes constants, and stores only IR.

        A prebuilt ``Tree`` raises ``TypeError`` before any record is
        stored. Non-callables also raise ``TypeError``.
        """
        if isinstance(condition, Tree) or not callable(condition):
            raise TypeError(
                'register_permission_condition expected a builder callable, '
                'got %r.' % (type(condition).__name__,)
            )
        key = (_condition_model_key(model), cond_code)
        if key in self._records:
            raise PermissionConditionError(
                'Named filter %r is already registered on %s.'
                % (cond_code, _condition_model_label(model))
            )
        expr = parse_named_filter(condition, model, cond_code, user_model)
        record = ConditionRecord(expr=expr, model=model)
        self._records[key] = record
        return record

    def get_permission_condition_record(self, model, cond_code):
        """Return the record for ``(model, cond_code)``, or ``None``."""
        return self._records.get((_condition_model_key(model), cond_code))

    def iter_permission_conditions(self):
        """Yield ``(model, cond_code, record)`` for every registration.

        Identity comes from the record so registrations remain
        validatable without importing extra application modules.
        """
        for (_key, cond_code), record in self._records.items():
            yield record.model, cond_code, record


class FrozenConditionLookup(object):
    """Condition rows frozen at ``build()``.

    The rows are a tuple taken once from the factory store. This lookup
    does not share that mutable store.
    """

    __slots__ = ('_index',)

    def __init__(self, rows):
        self._index = {
            (_condition_model_key(model), code): record
            for model, code, record in rows
        }

    def record_for(self, model, cond_code):
        return self._index.get((_condition_model_key(model), cond_code))
