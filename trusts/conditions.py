"""Restricted declarative permission conditions (issue #4 V1 / #142 A).

Register a named condition as a **trusted startup builder** (lambda or
``def``). Core invokes it once with symbolic ``(u, p, o)``, validates
and normalizes the returned predicate, and stores only IR. The callable
is not the policy record and is never invoked during ``has_perm``,
enumeration, or queryset filtering. A transitional prebuilt ``Expr`` is
still accepted in Stage A so unconverted Zero Meta trees keep loading.

Builders are trusted configuration, not a sandbox: Core does not parse
AST/bytecode and cannot stop a named function from querying or doing
I/O. Core-owned registration itself adds zero SQL.

Permission-condition records live on an instantiable
``ConditionRegistry`` (also exposed on each ``TrustsRegistry``). There
is no process-global store: each implementation handle owns its own
records so owners cannot share or overwrite each other.

V1 grammar: principal/object field refs and relationship traversal
(``_meta`` fields on the content model and the entity/user model; not
Python properties); normalized constants; ``==`` / ``!=``; nested ``&``
/ ``|``. Operand types must match without Django field coercion.
Missing attribute names fail closed at registration. Python ``and`` /
``or`` / ``not`` and chained comparisons raise
``PermissionConditionBooleanError``.
"""

from django.core.exceptions import FieldDoesNotExist, ObjectDoesNotExist
from django.db.models import options as model_options
from django.db.models import (
    F,
    Model,
    Q,
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
from django.db.models.fields import GenericIPAddressField


class PermissionConditionError(Exception):
    """Unsupported or malformed declarative permission condition.

    Fail closed: never ignore the condition and return the underlying grant.
    """


class PermissionConditionBooleanError(PermissionConditionError):
    """Raised when a symbolic condition is truth-tested (``and`` / ``or`` / ``not``)."""


class PermissionConditionUnsupported(PermissionConditionError):
    """Raised for operations outside the V1 grammar (calls, indexing, arithmetic)."""


class PermissionConditionNotQueryable(ValueError):
    """Raised when a SQL list/create filter cannot compile a ``:condition``.

    Generic core exception. Import this name from ``trusts.conditions``.
    """


def _ensure_permission_conditions_option():
    """Register generic ``Meta.permission_conditions`` idempotently.

    Must run at import, before Django constructs participating model
    classes. Repeated import/setup must not duplicate the name.
    """
    names = model_options.DEFAULT_NAMES
    if 'permission_conditions' in names:
        return
    if isinstance(names, tuple):
        model_options.DEFAULT_NAMES = names + ('permission_conditions',)
    else:
        names.append('permission_conditions')


_ensure_permission_conditions_option()


def permission_has_condition(perm):
    """True when ``perm`` is a string with a ``:condition`` suffix."""
    return isinstance(perm, str) and ':' in perm


def permission_condition_code(perm):
    """Return the ``:condition`` suffix, or ``''`` when absent."""
    if not isinstance(perm, str) or ':' not in perm:
        return ''
    if '.' in perm:
        try:
            from trusts import utils
            return utils.parse_perm_code(perm)[3]
        except ValueError:
            pass
    return perm.split(':', 1)[1]


def leftover_legacy_callback_setting_enabled():
    """True when the removed callback setting is still set.

    The setting never enables runtime callbacks. System checks report it
    as ``trusts.E007``. Read at call time so ``override_settings`` works.
    """
    from django.conf import settings as django_settings

    return bool(getattr(
        django_settings, 'TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS', False
    ))


_BOOLEAN_ERROR_MESSAGE = (
    "Python 'and'/'or'/'not' cannot be used in permission conditions "
    "because they cannot be overloaded; chained comparisons such as "
    "`0 < o.amount < 100` also truth-test a symbolic node. Use '&' and "
    "'|' for conjunction and disjunction, and '!=' instead of combining "
    "'not' with '=='."
)

_LITERAL_TYPES = (type(None), bool, int, float, str, bytes)


def _boolean_error():
    raise PermissionConditionBooleanError(_BOOLEAN_ERROR_MESSAGE)


def _unsupported(what):
    raise PermissionConditionUnsupported(
        '%s is not supported in declarative permission conditions.' % what
    )


class Expr(object):
    """Node in a permission-condition expression tree."""

    def __eq__(self, other):
        return Eq(self, as_node(other))

    def __ne__(self, other):
        return Ne(self, as_node(other))

    def __and__(self, other):
        return _bool_op(And, self, as_node(other), '&')

    def __or__(self, other):
        return _bool_op(Or, self, as_node(other), '|')

    def __rand__(self, other):
        return _bool_op(And, as_node(other), self, '&')

    def __ror__(self, other):
        return _bool_op(Or, as_node(other), self, '|')

    def __bool__(self):
        _boolean_error()

    def __call__(self, *args, **kwargs):
        _unsupported('Function or method calls')

    def __getitem__(self, key):
        _unsupported('Indexing')

    def __iter__(self):
        _unsupported('Iteration')

    def __add__(self, other):
        _unsupported('Arithmetic')

    def __radd__(self, other):
        _unsupported('Arithmetic')

    def __sub__(self, other):
        _unsupported('Arithmetic')

    def __rsub__(self, other):
        _unsupported('Arithmetic')

    def __mul__(self, other):
        _unsupported('Arithmetic')

    def __rmul__(self, other):
        _unsupported('Arithmetic')

    def __truediv__(self, other):
        _unsupported('Arithmetic')

    def __rtruediv__(self, other):
        _unsupported('Arithmetic')

    def __floordiv__(self, other):
        _unsupported('Arithmetic')

    def __mod__(self, other):
        _unsupported('Arithmetic')

    def __pow__(self, other):
        _unsupported('Arithmetic')

    def __lt__(self, other):
        return _Ordering('lt', self, as_node(other))

    def __le__(self, other):
        return _Ordering('le', self, as_node(other))

    def __gt__(self, other):
        return _Ordering('gt', self, as_node(other))

    def __ge__(self, other):
        return _Ordering('ge', self, as_node(other))

    def __setitem__(self, key, value):
        _unsupported('Item assignment')

    def __invert__(self):
        _unsupported("Unary '~' / 'not'")

    def __contains__(self, item):
        _unsupported("'in' tests")

    def __hash__(self):
        return id(self)

    def to_tuple(self):
        raise NotImplementedError


class Ref(Expr):
    """Symbolic principal, permission, or object reference, with optional path."""

    def __init__(self, source, path=()):
        if source not in ('principal', 'permission', 'object'):
            raise PermissionConditionError('Unknown reference source %r.' % (source,))
        self.source = source
        self.path = tuple(path)

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        return Ref(self.source, self.path + (name,))

    def __setattr__(self, name, value):
        if name in ('source', 'path'):
            object.__setattr__(self, name, value)
            return
        _unsupported('Assignment to symbolic fields')

    def __delattr__(self, name):
        _unsupported('Deletion of symbolic fields')

    def to_tuple(self):
        return ('ref', self.source, self.path)

    def __repr__(self):
        name = {'principal': 'u', 'permission': 'p', 'object': 'o'}[self.source]
        if not self.path:
            return name
        return '%s.%s' % (name, '.'.join(self.path))


class ModelIdentity(object):
    """Durable saved-model constant: concrete model identity plus PK.

    Not a live instance. Equality compares ``(app_label, model_name, pk)``
    so later mutation of a captured Python object cannot change policy.
    """

    __slots__ = ('app_label', 'model_name', 'pk')

    def __init__(self, app_label, model_name, pk):
        self.app_label = app_label
        self.model_name = model_name
        self.pk = pk

    def __eq__(self, other):
        if other is None:
            return False
        if isinstance(other, ModelIdentity):
            return (
                self.app_label, self.model_name, self.pk
            ) == (other.app_label, other.model_name, other.pk)
        if isinstance(other, Model):
            meta = other._meta.concrete_model._meta
            return (
                self.app_label, self.model_name, self.pk
            ) == (meta.app_label, meta.model_name, other.pk)
        return False

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.app_label, self.model_name, self.pk))

    def __repr__(self):
        return 'ModelIdentity(%s.%s, pk=%r)' % (
            self.app_label, self.model_name, self.pk,
        )


class Const(Expr):
    def __init__(self, value):
        self.value = value

    def to_tuple(self):
        if isinstance(self.value, ModelIdentity):
            return (
                'const',
                ('model', self.value.app_label, self.value.model_name, self.value.pk),
            )
        return ('const', self.value)

    def __repr__(self):
        return repr(self.value)


class Eq(Expr):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def to_tuple(self):
        return ('eq', self.left.to_tuple(), self.right.to_tuple())

    def __repr__(self):
        return '(%r == %r)' % (self.left, self.right)


class Ne(Expr):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def to_tuple(self):
        return ('ne', self.left.to_tuple(), self.right.to_tuple())

    def __repr__(self):
        return '(%r != %r)' % (self.left, self.right)


class And(Expr):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def to_tuple(self):
        return ('and', self.left.to_tuple(), self.right.to_tuple())

    def __repr__(self):
        return '(%r & %r)' % (self.left, self.right)


class Or(Expr):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def to_tuple(self):
        return ('or', self.left.to_tuple(), self.right.to_tuple())

    def __repr__(self):
        return '(%r | %r)' % (self.left, self.right)


class _Ordering(Expr):
    """Ordering comparison node so chained ``a < b < c`` hits ``__bool__``.

    Not part of the V1 grammar. Registering one as a condition is rejected.
    """

    def __init__(self, op, left, right):
        self.op = op
        self.left = left
        self.right = right

    def to_tuple(self):
        return (self.op, self.left.to_tuple(), self.right.to_tuple())

    def __repr__(self):
        symbols = {'lt': '<', 'le': '<=', 'gt': '>', 'ge': '>='}
        return '(%r %s %r)' % (self.left, symbols.get(self.op, self.op), self.right)


def is_predicate(node):
    return isinstance(node, (Eq, Ne, And, Or))


_IMMUTABLE_EXTRA = None


def _immutable_extra_types():
    global _IMMUTABLE_EXTRA
    if _IMMUTABLE_EXTRA is None:
        from datetime import date, datetime, time, timedelta
        from decimal import Decimal
        from uuid import UUID

        _IMMUTABLE_EXTRA = (Decimal, UUID, datetime, date, time, timedelta)
    return _IMMUTABLE_EXTRA


def _normalize_const_value(value):
    """Copy an allowed constant into durable IR, or raise.

    Scalars are stored by value. A saved model instance becomes
    ``ModelIdentity``. Mutable, lazy, request, queryset, and unsaved
    captures are rejected so later Python mutation cannot change policy.
    """
    if isinstance(value, ModelIdentity):
        return value
    if isinstance(value, _LITERAL_TYPES):
        return value
    if isinstance(value, _immutable_extra_types()):
        return value
    if isinstance(value, Model):
        adding = getattr(getattr(value, '_state', None), 'adding', True)
        if adding or value.pk is None:
            raise PermissionConditionError(
                'Unsaved model instance cannot be a permission-condition '
                'constant; save it and register the identity (model + pk).'
            )
        meta = value._meta.concrete_model._meta
        return ModelIdentity(meta.app_label, meta.model_name, value.pk)

    from django.db.models.manager import BaseManager
    from django.db.models.query import QuerySet
    from django.http import HttpRequest
    from django.utils.functional import LazyObject, Promise

    if isinstance(value, (list, dict, set, bytearray)):
        raise PermissionConditionError(
            'Mutable container %s cannot be a permission-condition '
            'constant; snapshot an immutable scalar or saved model.'
            % type(value).__name__
        )
    if isinstance(value, (QuerySet, BaseManager)):
        raise PermissionConditionError(
            'QuerySet/Manager captures cannot be permission-condition '
            'constants.'
        )
    if isinstance(value, (HttpRequest, LazyObject, Promise)):
        raise PermissionConditionError(
            'Lazy or request objects cannot be permission-condition '
            'constants.'
        )
    if callable(value) and not isinstance(value, type):
        raise PermissionConditionError(
            'Callables cannot be permission-condition constants.'
        )
    raise PermissionConditionError(
        'Constant of type %s is not a durable permission-condition value.'
        % type(value).__name__
    )


def normalize_expression(node):
    """Rewrite ``Const`` values to durable IR; keep identical nodes when possible."""
    if isinstance(node, Const):
        normalized = _normalize_const_value(node.value)
        if normalized is node.value:
            return node
        return Const(normalized)
    if isinstance(node, (Eq, Ne, And, Or)):
        left = normalize_expression(node.left)
        right = normalize_expression(node.right)
        if left is node.left and right is node.right:
            return node
        return type(node)(left, right)
    if isinstance(node, Ref):
        return node
    return node


def as_node(value):
    if isinstance(value, Expr):
        return value
    if isinstance(value, ModelIdentity):
        return Const(value)
    if isinstance(value, _LITERAL_TYPES):
        return Const(_normalize_const_value(value))
    if isinstance(value, _immutable_extra_types()):
        return Const(value)
    if isinstance(value, Model):
        return Const(_normalize_const_value(value))
    _unsupported('Constant of type %s' % type(value).__name__)


def _bool_op(cls, left, right, op):
    if not is_predicate(left) or not is_predicate(right):
        raise PermissionConditionUnsupported(
            "'%s' requires comparison operands (for example "
            "`(u == o.owner) %s (o.status != 'locked')`)." % (op, op)
        )
    return cls(left, right)


def principal_ref():
    return Ref('principal')


def permission_ref():
    return Ref('permission')


def object_ref():
    return Ref('object')


def condition_refs():
    """Return symbolic ``(u, p, o)`` for building a registered ``Expr``.

    Combine the refs with ``==`` / ``!=`` / ``&`` / ``|`` and pass the
    resulting tree to ``TrustsRegistry.register_permission_condition``
    (or ``ConditionRegistry.register_permission_condition``). These
    objects are policy data, not live principals or content rows.
    """
    return principal_ref(), permission_ref(), object_ref()


class _QueryNamespace(object):
    """Controlled lookup namespace for declarative permission conditions.

    Not a Django ``QuerySet``. V1 equality uses ``==`` / ``!=`` on
    ``condition_refs()``. Future relational operations (Django-style
    lookup names such as ``iexact`` or ``in``) belong here so they are
    not added as ad-hoc methods on ``Ref``. V1 does not implement those
    lookups.
    """

    def __getattr__(self, name):
        if name.startswith('_'):
            raise AttributeError(name)
        raise PermissionConditionUnsupported(
            'TQ.%s is not implemented in V1 permission conditions. '
            'The implemented grammar is field refs, constants, ==, !=, '
            '& and |. Additional lookups will be added to this namespace '
            'explicitly.' % name
        )

    def __repr__(self):
        return 'TQ'


Query = _QueryNamespace()
TQ = Query


def _entity_model():
    from django.contrib.auth import get_user_model
    return get_user_model()


def resolve_field_path(model, path, ref_kind='object'):
    """Validate ``path`` against ``model`` and return the Django lookup string.

    Relationship traversal is allowed; a non-relational field may only appear
    as the last component. Missing names raise ``PermissionConditionError``
    rather than resolving to ``None``.
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
            raise PermissionConditionError(
                'Permission condition field %r is not on model %s '
                '(path %s).' % (
                    name,
                    current._meta.label,
                    '.'.join(path[:i + 1]),
                )
            )
        if field.many_to_many or field.one_to_many:
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
        last = i == len(path) - 1
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


def _terminal_field(model, path, ref_kind='object'):
    resolve_field_path(model, path, ref_kind=ref_kind)
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
        from decimal import Decimal
        return (Decimal,)
    if isinstance(field, (CharField, TextField, GenericIPAddressField)):
        return (str,)
    if isinstance(field, UUIDField):
        from uuid import UUID
        return (UUID,)
    if isinstance(field, DateTimeField):
        from datetime import datetime
        return (datetime,)
    if isinstance(field, DateField):
        from datetime import date
        return (date,)
    if isinstance(field, TimeField):
        from datetime import time
        return (time,)
    if isinstance(field, DurationField):
        from datetime import timedelta
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


def _spec_from_const(value):
    if value is None:
        return ('null', None, 'None')
    if isinstance(value, ModelIdentity):
        from django.apps import apps as django_apps

        model = django_apps.get_model(value.app_label, value.model_name)
        return ('instance', model, '%s.%s' % (value.app_label, value.model_name))
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
    return ('scalar', (type(value),), type(value).__name__)


def _operand_spec(node, model):
    if isinstance(node, Const):
        return _spec_from_const(node.value)
    if isinstance(node, Ref):
        if node.source == 'object':
            return _spec_from_field(_terminal_field(model, node.path, 'object'))
        if node.source == 'principal':
            if not node.path:
                entity = _entity_model()
                return ('instance', entity, entity._meta.label)
            return _spec_from_field(
                _terminal_field(_entity_model(), node.path, 'principal')
            )
        if node.source == 'permission':
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


def _check_comparison_types(node, model):
    left = _operand_spec(node.left, model)
    right = _operand_spec(node.right, model)
    if _specs_compatible(left, right):
        return
    raise PermissionConditionError(
        'Permission condition compares incompatible types (%s vs %s). '
        'V1 does not coerce literals through Django field preparation; '
        'CharField values are strings, and relations compare to model '
        'instances (not raw primary keys).' % (left[2], right[2])
    )


def validate_expression(node, model):
    """Resolve paths and require comparable operand types on ``Eq`` / ``Ne``.

    Object paths are validated against ``model``; principal paths against
    the entity model. Incompatible field/literal pairs (for example
    ``CharField`` vs ``int``, or a ``ForeignKey`` vs a raw PK) raise
    ``PermissionConditionError`` so Django lookup coercion cannot make
    ``has_perm`` and ``.permitted()`` diverge.
    """
    if not is_predicate(node):
        raise PermissionConditionError(
            'Permission condition did not produce a comparison expression.'
        )
    _validate_node(node, model)


def _validate_node(node, model):
    if isinstance(node, (And, Or)):
        _validate_node(node.left, model)
        _validate_node(node.right, model)
        return
    if isinstance(node, (Eq, Ne)):
        _validate_node(node.left, model)
        _validate_node(node.right, model)
        _check_comparison_types(node, model)
        return
    if isinstance(node, Const):
        return
    if isinstance(node, Ref):
        if node.source == 'object':
            resolve_field_path(model, node.path, ref_kind='object')
        elif node.source == 'principal':
            if node.path:
                resolve_field_path(_entity_model(), node.path, ref_kind='principal')
        elif node.source == 'permission':
            if node.path:
                raise PermissionConditionError(
                    'Permission references cannot traverse attributes in V1.'
                )
        return
    raise PermissionConditionError(
        'Malformed permission condition node %r.' % (node,)
    )


def _walk_model_path(instance, model, path):
    """Follow a ``_meta`` field path on ``instance``.

    A missing field name raises ``PermissionConditionError``. A legitimate
    nullable relation (or a missing reverse one-to-one) resolves to ``None``.
    Python properties are not consulted: only model fields.
    """
    current = instance
    current_model = model
    for i, name in enumerate(path):
        try:
            field = current_model._meta.get_field(name)
        except FieldDoesNotExist:
            raise PermissionConditionError(
                'Permission condition field %r is not on model %s '
                '(path %s).' % (
                    name,
                    current_model._meta.label,
                    '.'.join(path[:i + 1]),
                )
            )
        last = i == len(path) - 1
        if field.many_to_many or field.one_to_many:
            raise PermissionConditionError(
                'Multi-valued relation %r on %s is not supported in V1 '
                'permission conditions (path %s). ManyToManyField and '
                'reverse one-to-many membership is not defined; '
                'has_perm and permitted both reject these refs.' % (
                    name,
                    current_model._meta.label,
                    '.'.join(path[:i + 1]),
                )
            )
        if not last and not field.is_relation:
            raise PermissionConditionError(
                'Cannot traverse field %r on %s in a permission '
                'condition; relationship traversal requires a '
                'ForeignKey or OneToOneField.' % (
                    name, current_model._meta.label
                )
            )
        if current is None:
            return None
        if field.is_relation and not field.many_to_many and not field.one_to_many:
            try:
                current = getattr(current, field.name)
            except ObjectDoesNotExist:
                current = None
            if not last:
                current_model = field.remote_field.model
            continue
        current = getattr(current, field.attname)
    return current


def _resolve_runtime(node, user, perm, obj, model):
    if isinstance(node, Const):
        return node.value
    if isinstance(node, Ref):
        if node.source == 'principal':
            if not node.path:
                return user
            return _walk_model_path(user, _entity_model(), node.path)
        if node.source == 'permission':
            if node.path:
                raise PermissionConditionError(
                    'Permission references cannot traverse attributes in V1.'
                )
            return perm
        if node.source == 'object':
            return _walk_model_path(obj, model, node.path)
    raise PermissionConditionError(
        'Cannot evaluate permission condition node %r.' % (node,)
    )


def _values_equal(left, right):
    """Equality that honors ``ModelIdentity`` from either side."""
    if isinstance(left, ModelIdentity):
        return left == right
    if isinstance(right, ModelIdentity):
        return right == left
    return left == right


def evaluate_expression(node, user, perm, obj, model=None):
    """Evaluate a captured expression against a real principal/permission/object."""
    if model is None:
        model = obj.__class__
    if isinstance(node, And):
        return evaluate_expression(node.left, user, perm, obj, model) and (
            evaluate_expression(node.right, user, perm, obj, model)
        )
    if isinstance(node, Or):
        return evaluate_expression(node.left, user, perm, obj, model) or (
            evaluate_expression(node.right, user, perm, obj, model)
        )
    if isinstance(node, Eq):
        return _values_equal(
            _resolve_runtime(node.left, user, perm, obj, model),
            _resolve_runtime(node.right, user, perm, obj, model),
        )
    if isinstance(node, Ne):
        return not _values_equal(
            _resolve_runtime(node.left, user, perm, obj, model),
            _resolve_runtime(node.right, user, perm, obj, model),
        )
    raise PermissionConditionError(
        'Permission condition did not produce a comparison expression.'
    )


class _Bound(object):
    def __init__(self, value):
        self.value = value


class _Unbound(object):
    def __init__(self, lookup):
        self.lookup = lookup


def _classify(node, model, user, perm):
    if isinstance(node, Const):
        return _Bound(node.value)
    if isinstance(node, Ref):
        if node.source == 'object':
            return _Unbound(resolve_object_field_path(model, node.path))
        if node.source == 'principal':
            if not node.path:
                return _Bound(user)
            return _Bound(_walk_model_path(user, _entity_model(), node.path))
        if node.source == 'permission':
            if node.path:
                raise PermissionConditionError(
                    'Permission references cannot traverse attributes in V1.'
                )
            return _Bound(perm)
    raise PermissionConditionError(
        'Cannot compile permission condition node %r.' % (node,)
    )


def _always_true():
    return Q()


def _always_false():
    return Q(pk__in=())


def _sql_const(value):
    if isinstance(value, ModelIdentity):
        return value.pk
    return value


def _q_eq_lookup(lookup, value):
    value = _sql_const(value)
    if value is None:
        return Q(**{'%s__isnull' % lookup: True})
    return Q(**{lookup: value})


def _q_ne_lookup(lookup, value):
    # Match Python: ``None != x`` is True when ``x is not None``.
    value = _sql_const(value)
    if value is None:
        return Q(**{'%s__isnull' % lookup: False})
    return Q(**{'%s__isnull' % lookup: True}) | ~Q(**{lookup: value})


def _q_eq_fields(a, b):
    # Python ``None == None`` is True; SQL ``NULL = NULL`` is not.
    return (
        (Q(**{'%s__isnull' % a: True}) & Q(**{'%s__isnull' % b: True})) |
        (
            Q(**{'%s__isnull' % a: False}) &
            Q(**{'%s__isnull' % b: False}) &
            Q(**{a: F(b)})
        )
    )


def _q_ne_fields(a, b):
    return (
        (Q(**{'%s__isnull' % a: True}) & Q(**{'%s__isnull' % b: False})) |
        (Q(**{'%s__isnull' % a: False}) & Q(**{'%s__isnull' % b: True})) |
        (
            Q(**{'%s__isnull' % a: False}) &
            Q(**{'%s__isnull' % b: False}) &
            ~Q(**{a: F(b)})
        )
    )


def _compile_comparison(node, model, user, perm):
    left = _classify(node.left, model, user, perm)
    right = _classify(node.right, model, user, perm)
    equal = isinstance(node, Eq)
    if isinstance(left, _Bound) and isinstance(right, _Bound):
        matches = _values_equal(left.value, right.value)
        if not equal:
            matches = not matches
        return _always_true() if matches else _always_false()
    if isinstance(left, _Unbound) and isinstance(right, _Bound):
        lookup, value = left.lookup, right.value
    elif isinstance(left, _Bound) and isinstance(right, _Unbound):
        lookup, value = right.lookup, left.value
    else:
        a, b = left.lookup, right.lookup
        return _q_eq_fields(a, b) if equal else _q_ne_fields(a, b)
    return _q_eq_lookup(lookup, value) if equal else _q_ne_lookup(lookup, value)


def compile_to_q(node, model, user, perm):
    """Compile an expression tree to a Django ``Q`` for ``model`` rows."""
    if isinstance(node, And):
        return compile_to_q(node.left, model, user, perm) & compile_to_q(
            node.right, model, user, perm
        )
    if isinstance(node, Or):
        return compile_to_q(node.left, model, user, perm) | compile_to_q(
            node.right, model, user, perm
        )
    if isinstance(node, (Eq, Ne)):
        return _compile_comparison(node, model, user, perm)
    raise PermissionConditionError(
        'Permission condition did not produce a comparison expression.'
    )


def compile_expression_q(expr, model, user, perm):
    """Compile a registered ``Expr`` to ``Q``. Fail closed if invalid."""
    if not is_predicate(expr):
        raise PermissionConditionError(
            'Permission condition did not produce a V1 comparison '
            'expression (==, !=, &, | over principal and object fields).'
        )
    validate_expression(expr, model)
    return compile_to_q(expr, model, user, perm)


def evaluate_registered_expression(expr, user, perm, obj, model=None):
    """Evaluate a registered ``Expr`` against a real principal/object."""
    if not is_predicate(expr):
        raise PermissionConditionError(
            'Permission condition did not produce a V1 comparison '
            'expression (==, !=, &, | over principal and object fields).'
        )
    klass = model
    if klass is None:
        klass = obj.model if hasattr(obj, 'model') and not isinstance(obj, Model) else obj.__class__
    validate_expression(expr, klass)
    return evaluate_expression(expr, user, perm, obj, model=klass)


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


class ConditionRecord(object):
    """Registered condition: normalized ``Expr`` IR only.

    ``model`` is retained so a registration can be validated by the
    system check after all apps have loaded. This record is
    implementation-neutral: it does not name Zero nouns. The builder
    callable is never stored.
    """

    __slots__ = ('expr', 'model')

    def __init__(self, expr=None, model=None):
        self.expr = expr
        self.model = model


def _invoke_condition_builder(builder):
    """Invoke a trusted registration-time builder exactly once."""
    u, p, o = condition_refs()
    try:
        expr = builder(u, p, o)
    except PermissionConditionError:
        raise
    except TypeError as exc:
        raise PermissionConditionError(
            'Permission condition builder must accept symbolic (u, p, o): %s'
            % exc
        ) from exc
    except Exception as exc:
        raise PermissionConditionError(
            'Permission condition builder failed: %s' % exc
        ) from exc
    if isinstance(expr, bool) or not isinstance(expr, Expr):
        raise PermissionConditionError(
            'Permission condition builder must return a V1 comparison '
            '(==, != combined with & / |), not %r.'
            % (type(expr).__name__,)
        )
    return expr


class ConditionRegistry(object):
    """Per-instance store of permission-condition records.

    Create a new instance per isolated context. There is no
    process-global singleton. Records are keyed by model identity plus
    condition code on *this* instance, so two registries never share or
    overwrite each other.

    A callable is a registration-time builder: invoked once with
    symbolic refs, then discarded. A transitional prebuilt ``Expr`` is
    still accepted. Field/type validation runs here (zero SQL).
    """

    def __init__(self):
        self._records = {}

    def register_permission_condition(self, model, cond_code, condition):
        """Register a ``:cond_code`` condition on ``model``.

        Pass a builder ``callable(u, p, o)`` or, in Stage A, a prebuilt
        ``Expr``. The builder is invoked exactly once. The stored record
        is normalized IR only.
        """
        if isinstance(condition, Expr):
            expr = condition
        elif callable(condition):
            expr = _invoke_condition_builder(condition)
        else:
            raise TypeError(
                'register_permission_condition expected a builder callable '
                'or a transitional Expr, got %r.'
                % (type(condition).__name__,)
            )
        if not is_predicate(expr):
            raise PermissionConditionError(
                'Registered expression must be a V1 comparison '
                '(==, != combined with & / |), not %r.' % (expr,)
            )
        expr = normalize_expression(expr)
        from django.apps import apps as django_apps

        if getattr(model, '_meta', None) is not None and django_apps.models_ready:
            validate_expression(expr, model)
        record = ConditionRecord(expr=expr, model=model)
        self._records[(_condition_model_key(model), cond_code)] = record
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

    def compile_registered_condition_q(self, model, perm, user):
        """Compile a ``:condition`` suffix to ``Q``, or raise fail-closed.

        Unregistered codes raise ``AttributeError``. Unbound records
        raise ``PermissionConditionError``. Invalid stored IR fails closed.
        """
        cond = permission_condition_code(perm)
        record = self.get_permission_condition_record(model, cond)
        if record is None:
            raise _unknown_condition_error(model, cond)
        if record.expr is None:
            label = getattr(getattr(model, '_meta', None), 'label', model)
            raise PermissionConditionError(
                'Permission condition %r on %s is unbound.' % (perm, label)
            )
        grant = perm.split(':', 1)[0] if isinstance(perm, str) else perm
        return compile_expression_q(record.expr, model, user, grant)

    def evaluate_permission_condition(self, model, cond_code, user, perm, obj):
        """Evaluate one registered condition against a real object.

        Unregistered codes raise ``AttributeError``. The stored IR is
        evaluated; builders are never invoked here.
        """
        record = self.get_permission_condition_record(model, cond_code)
        if record is None:
            raise _unknown_condition_error(model, cond_code)
        if record.expr is None:
            raise PermissionConditionError(
                'Permission condition %r on %s is unbound.'
                % (cond_code, getattr(getattr(model, '_meta', None), 'label', model))
            )
        return evaluate_registered_expression(
            record.expr, user, perm, obj, model=model,
        )


from trusts.core import ConditionLookup  # noqa: E402


class RegistryConditionLookup(ConditionLookup):
    """Generic ``ConditionLookup`` over a ``ConditionRegistry``.

    Bind with ``handle.registry.set_condition_lookup(
    RegistryConditionLookup(handle.registry))``. Accepts a
    ``ConditionRegistry`` or any object with a ``conditions`` store
    (a ``TrustsRegistry``). Core never imports Zero nouns.
    """

    def __init__(self, registry):
        conditions = getattr(registry, 'conditions', registry)
        record_for = getattr(conditions, 'get_permission_condition_record', None)
        compile_q = getattr(conditions, 'compile_registered_condition_q', None)
        if not callable(record_for) or not callable(compile_q):
            raise TypeError(
                'RegistryConditionLookup requires a ConditionRegistry '
                'or TrustsRegistry, not %r.' % (type(registry).__name__,)
            )
        self.conditions = conditions

    def record_for(self, model, cond_code):
        return self.conditions.get_permission_condition_record(model, cond_code)

    def compile_q(self, model, perm_string, user):
        return self.conditions.compile_registered_condition_q(
            model, perm_string, user,
        )
