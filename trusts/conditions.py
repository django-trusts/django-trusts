"""Restricted declarative permission conditions (issue #4 V1 / #142 A).

A callable argument to condition registration is a **builder**: Core
invokes it exactly once with symbolic ``(u, p, o)`` refs, validates the
returned predicate, normalizes constants into durable IR, and stores
only that IR. The callable is discarded from the policy record and is
never invoked during ``has_perm``, enumeration, or queryset filtering.

Builders are trusted startup/configuration code, the same class as
``AppConfig.ready()``. Core does not sandbox them. Core's own
registration path issues zero SQL (symbolic refs plus ``_meta``).

Transitional prebuilt ``Expr`` trees remain accepted so current Zero
``Trust:own`` Meta donation keeps loading. Stage B will reject ``Expr``
and hide construction nodes.

Permission-condition records live on an instantiable
``ConditionRegistry`` (also exposed on each ``TrustsRegistry`` and
``BackendHandle.register_permission_condition``). There is no
process-global store: each implementation handle owns its own records
so owners cannot share or overwrite each other.

V1 grammar: principal/object field refs and relationship traversal
(``_meta`` fields on the content model and the entity/user model; not
Python properties); literal constants; ``==`` / ``!=``; nested ``&`` /
``|``. Operand types must match without Django field coercion:
``CharField`` compares to ``str``, relations compare to model identity
(not raw primary keys). Missing attribute names fail closed; they are
not treated as ``NULL``. Python ``and`` / ``or`` / ``not`` and chained
comparisons cannot be overloaded and raise
``PermissionConditionBooleanError``.
"""

from datetime import date, datetime, time, timedelta
from decimal import Decimal
from io import IOBase
from uuid import UUID

from django.core.exceptions import FieldDoesNotExist, ObjectDoesNotExist
from django.db.models import options as model_options
from django.db.models import (
    F,
    Manager,
    Model,
    Q,
    QuerySet,
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


def obsolete_legacy_callback_setting_enabled():
    """True when the deleted runtime-callback setting is still ``True``.

    The setting no longer enables object-only callbacks. A True value is
    a configuration error (``trusts.E002``). Missing or False is quiet.
    Read at call time so ``override_settings`` works.
    """
    from django.conf import settings as django_settings

    return bool(getattr(
        django_settings, 'TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS', False
    ))


def legacy_permission_callbacks_allowed():
    """Obsolete alias. Reports the deleted setting; never enables callbacks.

    A True value is a configuration error (``trusts.E002``). Runtime
    authorization never invokes a registered callable.
    """
    return obsolete_legacy_callback_setting_enabled()


_BOOLEAN_ERROR_MESSAGE = (
    "Python 'and'/'or'/'not' cannot be used in permission conditions "
    "because they cannot be overloaded; chained comparisons such as "
    "`0 < o.amount < 100` also truth-test a symbolic node. Use '&' and "
    "'|' for conjunction and disjunction, and '!=' instead of combining "
    "'not' with '=='."
)

_SCALAR_CONSTANT_TYPES = (
    type(None), bool, int, float, str, bytes,
    Decimal, UUID, datetime, date, time, timedelta,
)


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
        if isinstance(other, ModelIdentity):
            return self.as_tuple() == other.as_tuple()
        if isinstance(other, Model):
            meta = other._meta.concrete_model._meta
            return (
                meta.app_label == self.app_label
                and meta.model_name == self.model_name
                and other.pk == self.pk
            )
        return NotImplemented

    def __ne__(self, other):
        equal = self.__eq__(other)
        if equal is NotImplemented:
            return NotImplemented
        return not equal

    def __hash__(self):
        return hash(self.as_tuple())

    def __repr__(self):
        return 'ModelIdentity(%r, %r, %r)' % (
            self.app_label, self.model_name, self.pk,
        )


class Const(Expr):
    def __init__(self, value):
        self.value = value

    def to_tuple(self):
        if isinstance(self.value, ModelIdentity):
            return ('const', self.value.as_tuple())
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
        _unsupported('QuerySet constants')
    if isinstance(value, Manager):
        _unsupported('Manager constants')
    if isinstance(value, (list, dict, set, tuple, frozenset)):
        _unsupported('Mutable or collection constants of type %s' % type(value).__name__)
    if isinstance(value, IOBase):
        _unsupported('File / stream constants')
    try:
        from django.http import HttpRequest
    except Exception:
        HttpRequest = None
    if HttpRequest is not None and isinstance(value, HttpRequest):
        _unsupported('HttpRequest constants')
    try:
        from django.utils.functional import Promise, SimpleLazyObject
    except Exception:
        Promise = SimpleLazyObject = None
    if Promise is not None and isinstance(value, Promise):
        _unsupported('Lazy / promise constants')
    if SimpleLazyObject is not None and isinstance(value, SimpleLazyObject):
        _unsupported('Lazy / request object constants')
    try:
        from django.db.backends.base.base import BaseDatabaseWrapper
    except Exception:
        BaseDatabaseWrapper = None
    if BaseDatabaseWrapper is not None and isinstance(value, BaseDatabaseWrapper):
        _unsupported('Database connection constants')
    if callable(value) and not isinstance(value, type) and not isinstance(value, Model):
        _unsupported('Callable constants')
    if not _is_allowed_scalar(value) and not isinstance(value, (Model, ModelIdentity)):
        _unsupported('Constant of type %s' % type(value).__name__)


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
    """Normalize Const operands in place. Returns ``node``."""
    if isinstance(node, (And, Or, Eq, Ne, _Ordering)):
        normalize_expression(node.left)
        normalize_expression(node.right)
        return node
    if isinstance(node, Const):
        node.value = normalize_constant(node.value)
        return node
    return node


def as_node(value):
    if isinstance(value, Expr):
        return value
    if isinstance(value, ModelIdentity):
        return Const(value)
    _reject_forbidden_constant(value)
    if isinstance(value, Model):
        return Const(normalize_constant(value))
    if _is_allowed_scalar(value):
        return Const(value)
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
    """Return symbolic ``(u, p, o)`` for a builder or transitional ``Expr``.

    Application code should pass a builder to
    ``handle.register_permission_condition``. These objects are policy
    data, not live principals or content rows. Public construction via
    this helper remains available until Stage B.
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


def _model_from_identity(identity):
    from django.apps import apps as django_apps

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
        return _resolve_runtime(node.left, user, perm, obj, model) == (
            _resolve_runtime(node.right, user, perm, obj, model)
        )
    if isinstance(node, Ne):
        return _resolve_runtime(node.left, user, perm, obj, model) != (
            _resolve_runtime(node.right, user, perm, obj, model)
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


def _q_eq_lookup(lookup, value):
    if value is None:
        return Q(**{'%s__isnull' % lookup: True})
    return Q(**{lookup: value})


def _q_ne_lookup(lookup, value):
    # Match Python: ``None != x`` is True when ``x is not None``.
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


def _sql_constant(value):
    if isinstance(value, ModelIdentity):
        return value.pk
    return value


def _compile_comparison(node, model, user, perm):
    left = _classify(node.left, model, user, perm)
    right = _classify(node.right, model, user, perm)
    equal = isinstance(node, Eq)
    if isinstance(left, _Bound) and isinstance(right, _Bound):
        matches = (left.value == right.value) if equal else (left.value != right.value)
        return _always_true() if matches else _always_false()
    if isinstance(left, _Unbound) and isinstance(right, _Bound):
        lookup, value = left.lookup, _sql_constant(right.value)
    elif isinstance(left, _Bound) and isinstance(right, _Unbound):
        lookup, value = right.lookup, _sql_constant(left.value)
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


def _condition_model_label(model):
    meta = getattr(model, '_meta', None)
    if meta is not None:
        return meta.label
    return repr(model)


def _invoke_condition_builder(builder, model, cond_code):
    """Invoke a trusted builder once with symbolic refs; return a predicate."""
    u, p, o = condition_refs()
    try:
        result = builder(u, p, o)
    except PermissionConditionError:
        raise
    except Exception as exc:
        raise PermissionConditionError(
            'Permission condition builder %r on %s raised %s: %s'
            % (cond_code, _condition_model_label(model), type(exc).__name__, exc)
        ) from exc
    if isinstance(result, bool):
        raise PermissionConditionError(
            'Permission condition builder %r on %s returned a boolean; '
            'return a comparison of the symbolic refs (for example '
            '`u == o.owner`).' % (cond_code, _condition_model_label(model))
        )
    if not isinstance(result, Expr) or not is_predicate(result):
        raise PermissionConditionError(
            'Permission condition builder %r on %s did not return a V1 '
            'comparison expression, got %r.'
            % (cond_code, _condition_model_label(model), result)
        )
    return result


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
    with symbolic refs, then discarded. A prebuilt ``Expr`` is accepted
    transitionally. Model-aware semantic validation of prebuilt ``Expr``
    trees is a system check; builders fail at register.
    """

    def __init__(self):
        self._records = {}

    def register_permission_condition(self, model, cond_code, condition):
        """Register a ``:cond_code`` condition on ``model``.

        Pass a builder ``callable(u, p, o)`` that returns a V1
        comparison. Core invokes it exactly once with symbolic refs,
        normalizes constants, and stores only IR.

        A prebuilt ``Expr`` is still accepted so current Zero
        ``Trust:own`` donation keeps loading. Shape errors (bare
        non-predicate ``Expr``, a value that is neither ``Expr`` nor
        callable) raise here.
        """
        from_builder = False
        if isinstance(condition, Expr):
            if not is_predicate(condition):
                raise PermissionConditionError(
                    'Registered expression must be a V1 comparison '
                    '(==, != combined with & / |), not %r.' % (condition,)
                )
            expr = condition
        elif callable(condition):
            expr = _invoke_condition_builder(condition, model, cond_code)
            from_builder = True
        else:
            raise TypeError(
                'register_permission_condition expected a builder callable '
                'or a transitional Expr, got %r.' % (type(condition).__name__,)
            )
        normalize_expression(expr)
        if from_builder and getattr(model, '_meta', None) is not None:
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

        Unregistered codes raise ``AttributeError``. Unbound records and
        registered trees that are not valid V1 fail closed.
        """
        cond = permission_condition_code(perm)
        record = self.get_permission_condition_record(model, cond)
        if record is None:
            raise _unknown_condition_error(model, cond)
        if record.expr is None:
            raise PermissionConditionError(
                'Permission condition %r on %s is unbound.'
                % (cond, _condition_model_label(model))
            )
        grant = perm.split(':', 1)[0] if isinstance(perm, str) else perm
        return compile_expression_q(record.expr, model, user, grant)

    def evaluate_permission_condition(self, model, cond_code, user, perm, obj):
        """Evaluate one registered condition against a real object.

        Unregistered codes raise ``AttributeError``. Unbound records
        fail closed. The builder is never invoked here.
        """
        record = self.get_permission_condition_record(model, cond_code)
        if record is None:
            raise _unknown_condition_error(model, cond_code)
        if record.expr is None:
            raise PermissionConditionError(
                'Permission condition %r on %s is unbound.'
                % (cond_code, _condition_model_label(model))
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
