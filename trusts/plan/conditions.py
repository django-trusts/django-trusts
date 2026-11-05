"""Private condition language (issue #4 V1 / #142 Stage B).

This module is not an application-facing import. It parses and checks
a builder. The queryset ``Q`` lives in ``trusts.plan.writers``.
``parse_named_filter`` returns the stored
node, a ``trusts.plan.grammar.Tree``.

A callable argument to ``parse_named_filter`` is a **builder**: this
module invokes it exactly once with symbolic ``(u, p, o)`` refs,
validates the returned predicate, and normalizes constants into durable
IR. The callable is not part of the returned tree and is never invoked
during ``has_perm``, enumeration, or queryset filtering.

Builders are trusted startup/configuration code, the same class as
``AppConfig.ready()``. Core does not sandbox them. Core's own
registration path issues zero SQL (symbolic refs plus ``_meta``).

Prebuilt trees are not accepted at register.
``parse_named_filter`` is the entry point: one builder in, one checked
tree out. The compiler stores that tree. This module does not.

V1 grammar: principal/object field refs and relationship traversal
(``_meta`` fields on the content model and the entity/user model; not
Python properties); literal constants; ``==`` / ``!=`` and ordered
comparisons of ordered scalars; ``Now``, ``Lower``, and ``Coalesce``
from ``trusts.functions``; nested ``&`` / ``|``; ``.contains()`` on a
forward many-to-many; a bare boolean field; and ``~`` on a boolean
field or on ``&`` / ``|``. Operand types must
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
    Value,
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
from django.db.backends.base.base import BaseDatabaseWrapper
from django.db.models.fields import GenericIPAddressField
from django.http import HttpRequest
from django.utils.functional import Promise, SimpleLazyObject

from trusts.errors import PermissionConditionError
from trusts.functions import Coalesce, Lower, Now
from trusts.plan.grammar import (
    ORDERED_KINDS,
    Symbol,
    Tree,
    invoke,
    is_predicate,
    missing_field,
    needs_expression,
    symbol_path,
    symbol_root,
    symbol_token,
    unsupported,
    walk,
)
from trusts.plan.rewrites import CallInput
from trusts.utils import parse_perm_code


def permission_binding(perm, model):
    """Unevaluated ``auth.Permission`` pk for a codename string.

    A ``Permission`` instance is returned unchanged. A string becomes
    the same exact-codename subquery ``has_perm`` and
    ``get_permitted_users`` run via ``codename_lookup``.
    """
    if isinstance(perm, Permission):
        return perm
    applabel, codename, _cond = parse_perm_code(perm)
    return codename_lookup(model, applabel, codename)


def codename_lookup(model, app_label, codename):
    """Exact-codename subquery ``.permitted(str)`` runs.

    ``model`` is the protected content model. Its model name stays a
    content constant. The codename and app label are call inputs.
    """
    return Subquery(
        Permission.objects.filter(
            content_type__app_label=CallInput(
                app_label.lower(), 'permission.app_label',
            ),
            content_type__model=model._meta.model_name,
            codename=CallInput(codename, 'permission.codename'),
        ).values('pk')[:1]
    )


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


_FUNCTIONS = (Now, Lower, Coalesce)


def capture_expression(builder, roots):
    """Run ``builder`` once and lower functions before the tree is stored."""
    return invoke(builder, roots, prepare=normalize_expression)


def normalize_expression(node, token=None):
    """Return a tree whose constants are durable values.

    ``Now``, ``Lower``, and ``Coalesce`` become ``call`` nodes. A symbol
    becomes a field. The stored tree holds no Django expression.
    """
    if _node(node, 'and', 'or', 'eq', 'ne', 'contains') or _node(
        node, *ORDERED_KINDS,
    ):
        left = normalize_expression(node.left, token)
        right = normalize_expression(node.right, token)
        if left is node.left and right is node.right:
            return node
        return Tree(node.kind, left=left, right=right)
    if _node(node, 'not', 'bare'):
        item = normalize_expression(node.item, token)
        if item is node.item:
            return node
        return Tree(node.kind, item=item)
    if _node(node, 'const'):
        lowered = _lower_value(node.value, token)
        if lowered.kind == 'const' and lowered.value is node.value:
            return node
        return lowered
    return node


def _lower_value(value, token, *, inside=False):
    """One builder-time operand as a field, constant, or call.

    ``Value`` is accepted only inside a Trusts function. A bare string,
    ``F``, or any other Django expression is rejected.
    """
    if isinstance(value, Symbol):
        if token is None or symbol_token(value) is not token:
            raise unsupported('A path from another builder')
        path = symbol_path(value)
        root = symbol_root(value)
        # The permission root is the codename. User and object still need a field.
        if not path and root != 'permission':
            raise unsupported(
                'A root without a field',
                hint='Name a field, for example o.owner.',
            )
        return Tree('field', root=root, path=path)
    if type(value) in _FUNCTIONS:
        return _lower_function(value, token)
    if inside and type(value) is Value:
        return _lower_value(value.value, token, inside=True)
    if hasattr(value, 'resolve_expression'):
        raise PermissionConditionError(
            'A %s constant is not supported in a named filter. '
            'SQL functions in a condition must be Now, Lower, and Coalesce '
            'from trusts.functions.' % type(value).__name__
        )
    return Tree('const', value=normalize_constant(value))


def _lower_function(expr, token):
    if expr.extra or 'output_field' in expr.__dict__:
        raise PermissionConditionError(
            'Now, Lower, and Coalesce from trusts.functions do not take '
            'template, function, output_field, or other keyword arguments.'
        )
    sources = expr.get_source_expressions()
    if type(expr) is Now and sources:
        raise PermissionConditionError(
            'Now() from trusts.functions takes no arguments.'
        )
    # Django already rejects Lower() with other than one argument and
    # Coalesce() with fewer than two, while the builder runs.
    return Tree(
        'call', value=type(expr).__name__.lower(),
        item=tuple(
            _lower_value(source, token, inside=True)
            for source in sources
        ),
    )


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


def _column_field(field, name):
    """The stored column. ``owner_id`` is the target key, not the relation."""
    if (
        field.is_relation
        and not field.many_to_many
        and not field.one_to_many
        and field.get_attname() == name
        and name != field.name
    ):
        return field.target_field
    return field


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


_ORDERED_TYPES = (int, float, Decimal, str, datetime, date, time, timedelta)


def _spec_is_ordered(spec):
    return (
        spec[0] == 'scalar'
        and bool(spec[1])
        and all(kind in _ORDERED_TYPES for kind in spec[1])
    )


def _is_text_spec(spec):
    return spec[0] == 'scalar' and spec[1] == (str,)


def _reject_split_function(node):
    """One function stays on one root. User and object cannot share a call."""
    roots = {leaf.root for leaf in walk(node) if leaf.kind == 'field'}
    if 'user' in roots and 'object' in roots:
        raise PermissionConditionError(
            '%s() mixes a user field and an object field. '
            'Keep each function on one root.'
            % node.value.capitalize()
        )


def _operand_spec(node, model, user_model):
    if _node(node, 'call'):
        return _call_spec(node, model, user_model)
    if _node(node, 'const'):
        return _spec_from_const(node.value)
    if _node(node, 'field'):
        if node.root in ('object', 'row'):
            ref = 'object' if node.root == 'object' else 'condition'
            field = _terminal_field(model, node.path, ref)
            return _spec_from_field(_column_field(field, node.path[-1]))
        if node.root == 'user':
            entity = user_model
            if not node.path:
                return ('instance', entity, entity._meta.label)
            field = _terminal_field(entity, node.path, 'principal')
            return _spec_from_field(_column_field(field, node.path[-1]))
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


def _call_spec(node, model, user_model):
    if node.value == 'now':
        return ('scalar', (datetime,), 'Now')
    specs = [_operand_spec(arg, model, user_model) for arg in node.item]
    if node.value == 'lower':
        if not _is_text_spec(specs[0]):
            raise PermissionConditionError(
                'Lower() accepts text, not %s.' % (specs[0][2],)
            )
        return ('scalar', (str,), 'Lower')
    if any(spec[0] == 'null' for spec in specs):
        raise PermissionConditionError(
            'Coalesce() does not accept None. NULL does not grant.'
        )
    classes = _coalesce_fields(node, model, user_model)
    if len(classes) > 1:
        raise PermissionConditionError(
            'Coalesce() arguments must share one field type (%s).'
            % ', '.join(sorted(classes))
        )
    if any(not _specs_compatible(specs[0], spec) for spec in specs[1:]):
        raise PermissionConditionError(
            'Coalesce() arguments must share one type (%s).'
            % ', '.join(spec[2] for spec in specs)
        )
    if classes:
        return _spec_from_field(next(iter(classes.values())))
    return specs[0]


def _coalesce_fields(node, model, user_model):
    """One example field for each column class, or ``Now()``, inside a call."""
    found = {}
    for leaf in walk(node):
        if leaf.kind == 'call' and leaf.value == 'now':
            found['DateTimeField'] = DateTimeField()
            continue
        if leaf.kind != 'field' or not leaf.path or leaf.root == 'permission':
            continue
        host = user_model if leaf.root == 'user' else model
        ref = 'principal' if leaf.root == 'user' else (
            'object' if leaf.root == 'object' else 'condition'
        )
        field = _column_field(
            _terminal_field(host, leaf.path, ref), leaf.path[-1],
        )
        if field.is_relation:
            raise PermissionConditionError(
                'Coalesce() does not accept relation %s.' % field.name
            )
        found[type(field).__name__] = field
    return found


def coalesce_output_field(node, model, user_model):
    """The field Django must use so ``Value()`` does not pick a sibling type."""
    found = _coalesce_fields(node, model, user_model)
    if len(found) != 1:
        return None
    field = next(iter(found.values()))
    if isinstance(field, DecimalField):
        return DecimalField(
            max_digits=field.max_digits, decimal_places=field.decimal_places,
        )
    return type(field)()


def check_comparison_types(node, model, user_model):
    left = _operand_spec(node.left, model, user_model)
    right = _operand_spec(node.right, model, user_model)
    ordered = node.kind in ORDERED_KINDS
    if needs_expression(node) and 'null' in (left[0], right[0]):
        raise PermissionConditionError(
            'NULL does not grant in an ordered or function comparison. '
            'Use Coalesce to supply a value.'
        )
    if _specs_compatible(left, right) and not (
        ordered and not (_spec_is_ordered(left) and _spec_is_ordered(right))
    ):
        return
    raise PermissionConditionError(
        'Permission condition compares incompatible types (%s vs %s). '
        'V1 does not coerce literals through Django field preparation; '
        'CharField values are strings, relations compare to model '
        'instances (not raw primary keys), and ordered comparison needs '
        'ordered scalars. Now() matches a DateTimeField only.'
        % (left[2], right[2])
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


def require_boolean_field(model, path, ref_kind, *, where=None, name=None):
    """One bare-boolean check for named filters, relations, and user rules."""
    field = _terminal_field(model, path, ref_kind)
    concrete = name is not None
    ok = isinstance(field, BooleanField) and (
        not concrete or getattr(field, 'concrete', False)
    )
    if ok:
        return field
    if name is not None:
        raise PermissionConditionError(
            'User condition %r needs %s.%s to be a concrete BooleanField.'
            % (name, model._meta.label, '__'.join(path))
        )
    raise PermissionConditionError(
        'A bare field in %s must be a boolean, not %s.%s.'
        % (where, field.model._meta.label, field.name)
    )


def check_const_member(model, collection_path, value, ref_kind='condition'):
    """A constant ``.contains()`` member must fit the related primary key."""
    field = _terminal_field(
        model, collection_path, ref_kind, collection=True,
    )
    if value is None:
        return
    _check_member_spec(_spec_from_const(value), field.remote_field.model)


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
    require_boolean_field(host, item.path, ref, where='a named filter')


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
    if _node(node, 'eq', 'ne', *ORDERED_KINDS):
        _validate_node(node.left, model, user_model)
        _validate_node(node.right, model, user_model)
        check_comparison_types(node, model, user_model)
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
    if _node(node, 'call'):
        for arg in node.item:
            _validate_node(arg, model, user_model)
        _reject_split_function(node)
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
            if len(node.path) > 1:
                raise PermissionConditionError(
                    'Permission references cannot traverse attributes in V1.'
                )
        return
    raise PermissionConditionError(
        'Malformed permission condition node %r.' % (node,)
    )


def condition_model_key(model):
    meta = getattr(model, '_meta', None)
    if meta is not None:
        return meta.label
    return model


def condition_model_label(model):
    meta = getattr(model, '_meta', None)
    if meta is not None:
        return meta.label
    return repr(model)


_PARSED_NAMED_FILTERS = {}


def parse_named_filter(builder, model, code, user_model):
    """Return the checked tree for one named-filter builder.

    The builder runs once. A later parse of the same builder, model,
    code, and user model returns that tree. Constants are normalized
    into durable values. When ``model`` has ``_meta``, field paths and
    operand types are checked against that model and ``user_model``.
    """
    key = (builder, condition_model_key(model), condition_model_key(user_model), code)
    expr = _PARSED_NAMED_FILTERS.get(key)
    if expr is not None:
        return expr
    expr = capture_expression(
        builder, ('user', 'permission', 'object'),
    )
    if getattr(model, '_meta', None) is not None:
        validate_expression(expr, model, user_model)
    _PARSED_NAMED_FILTERS[key] = expr
    return expr
