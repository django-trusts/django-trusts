"""Python and SQL writers for one checked condition tree.

``trusts.plan.conditions`` parses and checks a builder. These functions
turn that tree into a Python result or a Django ``Q``. They do not
register a filter and they do not look one up.
"""

from django.core.exceptions import ObjectDoesNotExist
from django.db.models import F, Model, Q

from trusts.errors import PermissionConditionError
from trusts.plan.conditions import (
    ModelIdentity,
    resolve_field_path,
)
from trusts.plan.grammar import Tree


def contains_q(lookup, member):
    """One membership lookup. ``member`` is a value or an ``F`` expression."""
    return Q(**{lookup: member})


def _node(node, *kinds):
    return isinstance(node, Tree) and node.kind in kinds


def _walk_model_path(instance, model, path, *, collection=False):
    """Follow a checked field path on ``instance``.

    ``resolve_field_path`` rejects a missing name, a multi-valued hop, and
    a non-relation in the middle. A nullable relation resolves to ``None``.
    Python properties are not consulted.
    """
    resolve_field_path(
        model, path, ref_kind='condition', collection=collection,
    )
    current = instance
    current_model = model
    for i, name in enumerate(path):
        field = current_model._meta.get_field(name)
        last = i == len(path) - 1
        if last and collection and field.many_to_many:
            if current is None:
                return None
            return getattr(current, field.name)
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


def _resolve_runtime(node, user, perm, obj, model, user_model):
    if _node(node, 'const'):
        return node.value
    if _node(node, 'field'):
        if node.root == 'user':
            if not node.path:
                return user
            return _walk_model_path(user, user_model, node.path)
        if node.root == 'permission':
            if node.path:
                raise PermissionConditionError(
                    'Permission references cannot traverse attributes in V1.'
                )
            return perm
        if node.root == 'object':
            return _walk_model_path(obj, model, node.path)
    raise PermissionConditionError(
        'Cannot evaluate permission condition node %r.' % (node,)
    )


def evaluate_expression(node, user, perm, obj, model=None, user_model=None):
    """Evaluate a captured expression against a real principal/permission/object."""
    if model is None:
        model = obj.__class__
    if _node(node, 'and'):
        return evaluate_expression(
            node.left, user, perm, obj, model, user_model,
        ) and evaluate_expression(
            node.right, user, perm, obj, model, user_model,
        )
    if _node(node, 'or'):
        return evaluate_expression(
            node.left, user, perm, obj, model, user_model,
        ) or evaluate_expression(
            node.right, user, perm, obj, model, user_model,
        )
    if _node(node, 'eq', 'ne'):
        return values_match(
            _resolve_runtime(node.left, user, perm, obj, model, user_model),
            _resolve_runtime(node.right, user, perm, obj, model, user_model),
            _node(node, 'eq'),
            fields=_both_fields(node),
        )
    if _node(node, 'contains'):
        return _evaluate_contains(
            node, user, perm, obj, model, user_model,
        )
    if _node(node, 'bare'):
        return boolean_holds(_resolve_runtime(
            node.item, user, perm, obj, model, user_model,
        ))
    if _node(node, 'not'):
        return not evaluate_expression(
            node.item, user, perm, obj, model, user_model,
        )
    raise PermissionConditionError(
        'Permission condition did not produce a comparison, '
        '.contains(), or boolean field.'
    )


class _Bound(object):
    def __init__(self, value):
        self.value = value


class _Unbound(object):
    def __init__(self, lookup):
        self.lookup = lookup


def _classify(node, model, user, perm, user_model):
    if _node(node, 'const'):
        return _Bound(node.value)
    if _node(node, 'field'):
        if node.root == 'object':
            return _Unbound('__'.join(node.path))
        if node.root == 'user':
            if not node.path:
                return _Bound(user)
            return _Bound(_walk_model_path(user, user_model, node.path))
        if node.root == 'permission':
            if node.path:
                raise PermissionConditionError(
                    'Permission references cannot traverse attributes in V1.'
                )
            return _Bound(perm)
    raise PermissionConditionError(
        'Cannot compile permission condition node %r.' % (node,)
    )


def values_match(left, right, equal, *, fields):
    """The NULL rule on loaded values.

    Between two fields (``fields``) NULL on either side never matches. A
    field against a constant follows Python: ``None == None`` holds and
    ``None != 5`` holds.
    """
    if fields and (left is None or right is None):
        return False
    return (left == right) == equal


def columns_q(a, b, equal):
    """Two columns. NULL on either side does not match.

    ``~Q(a=F(b))`` alone is true for NULL, because Django negates
    ``a = b AND a IS NOT NULL AND b IS NOT NULL``.
    """
    if equal:
        return Q(**{a: F(b)})
    return (
        Q(**{'%s__isnull' % a: False})
        & Q(**{'%s__isnull' % b: False})
        & ~Q(**{a: F(b)})
    )


def column_q(lookup, value, equal, *, field):
    """One column against a loaded value, under the NULL rule.

    ``field`` is true when ``value`` came from another field: NULL on
    either side then does not match. Against a constant, ``== None`` is
    ``IS NULL`` and ``!= 5`` matches a NULL column, as in Python.
    """
    value = member_pk(value)
    if value is None and field:
        return Q(pk__in=())
    if value is None:
        return Q(**{'%s__isnull' % lookup: equal})
    if equal:
        return Q(**{lookup: value})
    if field:
        return Q(**{'%s__isnull' % lookup: False}) & ~Q(**{lookup: value})
    return Q(**{'%s__isnull' % lookup: True}) | ~Q(**{lookup: value})


def _both_fields(node):
    return _node(node.left, 'field') and _node(node.right, 'field')


def _compile_comparison(node, model, user, perm, user_model):
    left = _classify(node.left, model, user, perm, user_model)
    right = _classify(node.right, model, user, perm, user_model)
    equal = _node(node, 'eq')
    fields = _both_fields(node)
    if isinstance(left, _Bound) and isinstance(right, _Bound):
        if values_match(left.value, right.value, equal, fields=fields):
            return Q()
        return Q(pk__in=())
    if isinstance(left, _Unbound) and isinstance(right, _Unbound):
        return columns_q(left.lookup, right.lookup, equal)
    if isinstance(left, _Unbound):
        return column_q(left.lookup, right.value, equal, field=fields)
    return column_q(right.lookup, left.value, equal, field=fields)


def boolean_holds(value):
    """A boolean field holds only when it is True. NULL does not."""
    return value is True


def boolean_q(lookup):
    """Column is True. NULL is not True."""
    return Q(**{lookup: True})


def negate_q(model, q):
    """Rows for which ``q`` is not true.

    A row ``q`` rejects, including a row it rejects because a value is
    NULL, is included. That is Python ``not``. ``~Q`` does not do this
    for a comparison: ``NOT (left = right)`` is unknown when either side
    is NULL, and ``~Q()`` is not an empty match.
    """
    return ~Q(pk__in=model._base_manager.filter(q).values('pk'))


def member_pk(value):
    """A saved instance or ``ModelIdentity`` as its pk. Other values pass."""
    if isinstance(value, (Model, ModelIdentity)):
        return value.pk
    return value


def _collection_contains(manager, pk):
    if manager is None or pk is None:
        return False
    return manager.filter(pk=pk).exists()


def _bound_value(node, user, perm, user_model):
    return _resolve_runtime(node, user, perm, None, None, user_model)


def _load_collection(node, user, obj, model, user_model):
    if node.root == 'object':
        return _walk_model_path(obj, model, node.path, collection=True)
    if node.root == 'user':
        return _walk_model_path(
            user, user_model, node.path, collection=True,
        )
    raise PermissionConditionError(
        'Cannot evaluate permission condition node %r.' % (node,)
    )


def _evaluate_contains(node, user, perm, obj, model, user_model):
    manager = _load_collection(node.left, user, obj, model, user_model)
    member = _resolve_runtime(
        node.right, user, perm, obj, model, user_model,
    )
    return _collection_contains(manager, member_pk(member))


def _compile_bare(node, model, user, perm, user_model):
    field = node.item
    if field.root == 'object':
        return boolean_q('__'.join(field.path))
    if boolean_holds(_bound_value(field, user, perm, user_model)):
        return Q()
    return Q(pk__in=())


def _compile_contains(node, model, user, perm, user_model):
    left = node.left
    right = node.right
    if left.root == 'object':
        lookup = '__'.join(left.path)
        if _node(right, 'field') and right.root == 'object':
            return contains_q(lookup, F('__'.join(right.path)))
        value = member_pk(_bound_value(right, user, perm, user_model))
        if value is None:
            return Q(pk__in=())
        return contains_q(lookup, value)
    manager = _load_collection(left, user, None, model, user_model)
    if _node(right, 'field') and right.root == 'object':
        if manager is None:
            return Q(pk__in=())
        member = '__'.join(right.path)
        return Q(**{'%s__in' % member: manager.values('pk')})
    if _collection_contains(
        manager, member_pk(_bound_value(right, user, perm, user_model)),
    ):
        return Q()
    return Q(pk__in=())


def compile_to_q(node, model, user, perm, user_model=None):
    """Compile an expression tree to a Django ``Q`` for ``model`` rows."""
    if _node(node, 'and'):
        return compile_to_q(node.left, model, user, perm, user_model) & compile_to_q(
            node.right, model, user, perm, user_model
        )
    if _node(node, 'or'):
        return compile_to_q(node.left, model, user, perm, user_model) | compile_to_q(
            node.right, model, user, perm, user_model
        )
    if _node(node, 'eq', 'ne'):
        return _compile_comparison(node, model, user, perm, user_model)
    if _node(node, 'contains'):
        return _compile_contains(node, model, user, perm, user_model)
    if _node(node, 'bare'):
        return _compile_bare(node, model, user, perm, user_model)
    if _node(node, 'not'):
        return negate_q(model, compile_to_q(
            node.item, model, user, perm, user_model,
        ))
    raise PermissionConditionError(
        'Permission condition did not produce a comparison, '
        '.contains(), or boolean field.'
    )

