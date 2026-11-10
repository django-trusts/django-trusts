"""SQL writer for one checked condition tree.

``trusts.plan.conditions`` parses and checks a builder. ``compile_to_q``
turns that tree into a Django ``Q``. It does not register a filter and
it does not look one up. Scalar comparisons, boolean fields,
``Reachable``, and ``~`` lower through ``trusts.plan.trivalent``. A
missing row is unknown. ``.contains()`` keeps the membership join it
already had.
"""

from django.core.exceptions import ObjectDoesNotExist
from django.db.models import Exists, F, Model, Q
from django.db.models.fields.related import ManyToManyRel

from trusts.errors import PermissionConditionError
from trusts.plan.conditions import (
    ModelIdentity,
    resolve_field_path,
)
from trusts.plan.grammar import REACHABLE_NAME, Tree
from trusts.plan.trivalent import grant_q, has_contains


def contains_q(lookup, member):
    """One membership lookup. ``member`` is a value or an ``F`` expression."""
    return Q(**{lookup: member})


def _terminal_field(model, path):
    current = model
    field = None
    for name in path:
        field = current._meta.get_field(name)
        remote = getattr(field, 'remote_field', None)
        related = getattr(remote, 'model', None) if remote is not None else None
        if related is None:
            return field
        current = related
    return field


def _far_stores_pk(field):
    """True when membership already compares the related primary key."""
    if (
        getattr(field, 'concrete', False)
        and (
            getattr(field, 'many_to_one', False)
            or getattr(field, 'one_to_one', False)
        )
    ):
        return bool(getattr(field.target_field, 'primary_key', False))
    if not getattr(field, 'many_to_many', False):
        return True
    if isinstance(field, ManyToManyRel):
        forward = field.field
        column = forward.m2m_column_name()
    else:
        forward = field
        column = forward.m2m_reverse_name()
    through = forward.remote_field.through
    for candidate in through._meta.local_fields:
        if (
            getattr(candidate, 'column', None) == column
            and getattr(candidate, 'is_relation', False)
        ):
            return bool(getattr(candidate.target_field, 'primary_key', False))
    return True


def pk_membership_lookup(model, path, lookup):
    """``lookup`` that matches the related row's primary key.

    A foreign key, one-to-one, or many-to-many that stores a non-PK
    ``to_field`` would compare that stored value to the member pk.
    ``__pk`` joins the target and compares its primary key. A relation
    that already stores the pk is left unchanged.
    """
    if not path:
        return lookup
    try:
        field = _terminal_field(model, path)
    except Exception:
        return lookup
    if field is None or _far_stores_pk(field):
        return lookup
    return '%s__pk' % lookup


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
            # The last hop is the stored target (``to_field``, not the
            # related primary key). Earlier hops are the related object.
            if last and getattr(field, 'concrete', False):
                return getattr(current, field.attname)
            try:
                current = getattr(current, field.name)
            except ObjectDoesNotExist:
                current = None
            if not last:
                current_model = field.remote_field.model
            continue
        current = getattr(current, field.attname)
    return current


def _permission_attr(perm, path):
    """One attribute of the permission this inquiry asked for.

    A string permission supplies ``app_label`` and ``codename``. A saved
    permission row supplies any concrete attribute. Longer paths stay
    rejected.
    """
    if not path:
        return perm
    if len(path) != 1:
        raise PermissionConditionError(
            'Permission references cannot traverse attributes in V1.'
        )
    attr = path[0]
    if isinstance(perm, Model):
        try:
            return getattr(perm, attr)
        except AttributeError as exc:
            raise PermissionConditionError(
                'Permission references cannot traverse attributes in V1.'
            ) from exc
    if isinstance(perm, str) and perm.count('.') == 1:
        app_label, codename = perm.split('.', 1)
        if attr == 'app_label':
            return app_label
        if attr == 'codename':
            return codename
    raise PermissionConditionError(
        'Permission references cannot traverse attributes in V1.'
    )


def column_q(lookup, value):
    """One column against a loaded value. NULL does not match."""
    value = member_pk(value)
    if value is None:
        return Q(pk__in=())
    return Q(**{'%s__isnull' % lookup: False}) & ~Q(**{lookup: value})


def member_pk(value):
    """A saved instance or ``ModelIdentity`` as its pk. Other values pass."""
    if isinstance(value, (Model, ModelIdentity)):
        return value.pk
    return value


def _bound_value(node, user, perm, user_model):
    """User, permission, or constant value. Object fields stay in the queryset."""
    if _node(node, 'const'):
        return node.value
    if _node(node, 'field'):
        if node.root == 'user':
            if not node.path:
                return user
            return _walk_model_path(user, user_model, node.path)
        if node.root == 'permission':
            return _permission_attr(perm, node.path)
    raise PermissionConditionError(
        'Cannot compile permission condition node %r.' % (node,)
    )


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
        host = model if left.root == 'object' else user_model
        return contains_q(
            pk_membership_lookup(host, left.path, lookup), value,
        )
    manager = _load_collection(left, user, None, model, user_model)
    if _node(right, 'field') and right.root == 'object':
        if manager is None:
            return Q(pk__in=())
        member = '__'.join(right.path)
        return Q(**{'%s__in' % member: manager.values('pk')})
    # A known member used to become an empty ``Q()``. Django drops that
    # child of ``|``, so a true membership disappeared beside an unknown
    # comparison and the forward check disagreed with the reverse one.
    # ``EXISTS`` is still one matching member, and it survives ``|`` / ``&``.
    value = member_pk(_bound_value(right, user, perm, user_model))
    if manager is None or value is None:
        return Q(pk__in=())
    return Q(Exists(manager.filter(pk=value)))


def _filter_bindings(model, user, perm, user_model):
    bindings = {'object': ('alias', model, ())}
    if user is not None and getattr(user, 'pk', None) is not None:
        host = user_model or user.__class__
        bindings['user'] = ('pk', host, user.pk)
    bindings['permission'] = ('permission', perm)
    return bindings


def compile_to_q(node, model, user, perm, user_model=None):
    """Compile an expression tree to a Django ``Q`` for ``model`` rows.

    Scalar predicates are one three-valued expression. ``.contains()``
    stays a membership lookup and is combined only at ``&`` / ``|``.
    """
    bindings = _filter_bindings(model, user, perm, user_model)
    if not has_contains(node):
        return grant_q(node, bindings)
    if _node(node, 'and'):
        return compile_to_q(
            node.left, model, user, perm, user_model,
        ) & compile_to_q(node.right, model, user, perm, user_model)
    if _node(node, 'or'):
        return compile_to_q(
            node.left, model, user, perm, user_model,
        ) | compile_to_q(node.right, model, user, perm, user_model)
    if _node(node, 'contains'):
        return _compile_contains(node, model, user, perm, user_model)
    raise PermissionConditionError(
        'Permission condition did not produce a comparison, '
        '%s(), .contains(), or boolean field.' % REACHABLE_NAME
    )

