"""Object-to-users compiler: one content object and one permission to users.

The permission row is canonical. A string is resolved inside the eventual
SQL. Construction does not query.
"""

__all__ = []

from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import Permission
from django.core.exceptions import FieldDoesNotExist
from django.db.models import Exists, F, Model, OuterRef, Q

from trusts.plan.conditions import (
    condition_model_key,
    permission_binding,
    resolve_field_path,
)
from trusts.plan.writers import (
    boolean_holds,
    boolean_q,
    negate_q,
    column_q,
    columns_q,
    contains_q,
    member_pk,
    values_match,
)
from trusts.errors import PermissionConditionError, TrustsConfigurationError
from trusts.utils import parse_perm_code
from trusts.plan.contents import _as_q
from trusts.plan.relations import _bound_permission_identity, bind_checked_user
from trusts.plan.grammar import Tree


def _reverse_checked(plan, exists, user_model, permission, content, values,
                     permission_model):
    """Closed user fragment, override, and eligibility for a reverse row."""
    checked = bind_checked_user(
        user_model,
        None if exists is None else _as_q(exists),
        plan=plan,
        closed=True,
        identity=_bound_permission_identity(
            permission, content.__class__, permission_model,
        ),
        values=values,
    )
    if checked.predicate is None:
        return None
    return _trusts_eligibility_q(user_model) & checked.predicate


def _plan_user_model(plan, content):
    """One concrete candidate-user model shared by every reverse branch."""
    models = {
        record.user_model._meta.concrete_model for record in plan.records
    }
    models.update(
        record.delegate_model._meta.concrete_model
        for record in plan.delegations
    )
    if len(models) != 1:
        raise TrustsConfigurationError(
            'Reverse permission inquiry for %s requires one registered '
            'candidate user model.' % content._meta.label
        )
    return models.pop()


def _permission_binding_for_plan(accepts_permission, content, perm, plan):
    """Return ``(binding, condition)``.

    ``accepts_permission`` is the singular-permission callable, or
    ``None`` for the mixin default (``auth.Permission``).
    ``condition`` is ``None`` or ``(singular_perm, code)``. A string
    binding is an unevaluated ``auth.Permission`` subquery. A model
    instance is that permission row.
    """
    permission_model = plan.permission_model
    if isinstance(perm, str):
        try:
            applabel, modelname, action, code = parse_perm_code(perm)
        except (ValueError, AttributeError):
            return None
        if (
            permission_model is not None
            and permission_model is not Permission
        ):
            return None
        binding = permission_binding(perm, content.__class__)
        if not code:
            return binding, None
        singular = '%s.%s_%s' % (applabel, action, modelname)
        return binding, (singular, code)
    if isinstance(perm, Model) and perm.pk is None:
        return None
    if accepts_permission is None:
        accepted = isinstance(perm, Permission)
    else:
        accepted = bool(accepts_permission(perm))
    if not accepted:
        return None
    if (
        permission_model is not None
        and perm._meta.concrete_model is not permission_model
    ):
        return None
    return perm, None


def _named_filter_q(named_filters, content, code, singular, user_model):
    """User-queryset ``Q``, ``True``, or ``None`` (fail closed).

    ``named_filters`` maps ``(model label, code)`` to ``(model, tree)``.
    ``None`` means this catalog grants nobody for this condition, matching
    a singular object check that returns false. Object-side fields are a
    subquery on the saved row. Construction does not query.
    """
    stored = named_filters.get(
        (condition_model_key(content.__class__), code),
    )
    if stored is None:
        return None
    _model, expr = stored
    return _condition_outcome(expr, content, singular, user_model)


def _condition_outcome(expr, content, singular, user_model):
    if isinstance(expr, Tree) and expr.kind == 'and':
        return _combine_and(
            _condition_outcome(expr.left, content, singular, user_model),
            _condition_outcome(expr.right, content, singular, user_model),
        )
    if isinstance(expr, Tree) and expr.kind == 'or':
        return _combine_or(
            _condition_outcome(expr.left, content, singular, user_model),
            _condition_outcome(expr.right, content, singular, user_model),
        )
    if isinstance(expr, Tree) and expr.kind in ('eq', 'ne'):
        return _comparison_outcome(
            expr, content, singular, user_model,
            equal=expr.kind == 'eq',
        )
    if isinstance(expr, Tree) and expr.kind == 'contains':
        return _contains_outcome(expr, content, singular, user_model)
    if isinstance(expr, Tree) and expr.kind == 'bare':
        return _bare_outcome(expr, content, singular, user_model)
    if isinstance(expr, Tree) and expr.kind == 'not':
        return _negated_outcome(expr, content, singular, user_model)
    raise TrustsConfigurationError(
        'Reverse permission inquiry cannot compile permission condition %r.'
        % (expr,)
    )


def _combine_and(left, right):
    if left is None or right is None:
        return None
    if left is True:
        return right
    if right is True:
        return left
    return left & right


def _combine_or(left, right):
    if left is True or right is True:
        return True
    if left is None:
        return right
    if right is None:
        return left
    return left | right


def _contains_outcome(expr, content, singular, user_model):
    left = expr.left
    right = expr.right
    if left.root == 'user':
        lookup = resolve_field_path(
            user_model, left.path, ref_kind='principal', collection=True,
        )
        if _is_field(right, 'user'):
            return contains_q(
                lookup, F(_user_lookup(user_model, right.path)),
            )
        if _is_field(right, 'object'):
            member = _object_lookup(content, right.path)
            saved = _saved_rows(content).filter(
                **{'%s__isnull' % member: False},
            )
            return Q(**{'%s__in' % lookup: saved.values(member)})
        pk = member_pk(_side_value(right, content, singular, user_model))
        if pk is None:
            return None
        return contains_q(lookup, pk)
    if left.root != 'object':
        raise TrustsConfigurationError(
            'Reverse permission inquiry cannot compile permission condition '
            'node %r.' % (left,)
        )
    lookup = _object_lookup(content, left.path, collection=True)
    if _is_field(right, 'user'):
        member = _user_lookup(user_model, right.path)
        return _exists_q(content, Q(**{lookup: OuterRef(member)}))
    if _is_field(right, 'object'):
        other = _object_lookup(content, right.path)
        return _exists_q(content, contains_q(lookup, F(other)))
    pk = member_pk(_side_value(right, content, singular, user_model))
    if pk is None:
        return None
    return _exists_q(content, contains_q(lookup, pk))


def _bare_outcome(expr, content, singular, user_model):
    field = expr.item
    if field.root == 'user':
        return boolean_q(_user_lookup(user_model, field.path))
    if field.root == 'object':
        lookup = _object_lookup(content, field.path)
        return _exists_q(content, boolean_q(lookup))
    if boolean_holds(_side_value(field, content, singular, user_model)):
        return True
    return None


def _negated_outcome(expr, content, singular, user_model):
    inner = _condition_outcome(expr.item, content, singular, user_model)
    if inner is True:
        return None
    if inner is None:
        return True
    return negate_q(user_model, inner)


def _side_value(node, content, singular, user_model):
    kind, value = _condition_side(node, content, singular, user_model)
    if kind == 'user' or kind == 'object':
        raise TrustsConfigurationError(
            'Reverse permission inquiry cannot compile permission condition '
            'node %r.' % (node,)
        )
    return value


def _comparison_outcome(expr, content, singular, user_model, *, equal):
    left = _condition_side(expr.left, content, singular, user_model)
    right = _condition_side(expr.right, content, singular, user_model)
    if left[0] == 'user' and right[0] == 'user':
        return columns_q(left[1], right[1], equal)
    if left[0] == 'object' or right[0] == 'object':
        return _object_comparison(content, left, right, equal)
    fields = 'const' not in (left[0], right[0])
    if left[0] == 'user' or right[0] == 'user':
        column, other = (left, right) if left[0] == 'user' else (right, left)
        return column_q(column[1], other[1], equal, field=fields)
    if values_match(left[1], right[1], equal, fields=fields):
        return True
    return None


def _condition_side(node, content, singular, user_model):
    if isinstance(node, Tree) and node.kind == 'const':
        return ('const', node.value)
    if _is_field(node, 'object'):
        return ('object', _object_lookup(content, node.path))
    if _is_field(node, 'permission'):
        if node.path:
            raise TrustsConfigurationError(
                'Permission references cannot traverse attributes.'
            )
        return ('value', singular)
    if _is_field(node, 'user'):
        return ('user', _user_lookup(user_model, node.path))
    raise TrustsConfigurationError(
        'Reverse permission inquiry cannot compile permission condition '
        'node %r.' % (node,)
    )


def _is_field(node, root):
    return isinstance(node, Tree) and node.kind == 'field' and node.root == root


def _object_lookup(content, path, *, collection=False):
    """Saved-row lookup for one object path. One rule for every hop."""
    if content.pk is None:
        raise PermissionConditionError('Save the object first.')
    return resolve_field_path(
        content.__class__, path, ref_kind='object', collection=collection,
    )


def _saved_rows(content):
    model = content._meta.concrete_model
    return model._default_manager.filter(pk=content.pk)


def _exists_q(content, q):
    return Q(Exists(_saved_rows(content).filter(q)))


def _object_comparison(content, left, right, equal):
    if left[0] == 'user' or right[0] == 'user':
        user_side, object_side = (
            (left, right) if left[0] == 'user' else (right, left)
        )
        return _user_object_q(
            content, user_side[1], object_side[1], equal,
        )
    if left[0] == 'object' and right[0] == 'object':
        return _exists_q(content, columns_q(left[1], right[1], equal))
    object_side, other = (
        (left, right) if left[0] == 'object' else (right, left)
    )
    fields = other[0] != 'const'
    return _exists_q(
        content,
        column_q(object_side[1], other[1], equal, field=fields),
    )


def _user_object_q(content, user_lookup, object_lookup, equal):
    """User column against one saved object column. NULL never matches."""
    rows = _saved_rows(content)
    matched = rows.filter(**{object_lookup: OuterRef(user_lookup)})
    if equal:
        return Q(Exists(matched))
    present = rows.filter(**{'%s__isnull' % object_lookup: False})
    return (
        Q(**{'%s__isnull' % user_lookup: False})
        & Q(Exists(present))
        & ~Q(Exists(matched))
    )


def _concrete_field(model, name):
    try:
        field = model._meta.get_field(name)
    except FieldDoesNotExist:
        return None
    if not getattr(field, 'concrete', False) or getattr(field, 'many_to_many', False):
        return None
    return field


def assert_persisted_principal(model):
    """Require the reverse-user boolean columns this inquiry compiles."""
    for name in ('is_anonymous', 'is_authenticated', 'is_active'):
        _principal_presence(model, name)


def _principal_presence(model, name):
    """How ``name`` is visible to SQL.

    ``field`` is a concrete boolean column. ``stock`` is
    ``AbstractBaseUser``'s property, which the Python shortcut evaluates
    without a column. ``absent`` uses the ``getattr`` default. Any other
    Python attribute fails closed.
    """
    field = _concrete_field(model, name)
    if field is not None:
        if field.get_internal_type() != 'BooleanField':
            raise TrustsConfigurationError(
                'Reverse permission inquiry needs %s.%s as a concrete '
                'BooleanField.' % (model._meta.label, name)
            )
        return 'field'
    found = None
    for cls in model.__mro__:
        if name in cls.__dict__:
            found = cls.__dict__[name]
            break
    if found is None:
        return 'absent'
    if found is AbstractBaseUser.__dict__.get(name):
        return 'stock'
    raise TrustsConfigurationError(
        '%s.%s is not a concrete BooleanField or the stock '
        'AbstractBaseUser property, so get_permitted_users cannot '
        'match has_perm in SQL.' % (model._meta.label, name)
    )


def _trusts_eligibility_q(model):
    """Anonymous and authenticated columns on a reverse candidate user.

    Registered user conditions and the override are bound by
    ``bind_checked_user``. Persisted rows use the stock
    anonymous/authenticated properties unless those names are concrete
    fields. The predicate is standard boolean SQL.
    """
    anonymous = _principal_presence(model, 'is_anonymous')
    authenticated = _principal_presence(model, 'is_authenticated')
    predicate = Q()
    if anonymous == 'field':
        predicate &= Q(is_anonymous=False)
    if authenticated == 'field':
        predicate &= Q(is_authenticated=True)
    return predicate


def _user_lookup(user_model, path):
    if not path:
        return 'pk'
    return resolve_field_path(user_model, path, ref_kind='principal')
