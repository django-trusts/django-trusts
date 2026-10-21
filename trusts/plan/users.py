"""Object-to-users compiler: one content object and one permission to users.

The permission row is canonical. A string is resolved inside the eventual
SQL. Construction does not query.
"""

__all__ = []

from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import Permission
from django.core.exceptions import FieldDoesNotExist
from django.db.models import F, Model, Q, QuerySet

from trusts.plan.conditions import (
    _condition_model_key,
    parse_perm_code,
    permission_binding,
    resolve_field_path,
)
from trusts.plan.writers import (
    _boolean_holds,
    _boolean_q,
    _collection_contains_q,
    _load_collection,
    _member_pk,
    _negate_q,
    column_q,
    columns_q,
    values_match,
)
from trusts.plan.predicates import contains_q
from trusts.plan.rewrites import bind_once
from trusts.errors import TrustsConfigurationError
from trusts.plan.contents import _as_q, _ordinary_records
from trusts.plan.relations import _bound_permission_identity, bind_checked_user
from trusts.plan.aggregates import _delegated_user_exists
from trusts.plan.grammar import Tree, missing_field



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


def lock_permitted_users_queryset(catalog, content, permission):
    """Backend-local reverse queryset compiled into the policy lock.

    This is the backend branch (eligibility and complete grants), not
    Django's outer superuser rule and not other backends. ``permission``
    is the permission-row sentinel, classified as ``permission.<target>``.
    Content is classified as ``content.<target>``.
    """
    plan = catalog.plan_for(content)
    if not plan.records and not plan.delegations:
        raise TrustsConfigurationError(
            'Policy SQL found no permitted-users query for %s.'
            % content._meta.label
        )
    user_model = _plan_user_model(plan, content)
    exists = plan.user_exists(content, permission) if plan.records else None
    if plan.delegations:
        permission_model = (
            permission._meta.concrete_model
            if isinstance(permission, Model) else None
        )
        delegated = _delegated_user_exists(
            plan.delegations,
            _ordinary_records(
                catalog, content, permission_model,
            ),
            content,
            permission,
            content_identity=plan.content_identity,
        )
        if delegated is not None:
            exists = (
                delegated if exists is None else (_as_q(exists) | delegated)
            )
    if plan.user_rules_closed is None:
        return user_model._default_manager.all().filter(pk__isnull=True)
    predicate = _reverse_checked(
        plan, exists, user_model, permission, content, {},
        plan.permission_model,
    )
    if predicate is None:
        raise TrustsConfigurationError(
            'Policy SQL found no permitted-users query for %s.'
            % content._meta.label
        )
    return bind_once(
        user_model._default_manager.all().filter(predicate).distinct(),
        user_model=catalog.user_model,
    )


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
        applabel, modelname, action, code = parse_perm_code(perm)
        if (
            permission_model is not None
            and permission_model is not Permission
        ):
            raise TrustsConfigurationError(
                'Permission string %r resolves through auth.Permission, '
                'but %s registrations use %s.'
                % (perm, content._meta.label, permission_model._meta.label)
            )
        binding = permission_binding(perm, content.__class__)
        if not code:
            return binding, None
        singular = '%s.%s_%s' % (applabel, action, modelname)
        return binding, (singular, code)
    if accepts_permission is None:
        accepted = isinstance(perm, Permission)
    else:
        accepted = bool(accepts_permission(perm))
    if not accepted:
        raise TrustsConfigurationError(
            '%s is not accepted as a singular object permission.'
            % type(perm).__name__
        )
    if (
        permission_model is not None
        and perm._meta.concrete_model is not permission_model
    ):
        raise TrustsConfigurationError(
            'Permission instance is %s; registrations for %s use %s.'
            % (
                perm._meta.label,
                content._meta.label,
                permission_model._meta.label,
            )
        )
    return perm, None


def _named_filter_q(named_filters, content, code, singular, user_model):
    """User-queryset ``Q``, ``True``, or ``None`` (fail closed).

    ``named_filters`` maps ``(model label, code)`` to ``(model, tree)``.
    ``None`` means this catalog grants nobody for this condition, matching
    a singular object check that returns false. Construction reads only
    values already loaded on ``content``.
    """
    stored = named_filters.get(
        (_condition_model_key(content.__class__), code),
    )
    if stored is None:
        return None
    _model, expr = stored
    if expr is None:
        raise TrustsConfigurationError(
            'Permission condition on %s is unbound.' % content._meta.label
        )
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
        if (
            isinstance(right, Tree)
            and right.kind == 'field'
            and right.root == 'user'
        ):
            return contains_q(
                lookup, F(_user_lookup(user_model, right.path)),
            )
        pk = _member_pk(_side_value(right, content, singular, user_model))
        if pk is None:
            return None
        return contains_q(lookup, pk)
    manager = _load_collection(
        left, None, content, content.__class__, user_model,
    )
    if (
        isinstance(right, Tree)
        and right.kind == 'field'
        and right.root == 'user'
    ):
        if manager is None:
            return None
        member = _user_lookup(user_model, right.path)
        return Q(**{'%s__in' % member: manager.values('pk')})
    return _collection_contains_q(
        manager, _member_pk(_side_value(right, content, singular, user_model)),
    )


def _bare_outcome(expr, content, singular, user_model):
    field = expr.item
    if field.root == 'user':
        return _boolean_q(_user_lookup(user_model, field.path))
    if _boolean_holds(_side_value(field, content, singular, user_model)):
        return True
    return None


def _negated_outcome(expr, content, singular, user_model):
    inner = _condition_outcome(expr.item, content, singular, user_model)
    if inner is True:
        return None
    if inner is None:
        return True
    return _negate_q(user_model, inner)


def _side_value(node, content, singular, user_model):
    kind, value = _condition_side(node, content, singular, user_model)
    if kind == 'user':
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
    if isinstance(node, Tree) and node.kind == 'field' and node.root == 'object':
        return ('value', _object_memory_value(content, node.path))
    if isinstance(node, Tree) and node.kind == 'field' and node.root == 'permission':
        if node.path:
            raise TrustsConfigurationError(
                'Permission references cannot traverse attributes.'
            )
        return ('value', singular)
    if isinstance(node, Tree) and node.kind == 'field' and node.root == 'user':
        return ('user', _user_lookup(user_model, node.path))
    raise TrustsConfigurationError(
        'Reverse permission inquiry cannot compile permission condition '
        'node %r.' % (node,)
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


def _object_memory_value(instance, path):
    """Field value already present on ``instance``. Does not query."""
    if not path:
        return instance
    current = instance
    model = instance.__class__
    for index, name in enumerate(path):
        try:
            field = model._meta.get_field(name)
        except FieldDoesNotExist as exc:
            raise missing_field(
                'condition', path[:index + 1], name, model,
            ) from exc
        last = index == len(path) - 1
        if field.many_to_many or field.one_to_many:
            raise TrustsConfigurationError(
                'Reverse permission inquiry cannot compile multi-valued '
                'condition field %s.%s.' % (model._meta.label, name)
            )
        if not last and getattr(field, 'is_relation', False):
            raise TrustsConfigurationError(
                'Reverse permission inquiry cannot traverse %s.%s without '
                'a construction query.' % (model._meta.label, name)
            )
        attname = field.attname
        if attname not in current.__dict__:
            raise TrustsConfigurationError(
                'Reverse permission inquiry needs %s.%s loaded on the '
                'content instance to compile a named filter without SQL.'
                % (model._meta.label, attname)
            )
        current = current.__dict__[attname]
        if not last:
            raise TrustsConfigurationError(
                'Reverse permission inquiry cannot traverse %s.%s.'
                % (model._meta.label, name)
            )
    return current


def _user_lookup(user_model, path):
    if not path:
        return 'pk'
    current = user_model
    for index, name in enumerate(path):
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist as exc:
            raise missing_field(
                'condition', path[:index + 1], name, current,
            ) from exc
        if field.many_to_many or field.one_to_many:
            raise TrustsConfigurationError(
                'Reverse permission inquiry cannot compile multi-valued '
                'principal field %s.%s.' % (current._meta.label, name)
            )
        if getattr(field, 'is_relation', False) and field.related_model is not None:
            current = field.related_model
    return '__'.join(path)
