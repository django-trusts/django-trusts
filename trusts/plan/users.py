"""Object-to-users compiler: one content object and one permission to users.

``trusts.reverse`` re-exports the names callers already import.

Private compiler for ``content.get_permitted_users(perm)`` and
``User.objects.permitted(content, perm)``. Both adapters call
``compile_permitted_users``. The permission row is canonical. A string is
resolved inside the eventual SQL. Construction does not query.
"""

__all__ = []

from django.contrib.auth import get_backends, get_user_model
from django.contrib.auth.backends import (
    AllowAllUsersModelBackend,
    AllowAllUsersRemoteUserBackend,
    ModelBackend,
    RemoteUserBackend,
)
from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import Permission
from django.core.exceptions import FieldDoesNotExist
from django.db import router
from django.db.models import F, Model, Q, QuerySet

from trusts.utils import parse_perm_code
from trusts._bind_once import bind_once
from trusts.backends import TrustModelBackendMixin, _permission_binding
from trusts.errors import TrustsConfigurationError
from trusts.plan.contents import _as_q, _ordinary_records
from trusts.plan.relations import _bound_permission_identity, bind_checked_user
from trusts.commons import _object_memory_value, _user_lookup
from trusts.plan.aggregates import _delegated_user_exists
from trusts.plan import conditions as _ir


_OBJECT_BLIND_BACKENDS = None


def compile_permitted_users(content, perm, *, user_queryset=None, **skip_flags):
    """Lazy user queryset for one saved content object and one permission.

    The candidate rows are ``user_queryset`` when given (the optional
    manager adapter) and otherwise ``AUTH_USER_MODEL``'s default manager.
    Each configured backend that can contribute an exact reverse predicate
    is OR-ed. A registered user override is part of the Trusts-owned
    predicate, not a separate superuser grant. The ``is_active`` check
    applies inside the Trusts-owned branch only. A custom predicate is
    not wrapped. ``skip_<name>=True`` sets that bound parameter. The
    values are forwarded only to the Trusts-owned mixin method.
    Django's ``PermissionsMixin.has_perm`` early return is
    not copied here. An unsupported object-permission backend raises
    before SQL.
    """
    # Call-time: tests patch this on ``trusts.apps``. A top-level import
    # would snapshot the real function. Sibling handles are not injected
    # into the registry, so this lookup stays the patch point.
    from trusts.apps import _relationship_implementation_handles

    _require_saved_content(content)
    _reject_permission_shape(perm)
    inquiry = bind_checked_user(
        None, skip_flags=skip_flags,
        handles=_relationship_implementation_handles(),
        require_user=False,
    )
    skipped = inquiry.values
    if user_queryset is None:
        user_queryset = get_user_model()._default_manager.get_queryset()
    elif not isinstance(user_queryset, QuerySet):
        raise TrustsConfigurationError(
            'user queryset must be a QuerySet, not %r.' % (user_queryset,)
        )
    backends = tuple(get_backends())
    _reject_unaccepted_permission_instance(perm, backends)
    user_model = user_queryset.model
    _assert_persisted_principal(user_model)
    parts = []
    involved = [user_model, content.__class__]
    if isinstance(perm, (str, Permission)):
        involved.append(Permission)
    for backend in backends:
        predicate = _backend_predicate(
            backend, content, perm,
            skipped=skipped,
        )
        if predicate is None:
            continue
        if not isinstance(predicate, Q):
            raise TrustsConfigurationError(
                '%s permitted_users_predicate returned %s, not a Q or None.'
                % (type(backend).__name__, type(predicate).__name__)
            )
        _assert_registration_user_model(backend, content, user_model)
        involved.extend(_registration_models(backend, content))
        parts.append(predicate)
    alias = _database_alias(content, user_queryset)
    _assert_same_database(alias, involved)
    if user_queryset.db != alias:
        user_queryset = user_queryset.using(alias)
    if not parts:
        combined = Q(pk__isnull=True)
    else:
        combined = parts[0]
        for part in parts[1:]:
            combined |= part
    return bind_once(user_queryset.filter(combined).distinct())


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


def trusts_mixin_predicate(backend, content, perm, *,
                           skipped=()):
    """Complete-path reverse predicate for one ``TrustModelBackendMixin``."""
    # Same call-time patch point as ``compile_permitted_users``.
    from trusts.apps import _relationship_implementation_handles

    handle = backend._own_handle()
    plan = handle.registry.plan_for(content)
    if not plan.records and not plan.delegations:
        return None
    binding, condition = _permission_binding_for_plan(
        backend, content, perm, plan,
    )
    exists = plan.user_exists(content, binding) if plan.records else None
    if plan.delegations:
        permission_model = (
            binding._meta.concrete_model
            if isinstance(binding, Model) else Permission
        )
        sponsor_records = _ordinary_records(
            _relationship_implementation_handles(), content, permission_model,
        )
        delegated = _delegated_user_exists(
            plan.delegations, sponsor_records, content, binding,
            content_identity=getattr(plan, 'content_identity', None),
            skipped=skipped,
        )
        if delegated is not None:
            exists = delegated if exists is None else (_as_q(exists) | delegated)
    user_model = _plan_user_model(plan, content)
    permission_model = plan.permission_model
    if permission_model is None and not isinstance(binding, Model):
        permission_model = Permission
    predicate = _reverse_checked(
        plan, exists, user_model, binding, content, skipped, permission_model,
    )
    if predicate is None:
        return None
    if condition:
        overlay = _named_filter_q(
            backend, content, perm, condition[0], user_model,
        )
        if overlay is None:
            return None
        if overlay is not True:
            predicate &= overlay
    return predicate


def lock_permitted_users_queryset(handle, content, permission, *, handles=None):
    """Backend-local reverse queryset compiled into the policy lock.

    This is the backend branch (eligibility and complete grants), not
    Django's outer superuser rule and not other backends. ``permission``
    is the permission-row sentinel, classified as ``permission.<target>``.
    Content is classified as ``content.<target>``.
    """
    plan = handle.registry.plan_for(content)
    if not plan.records and not plan.delegations:
        raise TrustsConfigurationError(
            'Policy SQL found no permitted-users query for %s.'
            % content._meta.label
        )
    user_model = _plan_user_model(plan, content)
    exists = plan.user_exists(content, permission) if plan.records else None
    if plan.delegations:
        sponsor_handles = (handle,) if handles is None else tuple(handles)
        permission_model = (
            permission._meta.concrete_model
            if isinstance(permission, Model) else None
        )
        delegated = _delegated_user_exists(
            plan.delegations,
            _ordinary_records(
                sponsor_handles, content, permission_model,
            ),
            content,
            permission,
            content_identity=getattr(plan, 'content_identity', None),
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


def _require_saved_content(content):
    if isinstance(content, QuerySet):
        raise TrustsConfigurationError(
            'get_permitted_users accepts one saved content object, '
            'not a queryset.'
        )
    if not isinstance(content, Model):
        raise TrustsConfigurationError(
            'content must be a saved model instance, not %r.' % (content,)
        )
    if content.pk is None:
        raise TrustsConfigurationError(
            'content must be a saved %s instance.' % content._meta.label
        )


def _reject_permission_shape(perm):
    if isinstance(perm, QuerySet):
        raise TrustsConfigurationError(
            'get_permitted_users accepts one permission, not a queryset.'
        )
    if isinstance(perm, (str, Model)):
        if isinstance(perm, Model) and perm.pk is None:
            raise TrustsConfigurationError(
                'permission must be a saved %s instance.' % perm._meta.label
            )
        return
    raise TrustsConfigurationError(
        'permission must be a permission string or model instance, not %r.'
        % (perm,)
    )


def _object_blind_backends():
    global _OBJECT_BLIND_BACKENDS
    if _OBJECT_BLIND_BACKENDS is None:
        _OBJECT_BLIND_BACKENDS = frozenset((
            ModelBackend,
            AllowAllUsersModelBackend,
            RemoteUserBackend,
            AllowAllUsersRemoteUserBackend,
        ))
    return _OBJECT_BLIND_BACKENDS


def _trusts_owned_reverse_hook(backend):
    """True when the reverse hook is the mixin method, not an override.

    The skipped condition names are passed only through that Trusts-owned
    method. Other hooks are called as
    ``permitted_users_predicate(content, perm)``. Trusts does not require
    them to accept ``skip_<name>`` and does not raise when they do not.
    """
    if not isinstance(backend, TrustModelBackendMixin):
        return False
    return (
        type(backend).permitted_users_predicate
        is TrustModelBackendMixin.permitted_users_predicate
    )


def _backend_predicate(backend, content, perm, *,
                       skipped=()):
    if getattr(backend, 'trusts_object_permissions', None) is False:
        return None
    if _declares_reverse_hook(backend):
        if _trusts_owned_reverse_hook(backend):
            return backend.permitted_users_predicate(
                content, perm, skipped=skipped,
            )
        return backend.permitted_users_predicate(content, perm)
    if type(backend) in _object_blind_backends():
        return None
    if not callable(getattr(backend, 'has_perm', None)):
        return None
    raise TrustsConfigurationError(
        '%s may grant an object permission but cannot express an exact '
        'reverse user predicate. get_permitted_users will not return a '
        'partial result.' % type(backend).__name__
    )


def _reject_unaccepted_permission_instance(perm, backends):
    if not isinstance(perm, Model) or isinstance(perm, Permission):
        return
    for backend in backends:
        checker = getattr(backend, 'singular_permission_accepted', None)
        if callable(checker) and checker(perm):
            return
    raise TrustsConfigurationError(
        '%s is not a permission identity accepted by a configured '
        'object-permission backend.' % type(perm).__name__
    )


def _declares_reverse_hook(backend):
    for cls in type(backend).__mro__:
        if 'permitted_users_predicate' in cls.__dict__:
            return True
    return False


def _permission_binding_for_plan(backend, content, perm, plan):
    """Return ``(binding, condition)``.

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
        binding = _permission_binding(perm, content.__class__)
        if not code:
            return binding, None
        singular = '%s.%s_%s' % (applabel, action, modelname)
        return binding, (singular, code)
    accepted = False
    checker = getattr(backend, 'singular_permission_accepted', None)
    if callable(checker):
        accepted = bool(checker(perm))
    if not accepted:
        raise TrustsConfigurationError(
            '%s does not accept %s as a singular object permission.'
            % (type(backend).__name__, type(perm).__name__)
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


def _named_filter_q(backend, content, perm, singular, user_model):
    """User-queryset ``Q``, ``True``, or ``None`` (fail closed).

    ``None`` means this backend grants nobody for this condition, matching
    a singular object check that returns false. Construction reads only
    values already loaded on ``content``.
    """
    record, _extra = backend._condition_overlay(perm, content, None)
    if record is None:
        return None
    expr = getattr(record, 'expr', None)
    if expr is None:
        raise TrustsConfigurationError(
            'Permission condition on %s is unbound.' % content._meta.label
        )
    outcome = _condition_outcome(expr, content, singular, user_model)
    return outcome


def _condition_outcome(expr, content, singular, user_model):
    if isinstance(expr, _ir.And):
        return _combine_and(
            _condition_outcome(expr.left, content, singular, user_model),
            _condition_outcome(expr.right, content, singular, user_model),
        )
    if isinstance(expr, _ir.Or):
        return _combine_or(
            _condition_outcome(expr.left, content, singular, user_model),
            _condition_outcome(expr.right, content, singular, user_model),
        )
    if isinstance(expr, (_ir.Eq, _ir.Ne)):
        return _comparison_outcome(
            expr, content, singular, user_model,
            equal=isinstance(expr, _ir.Eq),
        )
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


def _comparison_outcome(expr, content, singular, user_model, *, equal):
    left = _condition_side(expr.left, content, singular, user_model)
    right = _condition_side(expr.right, content, singular, user_model)
    if left[0] == 'const' and right[0] == 'const':
        matches = left[1] == right[1]
        return True if matches == equal else None
    if left[0] == 'user' and right[0] == 'user':
        return _user_fields_q(left[1], right[1], equal)
    if left[0] == 'user':
        return _user_const_q(left[1], right[1], equal)
    if right[0] == 'user':
        return _user_const_q(right[1], left[1], equal)
    raise TrustsConfigurationError(
        'Reverse permission inquiry cannot compile permission condition %r.'
        % (expr,)
    )


def _condition_side(node, content, singular, user_model):
    if isinstance(node, _ir.Const):
        return ('const', node.value)
    if isinstance(node, _ir.Ref) and node.source == 'object':
        return ('const', _object_memory_value(content, node.path))
    if isinstance(node, _ir.Ref) and node.source == 'permission':
        if node.path:
            raise TrustsConfigurationError(
                'Permission references cannot traverse attributes.'
            )
        return ('const', singular)
    if isinstance(node, _ir.Ref) and node.source == 'principal':
        return ('user', _user_lookup(user_model, node.path))
    raise TrustsConfigurationError(
        'Reverse permission inquiry cannot compile permission condition '
        'node %r.' % (node,)
    )


def _user_const_q(lookup, value, equal):
    if isinstance(value, _ir.ModelIdentity):
        value = value.pk
    elif isinstance(value, Model):
        value = value.pk
    if value is None:
        return Q(**{'%s__isnull' % lookup: equal})
    if equal:
        return Q(**{lookup: value})
    return Q(**{'%s__isnull' % lookup: True}) | ~Q(**{lookup: value})


def _user_fields_q(left, right, equal):
    if equal:
        return (
            (Q(**{'%s__isnull' % left: True}) & Q(**{'%s__isnull' % right: True}))
            | (
                Q(**{'%s__isnull' % left: False})
                & Q(**{'%s__isnull' % right: False})
                & Q(**{left: F(right)})
            )
        )
    return (
        (Q(**{'%s__isnull' % left: True}) & Q(**{'%s__isnull' % right: False}))
        | (Q(**{'%s__isnull' % left: False}) & Q(**{'%s__isnull' % right: True}))
        | (
            Q(**{'%s__isnull' % left: False})
            & Q(**{'%s__isnull' % right: False})
            & ~Q(**{left: F(right)})
        )
    )


def _concrete_field(model, name):
    try:
        field = model._meta.get_field(name)
    except FieldDoesNotExist:
        return None
    if not getattr(field, 'concrete', False) or getattr(field, 'many_to_many', False):
        return None
    return field


def _assert_persisted_principal(model):
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


def _assert_registration_user_model(backend, content, user_model):
    if not isinstance(backend, TrustModelBackendMixin):
        return
    plan = backend._own_handle().registry.plan_for(content)
    expected = user_model._meta.concrete_model
    for record in plan.records:
        registered = record.user_model._meta.concrete_model
        if registered is not expected:
            raise TrustsConfigurationError(
                'Reverse permission inquiry candidate user model is %s, '
                'but %s registers %s.'
                % (
                    expected._meta.label,
                    record.root._meta.label,
                    registered._meta.label,
                )
            )
    for record in plan.delegations:
        registered = record.delegate_model._meta.concrete_model
        if registered is not expected:
            raise TrustsConfigurationError(
                'Reverse permission inquiry candidate user model is %s, '
                'but %s registers delegate %s.'
                % (
                    expected._meta.label,
                    record.root._meta.label,
                    registered._meta.label,
                )
            )


def _registration_models(backend, content):
    if not isinstance(backend, TrustModelBackendMixin):
        return []
    plan = backend._own_handle().registry.plan_for(content)
    models = []
    for record in plan.records:
        models.extend((
            record.root,
            record.user_model,
            record.permission_model,
            record.content_model,
        ))
    for record in plan.delegations:
        models.extend((
            record.root,
            record.delegate_model,
            record.sponsor_model,
            record.content_model,
        ))
        if record.condition_permission_model is not None:
            models.append(record.condition_permission_model)
    return models


def _database_alias(content, user_queryset):
    state_db = getattr(getattr(content, '_state', None), 'db', None) or None
    if state_db:
        return state_db
    routed = router.db_for_read(user_queryset.model)
    if routed:
        return routed
    return user_queryset.db or 'default'


def _assert_same_database(alias, models):
    seen = set()
    for model in models:
        concrete = model._meta.concrete_model
        if concrete in seen:
            continue
        seen.add(concrete)
        chosen = router.db_for_read(concrete)
        if chosen is not None and chosen != alias:
            raise TrustsConfigurationError(
                'Reverse permission inquiry cannot join %s on database %r; '
                'the router selected %r. Cross-database authorization is '
                'not one SQL statement.'
                % (concrete._meta.label, alias, chosen)
            )
