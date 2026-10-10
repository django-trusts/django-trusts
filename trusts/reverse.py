"""Reverse permission inquiry: one content object and one permission to users.

Private compiler for ``content.get_permitted_users(perm)`` and
``User.objects.permitted(content, perm)``. Both adapters call
``compile_permitted_users``. The permission row is canonical. A string is
resolved inside the eventual SQL. Construction does not query.
"""

from django.contrib.auth.base_user import AbstractBaseUser
from django.contrib.auth.models import Permission
from django.core.exceptions import FieldDoesNotExist
from django.db.models import F, Model, Q, QuerySet

from trusts.core import (
    TrustsConfigurationError,
    _as_q,
    _delegated_user_exists,
    _ordinary_records,
)


_OBJECT_BLIND_BACKENDS = None


def compile_permitted_users(content, perm, *, user_queryset=None):
    """Lazy user queryset for one saved content object and one permission.

    The candidate rows are ``user_queryset`` when given (the optional
    manager adapter) and otherwise ``AUTH_USER_MODEL``'s default manager.
    Django's active-superuser rule is OR-ed with each configured backend
    that can contribute an exact reverse predicate. An unsupported
    object-permission backend raises before SQL.
    """
    from django.contrib.auth import get_backends, get_user_model

    _require_saved_content(content)
    _reject_permission_shape(perm)
    if user_queryset is None:
        user_queryset = get_user_model()._default_manager.get_queryset()
    elif not isinstance(user_queryset, QuerySet):
        raise TrustsConfigurationError(
            'user queryset must be a QuerySet, not %r.' % (user_queryset,)
        )
    backends = tuple(get_backends())
    _reject_unaccepted_permission_instance(perm, backends)
    user_model = user_queryset.model
    _assert_superuser_fields(user_model)
    _assert_persisted_principal(user_model)
    parts = [_superuser_q(user_model)]
    involved = [user_model, content.__class__]
    if isinstance(perm, (str, Permission)):
        involved.append(Permission)
    for backend in backends:
        predicate = _backend_predicate(backend, content, perm)
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
    combined = parts[0]
    for part in parts[1:]:
        combined |= part
    return user_queryset.filter(combined).distinct()


def trusts_mixin_predicate(backend, content, perm):
    """Complete-path reverse predicate for one ``TrustModelBackendMixin``."""
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
        )
        if delegated is not None:
            exists = delegated if exists is None else (_as_q(exists) | delegated)
    if exists is None:
        return None
    user_model = _plan_user_model(plan, content)
    eligibility = _trusts_eligibility_q(user_model)
    if eligibility is None:
        return None
    predicate = eligibility & _as_q(exists)
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
            exists = delegated if exists is None else (_as_q(exists) | delegated)
    if exists is None:
        raise TrustsConfigurationError(
            'Policy SQL found no permitted-users query for %s.'
            % content._meta.label
        )
    user_model = _plan_user_model(plan, content)
    eligibility = _trusts_eligibility_q(user_model)
    if eligibility is None:
        # ``none()`` does not render. ``pk IS NULL`` is the same empty
        # set for a saved primary key and stays classifiable.
        return user_model._default_manager.all().filter(pk__isnull=True)
    predicate = eligibility & _as_q(exists)
    return user_model._default_manager.all().filter(predicate).distinct()


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
        from django.contrib.auth.backends import (
            AllowAllUsersModelBackend,
            AllowAllUsersRemoteUserBackend,
            ModelBackend,
            RemoteUserBackend,
        )

        _OBJECT_BLIND_BACKENDS = frozenset((
            ModelBackend,
            AllowAllUsersModelBackend,
            RemoteUserBackend,
            AllowAllUsersRemoteUserBackend,
        ))
    return _OBJECT_BLIND_BACKENDS


def _backend_predicate(backend, content, perm):
    if getattr(backend, 'trusts_object_permissions', None) is False:
        return None
    if _declares_reverse_hook(backend):
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
    from trusts import utils
    from trusts.backends import _permission_binding

    permission_model = plan.permission_model
    if isinstance(perm, str):
        applabel, modelname, action, code = utils.parse_perm_code(perm)
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
    from trusts.conditions import _ir

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
    from trusts.conditions import _ir

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
            raise TrustsConfigurationError(
                'Permission condition field %r is not on %s.'
                % (name, model._meta.label)
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
    for name in path:
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist as exc:
            raise TrustsConfigurationError(
                'Permission condition field %r is not on %s.'
                % (name, current._meta.label)
            ) from exc
        if field.many_to_many or field.one_to_many:
            raise TrustsConfigurationError(
                'Reverse permission inquiry cannot compile multi-valued '
                'principal field %s.%s.' % (current._meta.label, name)
            )
        if getattr(field, 'is_relation', False) and field.related_model is not None:
            current = field.related_model
    return '__'.join(path)


def _user_const_q(lookup, value, equal):
    from trusts.conditions._ir import ModelIdentity

    if isinstance(value, ModelIdentity):
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


def _require_boolean(model, name, role):
    field = _concrete_field(model, name)
    if field is None or field.get_internal_type() != 'BooleanField':
        raise TrustsConfigurationError(
            'Reverse permission inquiry needs %s.%s as a concrete '
            'BooleanField to compile the %s in SQL.'
            % (model._meta.label, name, role)
        )


def _assert_superuser_fields(model):
    _require_boolean(model, 'is_active', 'active-superuser rule')
    _require_boolean(model, 'is_superuser', 'active-superuser rule')


def _assert_persisted_principal(model):
    for name in ('is_anonymous', 'is_authenticated', 'is_active'):
        _principal_presence(model, name)


def _superuser_q(model):
    """Django's outer rule: active superusers, not a global is_active filter."""
    return Q(is_active=True, is_superuser=True)


def _principal_presence(model, name):
    """How ``name`` is visible to SQL.

    ``field`` is a concrete boolean column. ``stock`` is
    ``AbstractBaseUser``'s property, which ``is_active_principal``
    evaluates without a column. ``absent`` uses that helper's
    ``getattr`` default. Any other Python attribute fails closed.
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


def _active_principal_value():
    """``is_active`` value required of a non-superuser candidate.

    Reverse inquiry matches ``is_active_principal``. Issue #284 can
    negate this one value for ``allow_in_active=True``. Django's
    separate active-superuser rule stays in ``_superuser_q``.
    """
    return True


def _trusts_eligibility_q(model):
    """Eligibility of ``TrustModelBackendMixin.has_perm`` as SQL.

    ``is_active_principal`` denies anonymous, unauthenticated, and inactive
    principals. A missing ``is_active`` uses the same default as
    ``getattr(user, 'is_active', False)`` and contributes no users.
    Persisted rows use the stock anonymous/authenticated properties
    unless those names are concrete fields.
    """
    if _principal_presence(model, 'is_active') != 'field':
        _principal_presence(model, 'is_anonymous')
        _principal_presence(model, 'is_authenticated')
        return None
    predicate = Q(is_active=_active_principal_value())
    if _principal_presence(model, 'is_anonymous') == 'field':
        predicate &= Q(is_anonymous=False)
    if _principal_presence(model, 'is_authenticated') == 'field':
        predicate &= Q(is_authenticated=True)
    return predicate


def _assert_registration_user_model(backend, content, user_model):
    from trusts.backends import TrustModelBackendMixin

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
    from trusts.backends import TrustModelBackendMixin

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
    from django.db import router

    state_db = getattr(getattr(content, '_state', None), 'db', None) or None
    if state_db:
        return state_db
    routed = router.db_for_read(user_queryset.model)
    if routed:
        return routed
    return user_queryset.db or 'default'


def _assert_same_database(alias, models):
    from django.db import router

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
