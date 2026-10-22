"""Front over one built registry. Not a builder and not a second store."""

from functools import reduce
from operator import or_

from django.contrib.auth import get_backends
from django.contrib.auth.models import Permission
from django.db import router
from django.db.models import Model, Q, QuerySet, Subquery

from trusts.backends import TrustModelBackendMixin, configured_catalogs
from trusts.errors import PermissionConditionError, TrustsConfigurationError
from trusts.plan.conditions import (
    evaluate_registered_expression,
    parse_perm_code,
    permission_binding,
    permission_has_condition,
)
from trusts.plan.contents import _ordinary_records, granted, relationship_family
from trusts.plan.delegations import _sponsor_record_matches
from trusts.plan.relations import bind_checked_user, known_skip_names
from trusts.plan.rewrites import bind_once
from trusts.plan.users import assert_persisted_principal
import trusts.plan.standards as standards

_NO_PRESET = object()


_BACKENDS_THAT_IGNORE_THE_OBJECT = (
    'django.contrib.auth.backends.ModelBackend',
    'django.contrib.auth.backends.AllowAllUsersModelBackend',
    'django.contrib.auth.backends.RemoteUserBackend',
    'django.contrib.auth.backends.AllowAllUsersRemoteUserBackend',
)


class Catalog(object):
    """Answers one backend class from the registry the sweep built.

    Callers outside the backend obtain this object from
    ``TrustModelBackendMixin.get_catalog()``.
    """

    def __init__(self, *, cls, path, family, registry):
        self.cls = cls
        self.path = path
        self.family = family
        self._registry = registry

    @property
    def records(self):
        return self._registry.records

    @property
    def delegations(self):
        return self._registry.delegations

    @property
    def compiler(self):
        return self._registry.compiler

    @property
    def user_conditions(self):
        return self._registry.user_conditions

    @property
    def user_override(self):
        return self._registry.user_override

    def plan_for(self, content, *, user=None, permission=None):
        return self._registry.plan_for(
            content, user=user, permission=permission,
        )

    def iter_permission_conditions(self):
        return self._registry.iter_permission_conditions()

    def permissions_for(self, user, content, *, kind='complete', skipped=None,
                        **skip_flags):
        return self._registry.permissions_for(
            user, content, kind=kind, skipped=skipped, **skip_flags,
        )

    def walk_questions(self, visitor):
        return self._registry.walk_questions(visitor)

    def filter_by_permitted_content(self, queryset, user, permission, *,
                                    content, skipped=None, **skip_flags):
        """Scope rows that are a proper prefix of ``content`` for this catalog."""
        return self._registry.filter_by_permitted_content(
            queryset, user, permission, content=content,
            skipped=skipped, **skip_flags,
        )

    def authorization_preflight(self, model, conditions):
        """Zero-SQL ``(participating, owns_conditions)`` for this catalog.

        A catalog with no applicable ``auth.Permission`` plan contributes
        nothing.
        """
        plan = _auth_permission_plan_for_model(self._registry, model)
        if plan is None:
            return False, False
        return True, _owns_selected_conditions(
            self._registry, model, conditions,
        )

    def authorization_grant(self, candidates, user, model, permission,
                            conditions, binding, *, api, skipped=()):
        """This catalog's grant predicate and whether it owned the names.

        ``(None, False)`` when this catalog does not participate. The
        predicate is a ``Q`` when this catalog grants. ``owned`` is true
        when names were selected and this catalog registered every one.
        """
        registry = self._registry
        if _auth_permission_plan(registry, candidates, user) is None:
            return None, False
        if conditions:
            overlay = _selected_condition_q(
                registry, model, permission, conditions, user, api=api,
            )
            if overlay is None:
                return None, False
            part = granted(
                registry, candidates, user, binding, kind='complete',
                permission_model=Permission, skipped=skipped,
            )
            if part is None:
                return None, True
            return part & overlay, True
        part = granted(
            registry, candidates, user, binding, kind='complete',
            permission_model=Permission, skipped=skipped,
        )
        if part is None:
            return None, False
        return part, False

    def complete_grant_q(self, candidates, user, permission, *, skipped=()):
        """This catalog's complete grant predicate, or None when it grants nothing."""
        return granted(
            self._registry, candidates, user, permission,
            kind='complete', skipped=skipped,
        )

    def permitted_users_predicate(self, content, perm, *, skipped=(),
                                  accepts_permission=None):
        return self._registry.permitted_users_predicate(
            content, perm, skipped=skipped,
            filter_lookup=self._registry.filter_lookup,
            accepts_permission=accepts_permission,
        )

    def permitted_users(self, content, perm, **skip_flags):
        return self._registry.permitted_users(content, perm, **skip_flags)

    def has_perm(self, user_obj, permext, obj, **skip_flags):
        inquiry = bind_checked_user(
            user_obj, skip_flags=skip_flags, registry=self._registry,
        )
        if inquiry.denied:
            return False
        entry = self.prepare_has_perm(
            user_obj, permext, obj, skipped=inquiry.values,
        )
        return entry.execute()

    def get_all_permissions(self, user_obj, obj, **skip_flags):
        return self._permission_codes(
            user_obj, obj, skip_flags, kind='complete',
        )

    def get_group_permissions(self, user_obj, obj, **skip_flags):
        return self._permission_codes(
            user_obj, obj, skip_flags, kind='group',
        )

    def prepare_has_perm(self, user_obj, permext, obj, *, skipped):
        registry = self._registry
        model = _content_model(obj)
        if not registry.applies(registry.plan_for(obj, user=user_obj)):
            return PreparedInquiry(model, result=False)
        record, extra_q = self._condition_overlay(permext, obj, user_obj)
        applabel, modelname, action, _cond = parse_perm_code(permext)
        perm = '%s.%s_%s' % (applabel, action, modelname)
        if permission_has_condition(permext) and record is None:
            return PreparedInquiry(model, result=False)
        held = registry.has_permission(
            user_obj, obj, permission_binding(perm, model),
            extra_q=extra_q, permission_model=Permission,
            skipped=dict(skipped) if isinstance(skipped, dict) else {},
        )
        if not held:
            return PreparedInquiry(model, result=False)
        if record is None or extra_q is not None:
            return PreparedInquiry(model, result=True)
        return self.permission_condition_met(record, user_obj, perm, obj)

    def permission_condition_met(self, record, user_obj, perm, obj):
        model = _content_model(obj)
        if record.expr is None:
            label = _model_label(model)
            raise PermissionConditionError(
                'Permission condition on %s is unbound.' % label
            )
        if isinstance(obj, QuerySet):
            objs, model = obj.all(), obj.model
        elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
            objs, model = obj, None
        else:
            objs = [obj]
        met = all(
            evaluate_registered_expression(
                record.expr, user_obj, perm, item,
                model=model or item.__class__,
            )
            for item in objs
        )
        return PreparedInquiry(model, result=bool(met))

    def _permission_codes(self, user_obj, obj, skip_flags, *, kind):
        inquiry = bind_checked_user(
            user_obj, skip_flags=skip_flags, registry=self._registry,
        )
        if inquiry.denied:
            return set()
        qs = self.permissions_for(
            user_obj, obj, kind=kind,
            skipped=dict(inquiry.values) if isinstance(inquiry.values, dict) else {},
        )
        if qs is None or qs == ():
            return set()
        return _perm_codes(qs)

    def _condition_overlay(self, permext, obj, user_obj):
        if not permission_has_condition(permext):
            return None, None
        applabel, modelname, _action, cond = parse_perm_code(permext)
        model = _content_model(obj)
        lookup = self._registry.filter_lookup
        if lookup is None:
            if isinstance(obj, QuerySet):
                return None, None
            raise AttributeError(
                'Permission condition code "%s" is not associate with model "%s_%s"'
                % (cond, applabel, modelname)
            )
        record = lookup.record_for(model, cond)
        if record is None or not isinstance(obj, QuerySet):
            return record, None
        return record, lookup.compile_q(obj.model, permext, user_obj)


class PreparedInquiry(object):
    def __init__(self, model, result=_NO_PRESET, qs=None):
        self.model = model
        self.result = result
        self.qs = qs

    def execute(self):
        if self.result is not _NO_PRESET:
            return self.result
        return bool(self.qs.exists())


def relationship_catalogs():
    """Relationship catalogs from ``get_catalog()``, in listed-backend order."""
    return relationship_family(configured_catalogs())


def guard_permission_string(permission, *, api):
    """Exact ``app_label.codename`` form. Does not infer a model name."""
    if not isinstance(permission, str):
        raise TypeError(
            '%s permission must be an app_label.codename string, not %r.'
            % (api, type(permission).__name__)
        )
    if ':' in permission or permission.count('.') != 1:
        raise TrustsConfigurationError(
            '%s permission must be one base "app_label.codename" string '
            'without a colon: %r.' % (api, permission)
        )
    app_label, codename = permission.split('.')
    if not app_label or not codename:
        raise TrustsConfigurationError(
            '%s permission must be one base "app_label.codename" string, '
            'not %r.' % (api, permission)
        )
    return app_label, codename


def guard_conditions(conditions, *, api):
    if type(conditions) is not tuple:
        raise TypeError(
            '%s conditions must be an exact tuple, not %r.'
            % (api, type(conditions).__name__)
        )
    seen = set()
    for name in conditions:
        if not isinstance(name, str) or not name or name != name.strip() or ':' in name:
            raise TrustsConfigurationError(
                '%s condition name is malformed: %r.' % (api, name)
            )
        if name in seen:
            raise TrustsConfigurationError(
                '%s conditions must not contain duplicates: %r.'
                % (api, name)
            )
        seen.add(name)
    return conditions


def codename_binding(model, app_label, codename):
    """Unevaluated pk of the exact codename on ``model``'s content type."""
    return Subquery(
        Permission.objects.filter(
            content_type__app_label=app_label.lower(),
            content_type__model=model._meta.model_name,
            codename=codename,
        ).values('pk')[:1]
    )


def assert_authorization_preflight(catalogs, model, conditions, *, api):
    """Fail closed unless one catalog has a plan and owns the names."""
    participating = False
    for catalog in catalogs:
        has_plan, owns = catalog.authorization_preflight(model, conditions)
        if not has_plan:
            continue
        participating = True
        if owns:
            return
    if not participating:
        raise TrustsConfigurationError(
            '%s has no applicable auth.Permission plan for %s.'
            % (api, model._meta.label)
        )
    raise TrustsConfigurationError(
        '%s condition %r is not registered on %s.'
        % (api, conditions[0], model._meta.label)
    )


def authorization_grant_q(catalogs, candidates, user, model, permission,
                           conditions, binding, *, api, skipped=()):
    """OR each catalog's auth.Permission grant. Order does not matter."""
    parts = []
    complete = 0
    for catalog in catalogs:
        predicate, owned = catalog.authorization_grant(
            candidates, user, model, permission, conditions, binding,
            api=api, skipped=skipped,
        )
        if owned:
            complete += 1
        if predicate is not None:
            parts.append(predicate)
    if conditions and complete == 0:
        raise TrustsConfigurationError(
            '%s condition %r is not registered on %s.'
            % (api, conditions[0], model._meta.label)
        )
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return reduce(or_, parts)


def compile_permitted_users(content, perm, *, user_queryset=None, **skip_flags):
    """Lazy user queryset for one saved content object and one permission.

    The candidate rows are ``user_queryset`` when given (the optional
    manager adapter) and otherwise the user model stored at ready.
    Each configured backend that can contribute an exact reverse predicate
    is OR-ed. A registered user override is part of the predicate, not a
    separate superuser grant. The ``is_active`` check applies inside that
    branch only. A custom predicate is not wrapped. ``skip_<name>=True``
    sets that bound parameter. The values are forwarded only to the mixin
    method. Django's ``PermissionsMixin.has_perm`` early return is not
    copied here. An unsupported object-permission backend raises before SQL.
    """
    _require_saved_content(content)
    _reject_permission_shape(perm)
    catalogs = relationship_catalogs()
    inquiry = bind_checked_user(
        None, skip_flags=skip_flags,
        skip_names=known_skip_names(catalogs),
        require_user=False,
    )
    skipped = inquiry.values
    if user_queryset is None:
        model = standards.user_model
        if model is None:
            raise TrustsConfigurationError(
                'get_permitted_users has no user model. '
                'TrustsImplementationConfig.ready has not stored one.'
            )
        user_queryset = model._default_manager.get_queryset()
    elif not isinstance(user_queryset, QuerySet):
        raise TrustsConfigurationError(
            'user queryset must be a QuerySet, not %r.' % (user_queryset,)
        )
    backends = tuple(get_backends())
    _reject_unaccepted_permission_instance(perm, backends)
    principal_model = user_queryset.model
    assert_persisted_principal(principal_model)
    parts = []
    involved = [principal_model, content.__class__]
    if isinstance(perm, (str, Permission)):
        involved.append(Permission)
    for backend in backends:
        predicate = _backend_predicate(backend, content, perm, skipped=skipped)
        if predicate is None:
            continue
        if not isinstance(predicate, Q):
            raise TrustsConfigurationError(
                '%s permitted_users_predicate returned %s, not a Q or None.'
                % (type(backend).__name__, type(predicate).__name__)
            )
        _assert_registration_user_model(backend, content, principal_model)
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


def _content_model(obj):
    return obj.model if isinstance(obj, QuerySet) else obj.__class__


def _model_label(model):
    meta = model._meta if isinstance(model, type) else getattr(model, '_meta', None)
    if meta is None:
        return model
    return meta.label


def _perm_codes(permission_qs):
    return set(
        '%s.%s' % (app, code)
        for app, code in permission_qs.values_list(
            'content_type__app_label', 'codename',
        )
    )


def _plan_is_auth_permission(plan, sponsor_records=()):
    """True when ``plan`` terminates on ``auth.Permission``."""
    permission_model = plan.permission_model
    if (
        plan.records
        and permission_model is not None
        and permission_model._meta.concrete_model is Permission
    ):
        return True
    for delegation in plan.delegations:
        for ordinary in sponsor_records:
            if not _sponsor_record_matches(ordinary, delegation):
                continue
            if ordinary.permission_model._meta.concrete_model is Permission:
                return True
    return False


def _auth_permission_plan(registry, candidates, user):
    """Applicable plan only when the permission terminal is auth.Permission."""
    plan = registry.plan_for(candidates, user=user)
    if not _plan_is_auth_permission(
        plan, _ordinary_records(registry, candidates),
    ):
        return None
    return plan


def _auth_permission_plan_for_model(registry, model):
    """Zero-SQL applicable auth.Permission plan for this content model."""
    plan = registry.plan_for(model)
    if not _plan_is_auth_permission(plan, _ordinary_records(registry, model)):
        return None
    return plan


def _owns_selected_conditions(registry, model, conditions):
    """True when every selected name is registered with a queryable expr."""
    if not conditions:
        return True
    lookup = registry.filter_lookup
    if lookup is None:
        return False
    for name in conditions:
        record = lookup.record_for(model, name)
        if record is None or record.expr is None:
            return False
    return True


def _selected_condition_q(registry, model, permission, conditions, user, *, api):
    """AND this registry's selected names, or None when any name is missing."""
    lookup = registry.filter_lookup
    if lookup is None:
        return None
    extra_q = None
    for name in conditions:
        record = lookup.record_for(model, name)
        if record is None:
            return None
        if record.expr is None:
            raise TrustsConfigurationError(
                '%s condition %r on %s is unsupported.'
                % (api, name, model._meta.label)
            )
        part = lookup.compile_q(model, '%s:%s' % (permission, name), user)
        extra_q = part if extra_q is None else extra_q & part
    return extra_q


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


def _trusts_owned_reverse_hook(backend):
    """True when the reverse hook is the mixin method, not an override."""
    if not isinstance(backend, TrustModelBackendMixin):
        return False
    return (
        type(backend).permitted_users_predicate
        is TrustModelBackendMixin.permitted_users_predicate
    )


def _backend_predicate(backend, content, perm, *, skipped=()):
    if getattr(backend, 'trusts_object_permissions', None) is False:
        return None
    if _declares_reverse_hook(backend):
        if _trusts_owned_reverse_hook(backend):
            return backend.permitted_users_predicate(
                content, perm, skipped=skipped,
            )
        return backend.permitted_users_predicate(content, perm)
    if '%s.%s' % (
        type(backend).__module__, type(backend).__qualname__,
    ) in _BACKENDS_THAT_IGNORE_THE_OBJECT:
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


def _assert_registration_user_model(backend, content, candidate_model):
    if not isinstance(backend, TrustModelBackendMixin):
        return
    catalog = backend.get_catalog()
    if catalog is None:
        return
    plan = catalog.plan_for(content)
    expected = candidate_model._meta.concrete_model
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
    catalog = backend.get_catalog()
    if catalog is None:
        return []
    plan = catalog.plan_for(content)
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
