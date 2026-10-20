"""Front over one built registry. Not a builder and not a second store."""

from django.contrib.auth.models import Permission
from django.db.models import Model, QuerySet

from trusts.errors import PermissionConditionError, TrustsConfigurationError
from trusts.plan.conditions import (
    evaluate_registered_expression,
    parse_perm_code,
    permission_binding,
    permission_has_condition,
)
from trusts.plan.standards import condition_names
from trusts.plan.contents import _ordinary_records, granted
from trusts.plan.delegations import _sponsor_record_matches
from trusts.plan.relations import bind_checked_user

_NO_PRESET = object()


class Catalog(object):
    """Answers one backend class from the registry the sweep built.

    ``family_registries`` are the other built registries of the same
    family, fixed by the sweep. Callers outside the backend obtain this
    object from ``TrustModelBackendMixin.get_catalog()``.
    """

    def __init__(self, *, cls, path, family, registry, family_registries):
        self.cls = cls
        self.path = path
        self.family = family
        self._registry = registry
        self.family_registries = tuple(family_registries)

    def policy(self):
        """Built registry for policy SQL and registration questions."""
        return self._registry

    def known_skip_names(self):
        """User-condition and override names this catalog can skip."""
        registry = self._registry
        return condition_names(registry.user_conditions, registry.user_override)

    def filter_by_permitted_content(self, queryset, user, permission, *,
                                    content, skipped=None, **skip_flags):
        """Scope rows that are a proper prefix of ``content`` for this catalog."""
        return self._registry.filter_by_permitted_content(
            queryset, user, permission, content=content,
            family_registries=self.family_registries,
            skipped=skipped, **skip_flags,
        )

    def authorization_preflight(self, model, conditions):
        """Zero-SQL ``(participating, owns_conditions)`` for this catalog.

        A catalog with no applicable ``auth.Permission`` plan contributes
        nothing. Family peers supply ordinary sponsor records for a
        delegation; they are not extra backends.
        """
        family = (self._registry,) + tuple(self.family_registries)
        plan = _auth_permission_plan_for_model(self._registry, model, family)
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
        family = (self._registry,) + tuple(self.family_registries)
        registry = self._registry
        if _auth_permission_plan(registry, candidates, user, family) is None:
            return None, False
        if conditions:
            overlay = _selected_condition_q(
                registry, model, permission, conditions, user, api=api,
            )
            if overlay is None:
                return None, False
            part = granted(
                (registry,), candidates, user, binding, kind='complete',
                family_registries=family, permission_model=Permission,
                skipped=skipped,
            )
            if part is None:
                return None, True
            return part & overlay, True
        part = granted(
            (registry,), candidates, user, binding, kind='complete',
            family_registries=family, permission_model=Permission,
            skipped=skipped,
        )
        if part is None:
            return None, False
        return part, False

    def permitted_users_predicate(self, content, perm, *, skipped=(),
                                  accepts_permission=None, owner_name=None):
        return self._registry.permitted_users_predicate(
            content, perm,
            family_registries=self.family_registries,
            skipped=skipped,
            condition_lookup=self._registry.condition_lookup,
            accepts_permission=accepts_permission,
            owner_name=owner_name,
        )

    def permitted_users(self, content, perm, **skip_flags):
        return self._registry.permitted_users(
            content, perm,
            family_registries=self.family_registries,
            **skip_flags,
        )

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
            extra_q=extra_q, family_registries=self.family_registries,
            permission_model=Permission,
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
        lookup = self._registry.condition_lookup
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


def _auth_permission_plan(registry, candidates, user, peers):
    """Applicable plan only when the permission terminal is auth.Permission."""
    plan = registry.plan_for(candidates, user=user)
    if not _plan_is_auth_permission(plan, _ordinary_records(peers, candidates)):
        return None
    return plan


def _auth_permission_plan_for_model(registry, model, peers):
    """Zero-SQL applicable auth.Permission plan for this content model."""
    plan = registry.plan_for(model)
    if not _plan_is_auth_permission(plan, _ordinary_records(peers, model)):
        return None
    return plan


def _owns_selected_conditions(registry, model, conditions):
    """True when every selected name is registered with a queryable expr."""
    if not conditions:
        return True
    lookup = registry.condition_lookup
    if lookup is None:
        return False
    for name in conditions:
        record = lookup.record_for(model, name)
        if record is None or record.expr is None:
            return False
    return True


def _selected_condition_q(registry, model, permission, conditions, user, *, api):
    """AND this registry's selected names, or None when any name is missing."""
    lookup = registry.condition_lookup
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


def grant_q(catalog, candidates, user, permission, *, skipped=()):
    """This catalog's complete grant predicate, or None when it grants nothing."""
    registry = catalog._registry
    return granted(
        (registry,), candidates, user, permission,
        kind='complete',
        family_registries=(registry,) + tuple(catalog.family_registries),
        skipped=skipped,
    )
