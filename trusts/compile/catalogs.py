"""One built catalog. Not a builder and not a second store."""

from dataclasses import dataclass, replace

from django.contrib.auth.models import Permission
from django.db import router
from django.db.models import Model, Q, QuerySet

from trusts.errors import PermissionConditionError, TrustsConfigurationError
from trusts.utils import parse_perm_code
from trusts.plan.aggregates import (
    _compile_common_permissions,
    _delegated_user_exists,
    all_match,
    instance_match,
)
from trusts.plan.conditions import (
    condition_model_key,
    permission_binding,
    validate_expression,
)
from trusts.plan.grammar import is_predicate
from trusts.plan.writers import compile_to_q, evaluate_expression
from trusts.plan.contents import (
    _as_q,
    _compile_granted,
    _compile_permitted_content_queryset,
    _ordinary_records,
    granted,
)
from trusts.plan.delegations import _sponsor_record_matches
from trusts.plan.hops import (
    concrete_model,
    content_model,
    require_instance,
)
from trusts.plan.relations import _candidate_model, bind_checked_user
from trusts.plan.rewrites import bind_once
from trusts.plan.users import (
    _named_filter_q,
    _permission_binding_for_plan,
    _plan_user_model,
    _reverse_checked,
)

_NO_PRESET = object()


@dataclass(frozen=True)
class Question(object):
    """One possible permission question for one content group.

    ``name`` is the document/API name (``permitted``, ``has_perm``,
    ``get_all_permissions``, ``get_group_permissions``,
    ``get_permitted_users``, or ``filter_by_permitted_content``).
    ``content_model`` is the concrete content model for the group.
    ``records`` / ``delegations`` are that group's lowered rows, split
    by kind, in registration order. ``question`` is one of the four
    catalog question families; its call signature depends on ``name``:

    - ``permitted``: ``question(user, permission) -> QuerySet``
    - ``has_perm``: ``question(user, content, permission) -> bool``
    - ``get_all_permissions`` / ``get_group_permissions``:
      ``question(user, content) -> QuerySet | ()``
    - ``get_permitted_users``: ``question(content, permission)``
      ``-> QuerySet``
    - ``filter_by_permitted_content``:
      ``question(queryset, user, permission) -> QuerySet`` where
      ``queryset`` is over a proper-prefix model of ``content_model``.
    """

    name: str
    content_model: type
    records: tuple
    delegations: tuple
    question: object


@dataclass(frozen=True, slots=True, eq=False)
class Catalog(object):
    """Answers from the rows ``Compiler.compile`` stored.

    ``named_filters``, ``plans``, ``content_prefixes``, and
    ``prepared_conditions`` are immutable mappings the factory stored.
    ``questions`` is that build's question tuple. ``plans`` maps keys to
    plans; ``None`` is the default. ``user_rules`` is ``(primary, absent)``.
    """

    records: tuple
    delegations: tuple
    named_filters: object
    user_conditions: object
    user_override: object
    path: str
    family: str
    user_model: object
    user_rules: tuple
    override_q: object
    plans: object
    questions: tuple = ()
    content_prefixes: object = None
    prepared_conditions: object = None

    def plan_for(self, content, *, user=None, permission=None):
        """Look up ``(content, user, permission)``. A miss is the default."""
        resolved = content_model(content)
        principal = None if user is None else concrete_model(
            require_instance(user, 'user'))
        terminal = None if permission is None else concrete_model(
            require_instance(permission, 'permission'))
        key = (resolved, principal, terminal)
        plan = self.plans.get(key, self.plans[None])
        return replace(plan, content_identity=_candidate_model(content))

    def iter_permission_conditions(self):
        """Yield ``(model, code, tree)`` from the frozen named-filter copy."""
        for (_label, code), (model, tree) in self.named_filters.items():
            yield model, code, tree

    def _stored_named_filter(self, model, code):
        return self.named_filters.get((condition_model_key(model), code))

    def has_permission(self, user, content, permission, *,
                       extra_q=None, permission_model=None,
                       skipped=None, **skip_flags):
        """Q1: does ``user`` hold ``permission`` on ``content``?

        ``content`` is one instance (instance check) or a QuerySet
        (every row must hold). A delegation uses this catalog's
        ordinary records. The compiler bound at construction compiles
        the grant.
        """
        if not isinstance(user, Model):
            return False
        if isinstance(permission, Model) and permission.pk is None:
            return False
        denied, values = self._resolve_skipped(user, skip_flags, skipped)
        if isinstance(content, QuerySet):
            if denied:
                return False
            matched = all_match(
                self, content, user, permission,
                kind='complete', extra_q=extra_q,
                permission_model=permission_model, skipped=values,
            )
            return False if matched is None else bool(matched)
        if not isinstance(content, Model) or content.pk is None:
            return False
        if denied:
            return False
        matched = instance_match(
            self, content, user, permission,
            kind='complete', extra_q=extra_q,
            permission_model=permission_model, skipped=values,
        )
        return False if matched is None else bool(matched)

    def filter_authorized(self, queryset, user, permission, *,
                          skipped=None, **skip_flags):
        """Q2: rows of ``queryset`` ``user`` may access for ``permission``."""
        if (
            not isinstance(queryset, QuerySet)
            or not isinstance(user, Model)
            or not isinstance(permission, Model)
            or permission.pk is None
        ):
            return (
                queryset.none() if isinstance(queryset, QuerySet)
                else type(queryset[0])._default_manager.none()
                if isinstance(queryset, (list, tuple)) and queryset
                and isinstance(queryset[0], Model)
                else queryset
            )
        denied, values = self._resolve_skipped(user, skip_flags, skipped)
        if denied:
            return queryset.none()
        granted_q = _compile_granted(
            self, queryset, user, permission,
            kind='complete', skipped=values,
        )
        if granted_q is None:
            return queryset.none()
        return bind_once(
            queryset.filter(granted_q).distinct(), user_model=self.user_model,
        )

    def filter_by_permitted_content(self, queryset, user, permission, *,
                                    content, skipped=None, **skip_flags):
        """Scope rows that are a proper prefix of ``content`` for this catalog."""
        if (
            not isinstance(queryset, QuerySet)
            or not isinstance(user, Model)
            or not isinstance(permission, Model)
            or permission.pk is None
        ):
            return (
                queryset.none() if isinstance(queryset, QuerySet)
                else type(queryset[0])._default_manager.none()
                if isinstance(queryset, (list, tuple)) and queryset
                and isinstance(queryset[0], Model)
                else queryset
            )
        denied, values = self._resolve_skipped(user, skip_flags, skipped)
        if denied:
            return queryset.none()
        return _compile_permitted_content_queryset(
            queryset, user, permission, content=content, catalog=self,
            skipped=values,
        )

    def permissions_for(self, user, content, *, kind='complete',
                        skipped=None, **skip_flags):
        """Q4: permission rows ``user`` holds on ``content`` (QS or ()).

        ``kind='group'`` is the group variant used by
        ``get_group_permissions``; ``'complete'`` is ``get_all_permissions``.
        The compiler bound at construction compiles the grant.
        """
        if not isinstance(user, Model):
            return ()
        if not isinstance(content, (Model, QuerySet)) or (
            isinstance(content, Model) and content.pk is None
        ):
            return ()
        denied, values = self._resolve_skipped(user, skip_flags, skipped)
        plan = self.plan_for(content, user=user)
        if denied:
            if not (plan.records or plan.delegations) or plan.permission_model is None:
                return ()
            return plan.permission_model._default_manager.none()
        qs = _compile_common_permissions(
            self, content, user, kind=kind, skipped=values,
        )
        if qs is None:
            if not (plan.records or plan.delegations) or plan.permission_model is None:
                return ()
            return plan.permission_model._default_manager.none()
        return qs

    def permitted_users_predicate(self, content, perm, *,
                                  skipped=(),
                                  accepts_permission=None):
        """Q3 predicate: ``Q`` over candidate users, or ``None``.

        ``accepts_permission`` is the singular-permission callable;
        omitted means ``auth.Permission``.
        """
        plan = self.plan_for(content)
        if not plan.records and not plan.delegations:
            return None
        bound = _permission_binding_for_plan(
            accepts_permission, content, perm, plan,
        )
        if bound is None:
            return None
        binding, condition = bound
        exists = plan.user_exists(content, binding) if plan.records else None
        if plan.delegations:
            permission_model = (
                binding._meta.concrete_model
                if isinstance(binding, Model) else Permission
            )
            sponsor_records = _ordinary_records(
                self, content, permission_model,
            )
            delegated = _delegated_user_exists(
                plan.delegations, sponsor_records, content, binding,
                content_identity=plan.content_identity,
                skipped=skipped,
            )
            if delegated is not None:
                exists = (
                    delegated if exists is None else (_as_q(exists) | delegated)
                )
        user_model = _plan_user_model(plan, content)
        permission_model = plan.permission_model
        if permission_model is None and not isinstance(binding, Model):
            permission_model = Permission
        predicate = _reverse_checked(
            plan, exists, user_model, binding, content, skipped,
            permission_model,
        )
        if predicate is None:
            return None
        if condition:
            overlay = _named_filter_q(
                self.named_filters, content, condition[1], condition[0],
                user_model,
            )
            if overlay is None:
                return None
            if overlay is not True:
                predicate &= overlay
        return predicate

    def permitted_users(self, content, perm, **skip_flags):
        """Q3: lazy user queryset permitted on ``content`` for ``perm``."""
        denied, values = self._resolve_skipped(
            None, skip_flags, None, require_user=False,
        )
        predicate = self.permitted_users_predicate(
            content, perm, skipped=values,
        )
        plan = self.plan_for(content)
        if predicate is None:
            user_model = (
                _plan_user_model(plan, content)
                if plan.records or plan.delegations else self.user_model
            )
            return user_model._default_manager.none()
        user_model = _plan_user_model(plan, content)
        return bind_once(
            user_model._default_manager.filter(predicate).distinct(),
            user_model=self.user_model,
        )

    def walk_questions(self, visitor):
        """Walk every possible question, per content group, in order.

        The visitor supplies one ``visit(question)`` method, called once
        per :class:`Question` in document order. The return value of each
        call is collected. Conditional questions are included only when
        they can arise: ``get_group_permissions`` only for a group with a
        ``via_group`` record, and ``filter_by_permitted_content`` only for
        a group whose content path has a proper prefix.
        """
        visit = visitor.visit
        return tuple(visit(question) for question in self.questions)

    def authorization_preflight(self, model, conditions):
        """Zero-SQL ``(participating, owns_conditions)`` for this catalog.

        A catalog with no applicable ``auth.Permission`` plan contributes
        nothing.
        """
        plan = _auth_permission_plan_for_model(self, model)
        if plan is None:
            return False, False
        return True, _owns_selected_conditions(self, model, conditions)

    def authorization_grant(self, candidates, user, model, permission,
                            conditions, binding, *, api, skipped=()):
        """This catalog's grant predicate and whether it owned the names.

        ``(None, False)`` when this catalog does not participate. The
        predicate is a ``Q`` when this catalog grants. ``owned`` is true
        when names were selected and this catalog registered every one.
        """
        if _auth_permission_plan(self, candidates, user) is None:
            return None, False
        if conditions:
            overlay = _selected_condition_q(
                self, model, permission, conditions, user, api=api,
            )
            if overlay is None:
                return None, False
            part = granted(
                self, candidates, user, binding, kind='complete',
                permission_model=Permission, skipped=skipped,
            )
            if part is None:
                return None, True
            return part & overlay, True
        part = granted(
            self, candidates, user, binding, kind='complete',
            permission_model=Permission, skipped=skipped,
        )
        if part is None:
            return None, False
        return part, False

    def complete_grant_q(self, candidates, user, permission, *, skipped=()):
        """This catalog's complete grant predicate, or None when it grants nothing."""
        return granted(
            self, candidates, user, permission,
            kind='complete', skipped=skipped,
        )

    def has_perm(self, user_obj, permext, obj, **skip_flags):
        if not isinstance(user_obj, Model) or not isinstance(obj, (Model, QuerySet)):
            return False
        if isinstance(obj, Model) and obj.pk is None:
            return False
        inquiry = bind_checked_user(
            user_obj, skip_flags=skip_flags, catalog=self,
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
        model = _content_model(obj)
        try: applabel, modelname, action, cond = parse_perm_code(permext)
        except ValueError: return PreparedInquiry(model, result=False)
        plan = self.plan_for(obj, user=user_obj)
        if not plan.applicable:
            return PreparedInquiry(model, result=False)
        stored, extra_q = self._condition_overlay(permext, obj, user_obj)
        perm = '%s.%s_%s' % (applabel, action, modelname)
        if cond and stored is None:
            return PreparedInquiry(model, result=False)
        held = self.has_permission(
            user_obj, obj, permission_binding(perm, model),
            extra_q=extra_q, permission_model=Permission,
            skipped=dict(skipped) if isinstance(skipped, dict) else {},
        )
        if not held:
            return PreparedInquiry(model, result=False)
        if stored is None or extra_q is not None:
            return PreparedInquiry(model, result=True)
        return self.permission_condition_met(stored, user_obj, perm, obj)

    def permission_condition_met(self, stored, user_obj, perm, obj):
        model = _content_model(obj)
        _registered, tree = stored
        if isinstance(obj, QuerySet):
            objs, model = obj.all(), obj.model
        elif hasattr(obj, '__iter__') and not isinstance(obj, (str, bytes)):
            objs, model = obj, None
        else:
            objs = [obj]
        met = all(
            evaluate_registered_expression(
                tree, user_obj, perm, item,
                model=model or item.__class__,
                user_model=self.user_model,
            )
            for item in objs
        )
        return PreparedInquiry(model, result=bool(met))

    def _permission_codes(self, user_obj, obj, skip_flags, *, kind):
        inquiry = bind_checked_user(
            user_obj, skip_flags=skip_flags, catalog=self,
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
        cond = parse_perm_code(permext)[3]
        if not cond:
            return None, None
        model = _content_model(obj)
        stored = _condition_entry(self, model, cond)
        if stored is None or not isinstance(obj, QuerySet):
            return stored, None
        return stored, _apply_prepared(
            stored, obj.model, user_obj, permext, self.user_model,
        )

    def _resolve_skipped(self, subject, skip_flags, skipped, *, require_user=True):
        if skip_flags:
            inquiry = bind_checked_user(
                subject, skip_flags=skip_flags, catalog=self,
                require_user=require_user,
            )
            return inquiry.denied, inquiry.values
        if isinstance(skipped, dict):
            return False, skipped
        return False, {}

    def permitted_content_prefix_models(self, model):
        """Concrete models that are a proper prefix of ``model``'s path."""
        prefixes = self.content_prefixes
        if not prefixes:
            return ()
        return prefixes.get(content_model(model), ())

    def _question_content_grant(self, content_model, user, permission):
        return self.filter_authorized(
            content_model._meta.concrete_model._default_manager.all(),
            user, permission,
        )

    def _question_filter_by_permitted_content(
        self, content_model, queryset, user, permission,
    ):
        return self.filter_by_permitted_content(
            queryset, user, permission, content=content_model,
        )


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


def _auth_permission_plan(catalog, candidates, user):
    """Applicable plan only when the permission terminal is auth.Permission."""
    plan = catalog.plan_for(candidates, user=user)
    if not _plan_is_auth_permission(
        plan, _ordinary_records(catalog, candidates),
    ):
        return None
    return plan


def _auth_permission_plan_for_model(catalog, model):
    """Zero-SQL applicable auth.Permission plan for this content model."""
    plan = catalog.plan_for(model)
    if not _plan_is_auth_permission(plan, _ordinary_records(catalog, model)):
        return None
    return plan


def _owns_selected_conditions(catalog, model, conditions):
    """True when every selected name is registered with a queryable tree."""
    if not conditions:
        return True
    for name in conditions:
        stored = catalog._stored_named_filter(model, name)
        if stored is None:
            return False
    return True


def _condition_entry(catalog, model, code):
    """The checked tree for this model and code, or None when it is absent."""
    return (catalog.prepared_conditions or {}).get(
        (condition_model_key(model), code),
    )


def _apply_prepared(entry, model, user, perm, user_model):
    """Bind the asking user and this call's grant. ``entry`` is ``(model, tree)``."""
    return compile_to_q(
        entry[1], model, user,
        perm.split(':', 1)[0] if isinstance(perm, str) else perm,
        user_model,
    )


def _selected_condition_q(catalog, model, permission, conditions, user, *, api):
    """AND this catalog's selected names, or None when any name is missing."""
    extra_q = None
    for name in conditions:
        stored = _condition_entry(catalog, model, name)
        if stored is None:
            return None
        part = _apply_prepared(
            stored, model, user, '%s:%s' % (permission, name),
            catalog.user_model,
        )
        extra_q = part if extra_q is None else extra_q & part
    return extra_q


def evaluate_registered_expression(expr, user, perm, obj, model=None, user_model=None):
    """Evaluate a registered ``Tree`` against a real principal/object."""
    if not is_predicate(expr):
        raise PermissionConditionError(
            'Permission condition did not produce a comparison, '
            '.contains(), boolean field, or combination with & and |.'
        )
    klass = model
    if klass is None:
        klass = (
            obj.model if hasattr(obj, 'model') and not isinstance(obj, Model)
            else obj.__class__
        )
    validate_expression(expr, klass, user_model)
    return evaluate_expression(
        expr, user, perm, obj, model=klass, user_model=user_model,
    )


def catalog_models(catalog, content, principal_model):
    """Models this catalog's plan joins, after the user model matches."""
    plan = catalog.plan_for(content)
    expected = principal_model._meta.concrete_model
    models = []
    for record in plan.records:
        registered = record.user_model._meta.concrete_model
        if registered is not expected:
            return None
        models.extend((
            record.root, record.user_model, record.permission_model,
            record.content_model,
        ))
    for record in plan.delegations:
        registered = record.delegate_model._meta.concrete_model
        if registered is not expected:
            return None
        models.extend((
            record.root, record.delegate_model, record.sponsor_model,
            record.content_model,
        ))
        if record.condition_permission_model is not None:
            models.append(record.condition_permission_model)
    return models


def database_alias(content, user_queryset):
    state_db = getattr(getattr(content, '_state', None), 'db', None) or None
    if state_db:
        return state_db
    routed = router.db_for_read(user_queryset.model)
    if routed:
        return routed
    return user_queryset.db or 'default'


def assert_same_database(alias, models):
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
