"""One built catalog. Not a builder and not a second store."""

from dataclasses import dataclass, replace
from functools import partial

from django.contrib.auth.models import Permission
from django.db import router
from django.db.models import Model, Q, QuerySet, Subquery

from trusts.apps import catalog_for_model
from trusts.errors import PermissionConditionError, TrustsConfigurationError
from trusts.plan.aggregates import (
    _compile_common_permissions,
    _delegated_user_exists,
    all_match,
    instance_match,
)
from trusts.plan.conditions import (
    compile_stored_condition_q,
    evaluate_registered_expression,
    parse_perm_code,
    permission_binding,
    permission_condition_code,
    permission_has_condition,
)
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
    resolved_hop,
)
from trusts.plan.relations import (
    PlanQueryCompiler,
    RelationPlan,
    _candidate_model,
    bind_checked_user,
    known_skip_names,
)
from trusts.plan.rewrites import bind_once
from trusts.plan.standards import builtin_user_conditions
from trusts.plan.users import (
    _named_filter_q,
    _permission_binding_for_plan,
    _plan_user_model,
    _reverse_checked,
    assert_persisted_principal,
)

_NO_PRESET = object()


@dataclass(frozen=True, slots=True)
class CatalogShape(object):
    """Frozen data ``Compiler.compile`` hands to one ``Catalog``.

    ``path`` and ``family`` are that catalog's identity.
    ``conditions`` is the ``(model, code, record)`` tuple taken once at
    build. ``user_rules`` is ``(primary, absent)``: stored rules use
    ``primary``; the built-in rule uses ``primary`` when the subject has
    a concrete boolean ``is_active`` and ``absent`` otherwise.
    ``override_q`` is the override compiled against the catalog user
    model, or ``None``. ``plans`` is the build-time ``(key, RelationPlan)``
    table. ``query_compiler is None`` means the default compiler.
    """

    records: tuple
    delegations: tuple
    conditions: tuple
    user_conditions: object
    user_override: object
    filter_lookup: object
    query_compiler: object
    path: str
    family: str
    user_model: object
    user_rules: tuple
    override_q: object
    plans: tuple


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


class Catalog(object):
    """Answers one backend class from the shape the sweep built.

    Callers outside the backend obtain this object from
    ``TrustModelBackendMixin.get_catalog()``. Rule and override fragments
    are on the shape. Nothing here compiles them again.
    """

    def __init__(self, shape, *, user_model):
        self.path = shape.path
        self.family = shape.family
        self.records = shape.records
        self.delegations = shape.delegations
        self._project = shape.query_compiler is None
        self.query_compiler = (
            PlanQueryCompiler()
            if shape.query_compiler is None else shape.query_compiler
        )
        self.user_model = user_model
        self.user_conditions = shape.user_conditions
        self.user_override = shape.user_override
        self.filter_lookup = shape.filter_lookup
        self.conditions = shape.conditions
        self.user_rules = shape.user_rules
        self.override_q = shape.override_q
        self.plans = shape.plans
        self._plans = dict(shape.plans)

    def plan_for(self, content, *, user=None, permission=None):
        """Look up ``(content, user, permission)``. A miss is not stored."""
        resolved = content_model(content)
        principal = None if user is None else concrete_model(
            require_instance(user, 'user'))
        terminal = None if permission is None else concrete_model(
            require_instance(permission, 'permission'))
        key = (resolved, principal, terminal)
        plan = self._plans[key] if key in self._plans else relation_plan(
            self.records, self.delegations, *key, self.user_model,
            self.user_conditions, self.user_rules, self.override_q)
        return replace(plan, content_identity=_candidate_model(content))

    def compile_registered_condition_q(self, model, perm, user):
        """Compile a registered ``:condition`` to ``Q`` from this catalog."""
        cond = permission_condition_code(perm)
        return compile_stored_condition_q(
            self.get_permission_condition_record(model, cond),
            model, perm, user, self.user_model,
        )

    def get_permission_condition_record(self, model, cond_code):
        return self.filter_lookup.record_for(model, cond_code)

    def iter_permission_conditions(self):
        return iter(self.conditions)

    def applies(self, plan):
        """Whether this catalog's compiler will compile ``plan``."""
        return bool(self.query_compiler.applies(plan))

    def has_permission(self, user, content, permission, *,
                       extra_q=None, permission_model=None,
                       skipped=None, **skip_flags):
        """Q1: does ``user`` hold ``permission`` on ``content``?

        ``content`` is one instance (instance check) or a QuerySet
        (every row must hold). A delegation uses this catalog's
        ordinary records. The compiler bound at construction compiles
        the grant.
        """
        user = require_instance(user, 'user')
        if isinstance(permission, Model):
            permission = require_instance(permission, 'permission')
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
        content = require_instance(content, 'content')
        if denied:
            return False
        if (self._project and extra_q is None
                and isinstance(permission, Model)):
            plan = self.plan_for(
                content, user=user,
                permission=permission if isinstance(permission, Model) else None,
            )
            if not plan.delegations:
                return plan.has_permission(user, content, permission, skipped=values)
        matched = instance_match(
            self, content, user, permission,
            kind='complete', extra_q=extra_q,
            permission_model=permission_model, skipped=values,
        )
        return False if matched is None else bool(matched)

    def filter_authorized(self, queryset, user, permission, *,
                          skipped=None, **skip_flags):
        """Q2: rows of ``queryset`` ``user`` may access for ``permission``."""
        if not isinstance(queryset, QuerySet):
            raise TrustsConfigurationError(
                'filter_authorized requires a QuerySet, not %r.' % (queryset,)
            )
        user = require_instance(user, 'user')
        permission = require_instance(permission, 'permission')
        denied, values = self._resolve_skipped(user, skip_flags, skipped)
        if denied:
            return queryset.none()
        if self._project:
            plan = self.plan_for(queryset, user=user, permission=permission)
            if not plan.delegations:
                return plan.filter_content(queryset, user, permission, skipped=values)
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
        if not isinstance(queryset, QuerySet):
            raise TrustsConfigurationError(
                'filter_by_permitted_content requires a QuerySet, not %r.'
                % (queryset,)
            )
        user = require_instance(user, 'user')
        permission = require_instance(permission, 'permission')
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
        user = require_instance(user, 'user')
        denied, values = self._resolve_skipped(user, skip_flags, skipped)
        plan = self.plan_for(content, user=user)
        if denied:
            if not (plan.records or plan.delegations) or plan.permission_model is None:
                return ()
            return plan.permission_model._default_manager.none()
        if (self._project and kind == 'complete'
                and not isinstance(content, QuerySet) and not plan.delegations):
            return plan.permissions(user, content, skipped=values)
        qs = _compile_common_permissions(
            self, content, user, kind=kind, skipped=values,
        )
        if qs is None:
            if not (plan.records or plan.delegations) or plan.permission_model is None:
                return ()
            return plan.permission_model._default_manager.none()
        return qs

    def permitted_users_predicate(self, content, perm, *,
                                  skipped=(), filter_lookup=None,
                                  accepts_permission=None):
        """Q3 predicate: ``Q`` over candidate users, or ``None``.

        ``filter_lookup`` defaults to this catalog's lookup.
        ``accepts_permission`` is the singular-permission callable;
        omitted means ``auth.Permission``.
        """
        plan = self.plan_for(content)
        if not plan.records and not plan.delegations:
            return None
        if filter_lookup is None:
            filter_lookup = self.filter_lookup
        binding, condition = _permission_binding_for_plan(
            accepts_permission, content, perm, plan,
        )
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
                filter_lookup, content, condition[1], condition[0], user_model,
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
            if plan.records or plan.delegations:
                user_model = _plan_user_model(plan, content)
            elif self.user_model is not None:
                user_model = self.user_model
            else:
                raise TrustsConfigurationError(
                    'permitted_users has no registered user model and this '
                    'catalog was built without user_model.'
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
        results = []
        for model, records, delegations in self._content_groups():
            for descriptor in self._descriptors_for(
                model, records, delegations,
            ):
                results.append(visit(descriptor))
        return tuple(results)

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
        if not self.applies(self.plan_for(obj, user=user_obj)):
            return PreparedInquiry(model, result=False)
        record, extra_q = self._condition_overlay(permext, obj, user_obj)
        applabel, modelname, action, _cond = parse_perm_code(permext)
        perm = '%s.%s_%s' % (applabel, action, modelname)
        if permission_has_condition(permext) and record is None:
            return PreparedInquiry(model, result=False)
        held = self.has_permission(
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
        if not permission_has_condition(permext):
            return None, None
        cond = parse_perm_code(permext)[3]
        model = _content_model(obj)
        lookup = self.filter_lookup
        record = lookup.record_for(model, cond)
        if record is None or not isinstance(obj, QuerySet):
            return record, None
        return record, lookup.compile_q(
            obj.model, permext, user_obj, self.user_model,
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

    def _content_groups(self):
        """``(content_model, records, delegations)`` in document order."""
        order = []
        by_model = {}
        for kind, rows in (('records', self.records),
                           ('delegations', self.delegations)):
            for record in rows:
                model = record.content_model
                slot = by_model.get(model)
                if slot is None:
                    by_model[model] = slot = {'records': [], 'delegations': []}
                    order.append(model)
                slot[kind].append(record)
        return tuple(
            (model, tuple(by_model[model]['records']),
             tuple(by_model[model]['delegations']))
            for model in order
        )

    def permitted_content_prefix_models(self, model):
        """Concrete models that are a proper prefix of ``model``'s path."""
        plan = self.plan_for(model)
        legs = tuple(plan.records) + tuple(plan.delegations or ())
        found = []
        seen = set()
        for record in legs:
            path = record.content_path
            if not path:
                continue
            current = record.root
            last = len(path) - 1
            for index, name in enumerate(path):
                field = current._meta.get_field(name)
                related, _target = resolved_hop(field, 'content', path)
                concrete = related._meta.concrete_model
                if index != last and concrete not in seen:
                    seen.add(concrete)
                    found.append(concrete)
                current = related
        return tuple(found)

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

    def _descriptors_for(self, content_model, records, delegations):
        descriptors = [
            Question(
                'permitted', content_model, records, delegations,
                partial(self._question_content_grant, content_model),
            ),
            Question(
                'has_perm', content_model, records, delegations,
                self.has_permission,
            ),
            Question(
                'get_all_permissions', content_model, records, delegations,
                self.permissions_for,
            ),
        ]
        if any(record.via_group for record in records):
            descriptors.append(Question(
                'get_group_permissions', content_model, records, delegations,
                partial(self.permissions_for, kind='group'),
            ))
        descriptors.append(Question(
            'get_permitted_users', content_model, records, delegations,
            self.permitted_users,
        ))
        if self.permitted_content_prefix_models(content_model):
            descriptors.append(Question(
                'filter_by_permitted_content', content_model, records,
                delegations,
                partial(
                    self._question_filter_by_permitted_content, content_model,
                ),
            ))
        return tuple(descriptors)


def relation_plan(records, delegations, content, user, permission,
                  catalog_user, user_conditions, user_rules, override_q):
    """One plan for ``(content, user, permission)``. An empty selection is a plan."""
    chosen = tuple(
        record for record in records
        if record.content_model is content
        and (user is None or record.user_model is user)
        and (permission is None or record.permission_model is permission))
    bridges = tuple(
        record for record in delegations
        if record.content_model is content
        and (user is None or record.delegate_model is user))
    plan_permission = permission
    if chosen:
        models = {record.permission_model for record in chosen}
        if len(models) != 1:
            raise TrustsConfigurationError(
                'Applicable registrations must share one permission '
                'model; got %s.'
                % ', '.join(sorted(model._meta.label for model in models)))
        plan_permission = models.pop()
    subject = user
    if subject is None:
        subjects = {record.user_model._meta.concrete_model for record in chosen}
        subjects.update(
            record.delegate_model._meta.concrete_model for record in bridges)
        if len(subjects) == 1:
            subject = subjects.pop()
    rules = closed = override = None
    if subject is not None:
        primary, absent = user_rules
        rules = primary if (
            user_conditions is not None or builtin_user_conditions(subject)
        ) else absent
        closed, override = rules, override_q
    return RelationPlan(
        records=chosen, delegations=bridges, permission_model=plan_permission,
        content_identity=content, user_rules=rules, user_rules_closed=closed,
        user_override_q=override, user_model=catalog_user)


def plan_table(records, delegations, catalog_user, user_conditions,
               user_rules, override_q):
    """One plan per key the stored rows can select, in first-seen order."""
    users, perms, order = {}, {}, []
    observed = [
        (record.content_model, record.user_model, record.permission_model)
        for record in records]
    observed.extend(
        (record.content_model, record.delegate_model, None)
        for record in delegations)
    for content, user, perm in observed:
        seen = users.get(content)
        if seen is None:
            order.append(content)
            users[content] = seen = []
            perms[content] = []
        if user not in seen:
            seen.append(user)
        if perm is not None and perm not in perms[content]:
            perms[content].append(perm)
    return tuple(
        ((content, user, perm), relation_plan(
            records, delegations, content, user, perm, catalog_user,
            user_conditions, user_rules, override_q))
        for content in order
        for user in (None, *users[content])
        for perm in (None, *perms[content]))


class PreparedInquiry(object):
    def __init__(self, model, result=_NO_PRESET, qs=None):
        self.model = model
        self.result = result
        self.qs = qs

    def execute(self):
        if self.result is not _NO_PRESET:
            return self.result
        return bool(self.qs.exists())


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


def assert_authorization_preflight(catalog, model, conditions, *, api):
    """Fail closed unless this catalog has a plan and owns the names."""
    if catalog is not None:
        has_plan, owns = catalog.authorization_preflight(model, conditions)
        if has_plan and owns:
            return
        if has_plan:
            raise TrustsConfigurationError(
                '%s condition %r is not registered on %s.'
                % (api, conditions[0], model._meta.label)
            )
    raise TrustsConfigurationError(
        '%s has no applicable auth.Permission plan for %s.'
        % (api, model._meta.label)
    )


def authorization_grant_q(catalog, candidates, user, model, permission,
                           conditions, binding, *, api, skipped=()):
    """This catalog's auth.Permission grant, or ``None`` when it grants nothing."""
    if catalog is None:
        return None
    predicate, owned = catalog.authorization_grant(
        candidates, user, model, permission, conditions, binding,
        api=api, skipped=skipped,
    )
    if conditions and not owned:
        raise TrustsConfigurationError(
            '%s condition %r is not registered on %s.'
            % (api, conditions[0], model._meta.label)
        )
    return predicate


def compile_permitted_users(content, perm, *, user_queryset=None, **skip_flags):
    """Lazy user queryset for one saved content object and one permission.

    The candidate rows are ``user_queryset`` when given and otherwise the
    user model on the catalog owned by the content model's app. That
    catalog's predicate includes a registered user override. ``skip_<name>``
    is a bound parameter on that predicate.
    """
    _require_saved_content(content)
    _reject_permission_shape(perm)
    catalog = catalog_for_model(type(content))
    subjects = () if catalog is None else (catalog,)
    inquiry = bind_checked_user(
        None, skip_flags=skip_flags,
        skip_names=known_skip_names(subjects),
        require_user=False,
    )
    if user_queryset is None:
        if catalog is None or catalog.user_model is None:
            raise TrustsConfigurationError(
                'get_permitted_users has no user model. '
                'The catalog is not built yet.'
            )
        user_queryset = catalog.user_model._default_manager.get_queryset()
    elif not isinstance(user_queryset, QuerySet):
        raise TrustsConfigurationError(
            'user queryset must be a QuerySet, not %r.' % (user_queryset,)
        )
    principal_model = user_queryset.model
    assert_persisted_principal(principal_model)
    involved = [principal_model, type(content)]
    if isinstance(perm, (str, Permission)):
        involved.append(Permission)
    combined = Q(pk__isnull=True)
    if catalog is not None:
        predicate = catalog.permitted_users_predicate(
            content, perm, skipped=inquiry.values,
        )
        if predicate is not None and not isinstance(predicate, Q):
            raise TrustsConfigurationError(
                'permitted_users_predicate returned %s, not a Q or None.'
                % type(predicate).__name__
            )
        if predicate is not None:
            combined = predicate
        involved.extend(_catalog_models(catalog, content, principal_model))
    alias = _database_alias(content, user_queryset)
    _assert_same_database(alias, involved)
    if user_queryset.db != alias:
        user_queryset = user_queryset.using(alias)
    user_model = principal_model if catalog is None else catalog.user_model
    return bind_once(
        user_queryset.filter(combined).distinct(), user_model=user_model,
    )


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
    """True when every selected name is registered with a queryable expr."""
    if not conditions:
        return True
    lookup = catalog.filter_lookup
    for name in conditions:
        record = lookup.record_for(model, name)
        if record is None or record.expr is None:
            return False
    return True


def _selected_condition_q(catalog, model, permission, conditions, user, *, api):
    """AND this catalog's selected names, or None when any name is missing."""
    lookup = catalog.filter_lookup
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
        part = lookup.compile_q(
            model, '%s:%s' % (permission, name), user, catalog.user_model,
        )
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


def _catalog_models(catalog, content, principal_model):
    """Models this catalog's plan joins, after the user model matches."""
    plan = catalog.plan_for(content)
    expected = principal_model._meta.concrete_model
    models = []
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
        models.extend((
            record.root, record.user_model, record.permission_model,
            record.content_model,
        ))
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
        models.extend((
            record.root, record.delegate_model, record.sponsor_model,
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
