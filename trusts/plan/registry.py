"""Frozen registry constructed from already-lowered values.

Records, delegations, the named-filter condition store, stored user
conditions, and the user override are passed in as data, all at once.
Builders and model helpers are imported directly here; this module
does not import ``trusts.core`` or ``trusts.compile``. Object methods
take the runtime user, content, and permission.
"""

__all__ = []

from django.db.models import QuerySet

from trusts.commons import _concrete_model, _content_model, _require_instance
from trusts.errors import TrustsConfigurationError
from trusts.plan.handles import BackendHandle
from trusts.plan.relations import (
    PlanQueryCompiler,
    RelationPlan,
    _candidate_model,
    bind_checked_user,
)
from trusts.plan.standards import (
    builtin_user_conditions,
    compile_override_q,
    compile_user_rules,
    condition_names,
)


_CONDITION_LOOKUP_UNSET = object()


class FrozenRegistry(object):
    """Query-time registry built whole from lowered values.

    ``records`` and ``delegations`` are the lowered rows.
    ``conditions`` is the named-filter store (shared, not copied);
    a new empty store is created when omitted. ``user_conditions``
    is the stored user-condition tuple, or ``None`` for the built-in
    per-model rule. ``user_override`` is the stored override or
    ``None``. ``condition_lookup`` is derived from ``conditions``
    when omitted; an explicit ``None`` stays unbound.
    """

    def __init__(
        self, *, records, delegations, conditions=None,
        user_conditions=None, user_override=None,
        condition_lookup=_CONDITION_LOOKUP_UNSET,
    ):
        self.records = tuple(records)
        self.delegations = tuple(delegations)
        if conditions is None:
            # Stay lazy: importing this module must not load the
            # condition IR unless a store or lookup must be created.
            from trusts.plan.conditions import ConditionRegistry

            conditions = ConditionRegistry()
        self.conditions = conditions
        self.user_conditions = (
            None if user_conditions is None else tuple(user_conditions)
        )
        self.user_override = user_override
        if condition_lookup is _CONDITION_LOOKUP_UNSET:
            from trusts.plan.conditions import RegistryConditionLookup

            condition_lookup = RegistryConditionLookup(self.conditions)
        # An explicit None stays unbound (set_condition_lookup(None)
        # on the builder must survive the build); only omission derives.
        self.condition_lookup = condition_lookup
        self._rule_fragments = {}
        self._override_fragments = {}

    def plan_for(self, content, *, user=None, permission=None):
        """Same terminal selection as ``TrustsRegistry.plan_for``.

        Lowered rows and rule data come from construction. ``content``,
        ``user``, and ``permission`` are the runtime parameters.
        """
        content_model = _content_model(content)
        user_model = None
        if user is not None:
            user_model = _concrete_model(
                _require_instance(user, 'user'),
            )
        permission_model = None
        if permission is not None:
            permission_model = _concrete_model(
                _require_instance(permission, 'permission'),
            )
        records = self._records_for(
            content_model, user_model, permission_model,
        )
        delegations = self._delegations_for(content_model, user_model)
        plan_permission = permission_model
        if records:
            models = {record.permission_model for record in records}
            if len(models) != 1:
                raise TrustsConfigurationError(
                    'Applicable registrations must share one permission '
                    'model; got %s.'
                    % ', '.join(sorted(model._meta.label for model in models))
                )
            plan_permission = models.pop()
        subject = self._compiled_subject(records, delegations, user_model)
        rules = closed = override = None
        if subject is not None:
            rules = self._rule_fragment(subject, role='user')
            closed = rules
            override = self._override_fragment(subject)
        return RelationPlan(
            records=records,
            delegations=delegations,
            permission_model=plan_permission,
            content_identity=_candidate_model(content),
            user_rules=rules,
            user_rules_closed=closed,
            user_override_q=override,
        )

    # -- compatibility surface used by handle-based callers -------------
    # ``TrustsRegistry`` (the builder) exposes these names; built
    # registries must too, because Zero and the snapshot read them off
    # ``handle.registry`` / a built registry interchangeably.

    def build_registry(self):
        """Return ``self``: a built registry is already query-time data."""
        return self

    @property
    def _user_override(self):
        return self.user_override

    def _stored_user_conditions(self):
        """``None`` when this registry still uses the built-in rule."""
        return self.user_conditions

    def _known_skip_names(self):
        return condition_names(self.user_conditions, self.user_override)

    def compile_registered_condition_q(self, model, perm, user):
        """Compile a registered ``:condition`` to ``Q`` from this registry."""
        return self.conditions.compile_registered_condition_q(model, perm, user)

    def get_permission_condition_record(self, model, cond_code):
        getter = getattr(self.conditions, 'get_permission_condition_record', None)
        return getter(model, cond_code) if callable(getter) else None

    def iter_permission_conditions(self):
        iterator = getattr(self.conditions, 'iter_permission_conditions', None)
        return iterator() if callable(iterator) else iter(())

    # -- question helpers ------------------------------------------------

    def _handle(self, compiler=None):
        return BackendHandle(
            path='', registry=self,
            compiler=compiler if compiler is not None else PlanQueryCompiler(),
        )

    @staticmethod
    def _as_registry(value):
        if value is None or isinstance(value, FrozenRegistry):
            return value
        build = getattr(value, 'build_registry', None)
        return build() if callable(build) else value

    def _sponsor_handles(self, sponsors, compiler=None):
        handles = []
        seen = set()
        for sponsor in sponsors or ():
            registry = self._as_registry(sponsor)
            if registry is None or id(registry) in seen:
                continue
            seen.add(id(registry))
            if isinstance(registry, FrozenRegistry):
                handles.append(registry._handle(compiler=compiler))
            else:
                # Duck-typed registry (fake in tests): keep it as the
                # handle's registry so its plan_for/records are used.
                handles.append(BackendHandle(
                    path='', registry=registry,
                    compiler=compiler if compiler is not None else PlanQueryCompiler(),
                ))
        return tuple(handles)

    def _all_handles(self, sponsors, compiler=None):
        return (self._handle(compiler=compiler),) + self._sponsor_handles(
            sponsors, compiler=compiler,
        )

    def _resolve_skipped(self, subject, skip_flags, skipped, *, require_user=True):
        if skip_flags:
            inquiry = bind_checked_user(
                subject, skip_flags=skip_flags, registry=self,
                require_user=require_user,
            )
            return inquiry.denied, inquiry.values
        if isinstance(skipped, dict):
            return False, skipped
        return False, {}

    # -- the four canonical questions -----------------------------------
    # Production semantics live in plan.contents / plan.aggregates /
    # plan.users; these methods only retarget those implementations
    # from a handle to this registry (synthetic handle carrying the
    # caller's compiler, PlanQueryCompiler by default). ``sponsors``
    # is a tuple of other built registries whose ordinary records may
    # satisfy this registry's delegations; this registry is always its
    # own first sponsor. ``None`` is never returned: inapplicable is
    # False / empty queryset / () as each question requires.

    def has_permission(self, user, content, permission, *, sponsors=(),
                       compiler=None, extra_q=None, permission_model=None,
                       skipped=None, **skip_flags):
        """Q1: does ``user`` hold ``permission`` on ``content``?

        ``content`` is one instance (instance check) or a QuerySet
        (every row must hold). Delegations via sponsors are included,
        unlike the old builder trio which ignored them. An explicit
        ``compiler`` (the backend's) is honoured through the production
        aggregates; with no compiler, the ordinary path is the plan's
        own projection so non-PK permission targets correlate exactly
        as before.
        """
        from django.db.models import Model

        from trusts.plan.aggregates import all_match, instance_match

        user = _require_instance(user, 'user')
        if isinstance(permission, Model):
            permission = _require_instance(permission, 'permission')
        denied, values = self._resolve_skipped(user, skip_flags, skipped)
        if isinstance(content, QuerySet):
            if denied:
                return False
            matched = all_match(
                (self._handle(compiler=compiler),), content, user, permission,
                kind='complete', extra_q=extra_q,
                sponsor_handles=self._all_handles(sponsors, compiler=compiler),
                permission_model=permission_model, skipped=values,
            )
            return False if matched is None else bool(matched)
        content = _require_instance(content, 'content')
        if denied:
            return False
        plan = self.plan_for(
            content, user=user,
            permission=permission if isinstance(permission, Model) else None,
        )
        if compiler is None and extra_q is None and not plan.delegations:
            return plan.has_permission(
                user, content, permission, skipped=values,
            )
        matched = instance_match(
            self._handle(compiler=compiler), content, user, permission,
            kind='complete', extra_q=extra_q,
            sponsor_handles=self._all_handles(sponsors, compiler=compiler),
            permission_model=permission_model, skipped=values,
        )
        return False if matched is None else bool(matched)

    def filter_authorized(self, queryset, user, permission, *, sponsors=(),
                          compiler=None, skipped=None, **skip_flags):
        """Q2: rows of ``queryset`` ``user`` may access for ``permission``."""
        from trusts.plan.contents import _compile_granted
        from trusts.plan.rewrites import bind_once

        if not isinstance(queryset, QuerySet):
            raise TrustsConfigurationError(
                'filter_authorized requires a QuerySet, not %r.' % (queryset,)
            )
        user = _require_instance(user, 'user')
        permission = _require_instance(permission, 'permission')
        denied, values = self._resolve_skipped(user, skip_flags, skipped)
        if denied:
            return queryset.none()
        plan = self.plan_for(queryset, user=user, permission=permission)
        if compiler is None and not plan.delegations:
            return plan.filter_content(
                queryset, user, permission, skipped=values,
            )
        granted_q = _compile_granted(
            (self._handle(compiler=compiler),), queryset, user, permission,
            kind='complete',
            sponsor_handles=self._all_handles(sponsors, compiler=compiler),
            skipped=values,
        )
        if granted_q is None:
            return queryset.none()
        return bind_once(queryset.filter(granted_q).distinct())

    def filter_by_permitted_content(self, queryset, user, permission, *,
                                    content, sponsors=(), compiler=None,
                                    skipped=None, **skip_flags):
        """Q2 variant: scope rows that are a proper prefix of ``content``."""
        from trusts.plan.contents import _compile_permitted_content_queryset

        if not isinstance(queryset, QuerySet):
            raise TrustsConfigurationError(
                'filter_by_permitted_content requires a QuerySet, not %r.'
                % (queryset,)
            )
        user = _require_instance(user, 'user')
        permission = _require_instance(permission, 'permission')
        denied, values = self._resolve_skipped(user, skip_flags, skipped)
        if denied:
            return queryset.none()
        own = self._handle(compiler=compiler)
        return _compile_permitted_content_queryset(
            queryset, user, permission, content=content, handles=(own,),
            sponsor_handles=(own,) + self._sponsor_handles(sponsors, compiler=compiler),
            skipped=values,
        )

    def permissions_for(self, user, content, *, kind='complete', sponsors=(),
                        compiler=None, skipped=None, **skip_flags):
        """Q4: permission rows ``user`` holds on ``content`` (QS or ()).

        ``kind='group'`` is the group variant used by
        ``get_group_permissions``; ``'complete'`` is ``get_all_permissions``.
        A single instance with no delegations and no explicit compiler
        uses the plan's own projection (exact non-PK target
        correlation); QuerySet candidates, group kind, delegations, and
        explicit compilers use the production common-permissions
        aggregate, which is the backend's existing semantics.
        """
        from trusts.plan.aggregates import _compile_common_permissions

        user = _require_instance(user, 'user')
        denied, values = self._resolve_skipped(user, skip_flags, skipped)
        plan = self.plan_for(content, user=user)
        if denied:
            if not (plan.records or plan.delegations) or plan.permission_model is None:
                return ()
            return plan.permission_model._default_manager.none()
        if (
            compiler is None and kind == 'complete'
            and not isinstance(content, QuerySet)
            and not plan.delegations
        ):
            return plan.permissions(user, content, skipped=values)
        qs = _compile_common_permissions(
            (self._handle(compiler=compiler),), content, user, kind=kind,
            sponsor_handles=self._all_handles(sponsors, compiler=compiler),
            skipped=values,
        )
        if qs is None:
            if not (plan.records or plan.delegations) or plan.permission_model is None:
                return ()
            return plan.permission_model._default_manager.none()
        return qs

    # Backwards-compatible alias name used in earlier discussion.
    common_permissions = permissions_for

    def permitted_users_predicate(self, content, perm, *, sponsors=(),
                                  skipped=(), backend=None):
        """Q3 predicate: ``Q`` over candidate users, or ``None``.

        ``backend`` is only the Django adapter that owns the
        ``:condition`` overlay / singular-permission acceptance when
        called from ``TrustModelBackendMixin``; standalone calls use
        the auth.Permission default.
        """
        from trusts.plan.users import permitted_users_predicate_for_registry

        sponsor_handles = self._all_handles(sponsors)
        return permitted_users_predicate_for_registry(
            self, content, perm, sponsor_handles=sponsor_handles,
            skipped=skipped, backend=backend,
        )

    def permitted_users(self, content, perm, *, sponsors=(), **skip_flags):
        """Q3: lazy user queryset permitted on ``content`` for ``perm``."""
        from django.contrib.auth import get_user_model
        from trusts.plan.rewrites import bind_once
        from trusts.plan.users import _plan_user_model

        denied, values = self._resolve_skipped(
            None, skip_flags, None, require_user=False,
        )
        # require_user=False never denies; values carry skip_<name>.
        predicate = self.permitted_users_predicate(
            content, perm, sponsors=sponsors, skipped=values,
        )
        plan = self.plan_for(content)
        if predicate is None:
            if plan.records or plan.delegations:
                user_model = _plan_user_model(plan, content)
            else:
                user_model = get_user_model()
            return user_model._default_manager.none()
        user_model = _plan_user_model(plan, content)
        return bind_once(
            user_model._default_manager.filter(predicate).distinct()
        )

    def _records_for(self, content_model, user_model, permission_model):
        chosen = []
        for record in self.records:
            if record.content_model is not content_model:
                continue
            if user_model is not None and record.user_model is not user_model:
                continue
            if (
                permission_model is not None
                and record.permission_model is not permission_model
            ):
                continue
            chosen.append(record)
        return tuple(chosen)

    def _delegations_for(self, content_model, delegate_model):
        chosen = []
        for record in self.delegations:
            if record.content_model is not content_model:
                continue
            if (
                delegate_model is not None
                and record.delegate_model is not delegate_model
            ):
                continue
            chosen.append(record)
        return tuple(chosen)

    def _compiled_subject(self, records, delegations, user_model):
        if user_model is not None:
            return user_model
        models = {
            record.user_model._meta.concrete_model for record in records
        }
        models.update(
            record.delegate_model._meta.concrete_model
            for record in delegations
        )
        if len(models) == 1:
            return models.pop()
        return None

    def _conditions_for_model(self, model):
        if self.user_conditions is not None:
            return self.user_conditions
        return builtin_user_conditions(model)

    def _rule_fragment(self, model, *, role, path=''):
        model = model._meta.concrete_model
        key = (model, role, path)
        try:
            return self._rule_fragments[key]
        except KeyError:
            compiled = compile_user_rules(
                model, path, self._conditions_for_model(model),
                role=role, values={},
            )
            self._rule_fragments[key] = compiled
            return compiled

    def _override_fragment(self, model):
        model = model._meta.concrete_model
        try:
            return self._override_fragments[model]
        except KeyError:
            compiled = compile_override_q(
                model, '', self.user_override, {},
            )
            self._override_fragments[model] = compiled
            return compiled
