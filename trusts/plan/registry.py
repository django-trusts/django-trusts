"""Registry constructed from already-lowered values.

Records, delegations, the named-filter condition store, stored user
conditions, and the user override are passed in as data, all at once.
Builders and model helpers are imported directly here; this module
does not import ``trusts.core`` or ``trusts.compile``. Object methods
take the runtime user, content, and permission.
"""

__all__ = []

from dataclasses import dataclass
from functools import partial

from django.db.models import QuerySet

from trusts.commons import (
    _concrete_model, _content_model, _require_instance, _resolved_hop,
)
from trusts.errors import TrustsConfigurationError
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


@dataclass(frozen=True)
class Question(object):
    """One possible permission question for one content group.

    ``name`` is the document/API name (``permitted``, ``has_perm``,
    ``get_all_permissions``, ``get_group_permissions``,
    ``get_permitted_users``, or ``filter_by_permitted_content``).
    ``content_model`` is the concrete content model for the group.
    ``records`` / ``delegations`` are that group's lowered rows, split
    by kind, in registration order. ``question`` is one of the four
    registry question families pre-bound with the walk's ``sponsors``;
    its call signature depends on ``name``:

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


class Registry(object):
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
        compiler=None, path='', family='relationship',
    ):
        self.records = tuple(records)
        self.delegations = tuple(delegations)
        self.compiler = compiler
        self.path = path
        self.family = family
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

    # -- names the builder exposes; a built registry exposes them too --

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

    def _picked_compiler(self, compiler):
        return PlanQueryCompiler() if compiler is None else compiler

    @staticmethod
    def _as_registry(value):
        if value is None or isinstance(value, Registry):
            return value
        build = getattr(value, 'build_registry', None)
        return build() if callable(build) else value

    def _route(self, compiler=None):
        return (self, self._picked_compiler(compiler))

    def _sponsor_routes(self, sponsors, compiler=None):
        routes = []
        seen = set()
        chosen = self._picked_compiler(compiler)
        for sponsor in sponsors or ():
            registry = self._as_registry(sponsor)
            if registry is None or id(registry) in seen:
                continue
            seen.add(id(registry))
            routes.append((registry, chosen))
        return tuple(routes)

    def _all_routes(self, sponsors, compiler=None):
        return (self._route(compiler),) + self._sponsor_routes(
            sponsors, compiler,
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
                (self._route(compiler=compiler),), content, user, permission,
                kind='complete', extra_q=extra_q,
                sponsor_handles=self._all_routes(sponsors, compiler=compiler),
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
            self._route(compiler=compiler), content, user, permission,
            kind='complete', extra_q=extra_q,
            sponsor_handles=self._all_routes(sponsors, compiler=compiler),
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
            (self._route(compiler=compiler),), queryset, user, permission,
            kind='complete',
            sponsor_handles=self._all_routes(sponsors, compiler=compiler),
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
        own = self._route(compiler=compiler)
        return _compile_permitted_content_queryset(
            queryset, user, permission, content=content, handles=(own,),
            sponsor_handles=(own,) + self._sponsor_routes(sponsors, compiler=compiler),
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
            (self._route(compiler=compiler),), content, user, kind=kind,
            sponsor_handles=self._all_routes(sponsors, compiler=compiler),
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

        sponsor_handles = self._all_routes(sponsors)
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

    # -- walking every possible question ------------------------------
    # Thomas's phrasing: ``registry.walk_questions(visitor)``. The
    # visitor is duck-typed: it supplies one ``visit(question)``
    # method, called once per :class:`Question` descriptor in
    # document order (content groups in first-registration order,
    # questions in policy-document order within a group). The return
    # value of each ``visit`` call is collected and returned as a
    # tuple in the same order; a visitor may return ``None`` for a
    # question it omits (for example an empty prefix statement).
    # ``sponsors`` are other registries (or buildable builders /
    # handles) whose ordinary records may satisfy this registry's
    # delegations; they are pre-bound into each descriptor's question
    # callable, never passed to the visitor separately.

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

    def _permitted_content_prefix_models(self, model):
        """Concrete models that are a proper prefix of ``model``'s path.

        Order is registration order, then path order; a model is
        listed once. This is the registry-side copy of the logic the
        policy snapshot uses to decide whether the
        ``filter_by_permitted_content`` question exists at all.
        """
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
                related, _target = _resolved_hop(field, 'content', path)
                concrete = related._meta.concrete_model
                if index != last and concrete not in seen:
                    seen.add(concrete)
                    found.append(concrete)
                current = related
        return tuple(found)

    def _question_permitted(self, content_model, user, permission, *,
                            sponsors=()):
        return self.filter_authorized(
            content_model._meta.concrete_model._default_manager.all(),
            user, permission, sponsors=sponsors,
        )

    def _question_filter_by_permitted_content(
        self, content_model, queryset, user, permission, *, sponsors=(),
    ):
        return self.filter_by_permitted_content(
            queryset, user, permission, content=content_model,
            sponsors=sponsors,
        )

    def _descriptors_for(self, content_model, records, delegations, sponsors):
        descriptors = [
            Question(
                'permitted', content_model, records, delegations,
                partial(
                    self._question_permitted, content_model,
                    sponsors=sponsors,
                ),
            ),
            Question(
                'has_perm', content_model, records, delegations,
                partial(self.has_permission, sponsors=sponsors),
            ),
            Question(
                'get_all_permissions', content_model, records, delegations,
                partial(self.permissions_for, sponsors=sponsors),
            ),
        ]
        if any(getattr(record, 'via_group', False) for record in records):
            descriptors.append(Question(
                'get_group_permissions', content_model, records, delegations,
                partial(self.permissions_for, kind='group', sponsors=sponsors),
            ))
        descriptors.append(Question(
            'get_permitted_users', content_model, records, delegations,
            partial(self.permitted_users, sponsors=sponsors),
        ))
        if self._permitted_content_prefix_models(content_model):
            descriptors.append(Question(
                'filter_by_permitted_content', content_model, records,
                delegations,
                partial(
                    self._question_filter_by_permitted_content, content_model,
                    sponsors=sponsors,
                ),
            ))
        return tuple(descriptors)

    def walk_questions(self, visitor, *, sponsors=()):
        """Walk every possible question, per content group, in order.

        See the section comment above for the visitor protocol.
        Conditional questions are included only when they can arise:
        ``get_group_permissions`` only for a group with a ``group=``
        (``via_group``) record, and ``filter_by_permitted_content``
        only for a group whose content path has a proper prefix.
        """
        visit = getattr(visitor, 'visit', None)
        if not callable(visit):
            raise TypeError(
                'walk_questions visitor must supply a callable '
                'visit(question), not %r.' % (visitor,)
            )
        sponsors = tuple(sponsors or ())
        results = []
        for model, records, delegations in self._content_groups():
            for descriptor in self._descriptors_for(
                model, records, delegations, sponsors,
            ):
                results.append(visit(descriptor))
        return tuple(results)

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
