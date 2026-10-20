"""Registry constructed from already-lowered values.

Records, delegations, the named-filter condition store, stored user
conditions, and the user override are passed in as data, all at once.
Builders and model helpers are imported directly here. This module
does not import ``trusts.compile``. Object methods take the runtime
user, content, and permission.
"""

__all__ = []

from dataclasses import dataclass
from functools import partial

from django.db.models import QuerySet

from trusts.plan.hops import (
    concrete_model, content_model, require_instance, resolved_hop,
)
from trusts.errors import TrustsConfigurationError
from trusts.plan.relations import (
    PlanQueryCompiler,
    RelationPlan,
    _candidate_model,
    answering_compiler,
    bind_checked_user,
)
from trusts.plan.standards import (
    builtin_user_conditions,
    compile_override_q,
    compile_user_rules,
    condition_names,
)
from django.db.models import Model
from trusts.plan.aggregates import all_match, instance_match
from trusts.plan.contents import _compile_granted
from trusts.plan.rewrites import bind_once
from trusts.plan.contents import _compile_permitted_content_queryset
from trusts.plan.aggregates import _compile_common_permissions
from trusts.plan.users import permitted_users_predicate_for_registry
from trusts.plan.users import _plan_user_model
from trusts.plan.conditions import ConditionRegistry
from trusts.plan.conditions import RegistryConditionLookup


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
    registry question families pre-bound with the walk's ``family_registries``;
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
        compiler=None, path='', family='relationship', user_model=None,
    ):
        self.records = tuple(records)
        self.delegations = tuple(delegations)
        self._project = compiler is None
        self._compiler = PlanQueryCompiler() if compiler is None else compiler
        self.path = path
        self.family = family
        self.user_model = user_model
        if conditions is None:
            # Stay lazy: importing this module must not load the
            # condition IR unless a store or lookup must be created.

            conditions = ConditionRegistry()
        self.conditions = conditions
        self.user_conditions = (
            None if user_conditions is None else tuple(user_conditions)
        )
        self.user_override = user_override
        if condition_lookup is _CONDITION_LOOKUP_UNSET:

            condition_lookup = RegistryConditionLookup(self.conditions)
        # An explicit None stays unbound (set_condition_lookup(None)
        # on the builder must survive the build); only omission derives.
        self.condition_lookup = condition_lookup
        self._rule_fragments = {}
        self._override_fragments = {}

    @property
    def compiler(self):
        """Compiler bound at construction."""
        return self._compiler

    def plan_for(self, content, *, user=None, permission=None):
        """Same terminal selection as ``TrustsRegistry.plan_for``.

        Lowered rows and rule data come from construction. ``content``,
        ``user``, and ``permission`` are the runtime parameters.
        """
        content_model = content_model(content)
        user_model = None
        if user is not None:
            user_model = concrete_model(
                require_instance(user, 'user'),
            )
        permission_model = None
        if permission is not None:
            permission_model = concrete_model(
                require_instance(permission, 'permission'),
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

    def _with_family_registries(self, family_registries):
        """This registry, then each other family registry, once."""
        routes = []
        seen = set()
        for other in (self,) + tuple(family_registries or ()):
            if other is None or id(other) in seen:
                continue
            seen.add(id(other))
            routes.append(other)
        return tuple(routes)

    def applies(self, plan):
        """Whether this registry's compiler will compile ``plan``."""
        compiler = answering_compiler(self)
        applies = getattr(compiler, 'applies', None)
        if callable(applies):
            return bool(applies(plan))
        return bool(plan.records)

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
    # plan.users. These methods call them on this registry. The
    # compiler is bound here. Omission stores ``PlanQueryCompiler``
    # and projects simple questions. ``family_registries`` are other
    # registries whose ordinary records may satisfy this registry's
    # delegations; this registry is always included first. ``None`` is
    # never returned: inapplicable is False / empty queryset / () as
    # each question requires.

    def has_permission(self, user, content, permission, *, family_registries=(),
                       extra_q=None, permission_model=None,
                       skipped=None, **skip_flags):
        """Q1: does ``user`` hold ``permission`` on ``content``?

        ``content`` is one instance (instance check) or a QuerySet
        (every row must hold). Delegations via family_registries are included.
        The compiler bound at construction compiles the grant.
        """


        user = require_instance(user, 'user')
        if isinstance(permission, Model):
            permission = require_instance(permission, 'permission')
        denied, values = self._resolve_skipped(user, skip_flags, skipped)
        family_registries = self._with_family_registries(family_registries)
        if isinstance(content, QuerySet):
            if denied:
                return False
            matched = all_match(
                (self,), content, user, permission,
                kind='complete', extra_q=extra_q,
                family_registries=family_registries,
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
            family_registries=family_registries,
            permission_model=permission_model, skipped=values,
        )
        return False if matched is None else bool(matched)

    def filter_authorized(self, queryset, user, permission, *, family_registries=(),
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
            (self,), queryset, user, permission,
            kind='complete',
            family_registries=self._with_family_registries(family_registries),
            skipped=values,
        )
        if granted_q is None:
            return queryset.none()
        return bind_once(queryset.filter(granted_q).distinct())

    def filter_by_permitted_content(self, queryset, user, permission, *,
                                    content, family_registries=(),
                                    skipped=None, **skip_flags):
        """Q2 variant: scope rows that are a proper prefix of ``content``."""

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
        family_registries = self._with_family_registries(family_registries)
        return _compile_permitted_content_queryset(
            queryset, user, permission, content=content, registries=(self,),
            family_registries=family_registries,
            skipped=values,
        )

    def permissions_for(self, user, content, *, kind='complete', family_registries=(),
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
            (self,), content, user, kind=kind,
            family_registries=self._with_family_registries(family_registries),
            skipped=values,
        )
        if qs is None:
            if not (plan.records or plan.delegations) or plan.permission_model is None:
                return ()
            return plan.permission_model._default_manager.none()
        return qs

    # Backwards-compatible alias name used in earlier discussion.
    common_permissions = permissions_for

    def permitted_users_predicate(self, content, perm, *, family_registries=(),
                                  skipped=(), condition_lookup=None,
                                  accepts_permission=None, owner_name=None):
        """Q3 predicate: ``Q`` over candidate users, or ``None``.

        ``condition_lookup`` defaults to this registry's lookup.
        ``accepts_permission`` is the singular-permission callable;
        omitted means ``auth.Permission``.
        """

        family_registries = self._with_family_registries(family_registries)
        return permitted_users_predicate_for_registry(
            self, content, perm, family_registries=family_registries,
            skipped=skipped, condition_lookup=condition_lookup,
            accepts_permission=accepts_permission,
            owner_name=owner_name,
        )

    def permitted_users(self, content, perm, *, family_registries=(), **skip_flags):
        """Q3: lazy user queryset permitted on ``content`` for ``perm``."""

        denied, values = self._resolve_skipped(
            None, skip_flags, None, require_user=False,
        )
        # require_user=False never denies; values carry skip_<name>.
        predicate = self.permitted_users_predicate(
            content, perm, family_registries=family_registries, skipped=values,
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
                    'registry was built without user_model.'
                )
            return user_model._default_manager.none()
        user_model = _plan_user_model(plan, content)
        return bind_once(
            user_model._default_manager.filter(predicate).distinct()
        )

    # -- walking every possible question ------------------------------
    # ``registry.walk_questions(visitor)``. The visitor supplies one
    # ``visit(question)`` method, called once per :class:`Question`
    # descriptor in document order (content groups in first-registration
    # order, questions in policy-document order within a group). The
    # return value of each ``visit`` call is collected and returned as a
    # tuple in the same order; a visitor may return ``None`` for a
    # question it omits (for example an empty prefix statement).
    # ``family_registries`` are other registries whose ordinary records
    # may satisfy this registry's delegations; they are pre-bound into
    # each descriptor's question callable, never passed to the visitor
    # separately.

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
                related, _target = resolved_hop(field, 'content', path)
                concrete = related._meta.concrete_model
                if index != last and concrete not in seen:
                    seen.add(concrete)
                    found.append(concrete)
                current = related
        return tuple(found)

    def _question_content_grant(self, content_model, user, permission, *,
                            family_registries=()):
        return self.filter_authorized(
            content_model._meta.concrete_model._default_manager.all(),
            user, permission, family_registries=family_registries,
        )

    def _question_filter_by_permitted_content(
        self, content_model, queryset, user, permission, *, family_registries=(),
    ):
        return self.filter_by_permitted_content(
            queryset, user, permission, content=content_model,
            family_registries=family_registries,
        )

    def _descriptors_for(self, content_model, records, delegations, family_registries):
        descriptors = [
            Question(
                'permitted', content_model, records, delegations,
                partial(
                    self._question_content_grant, content_model,
                    family_registries=family_registries,
                ),
            ),
            Question(
                'has_perm', content_model, records, delegations,
                partial(self.has_permission, family_registries=family_registries),
            ),
            Question(
                'get_all_permissions', content_model, records, delegations,
                partial(self.permissions_for, family_registries=family_registries),
            ),
        ]
        if any(getattr(record, 'via_group', False) for record in records):
            descriptors.append(Question(
                'get_group_permissions', content_model, records, delegations,
                partial(self.permissions_for, kind='group', family_registries=family_registries),
            ))
        descriptors.append(Question(
            'get_permitted_users', content_model, records, delegations,
            partial(self.permitted_users, family_registries=family_registries),
        ))
        if self._permitted_content_prefix_models(content_model):
            descriptors.append(Question(
                'filter_by_permitted_content', content_model, records,
                delegations,
                partial(
                    self._question_filter_by_permitted_content, content_model,
                    family_registries=family_registries,
                ),
            ))
        return tuple(descriptors)

    def walk_questions(self, visitor, *, family_registries=()):
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
        family_registries = tuple(family_registries or ())
        results = []
        for model, records, delegations in self._content_groups():
            for descriptor in self._descriptors_for(
                model, records, delegations, family_registries,
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
