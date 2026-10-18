"""Frozen registry constructed from already-lowered values.

Records, delegations, the named-filter condition store, stored user
conditions, and the user override are passed in as data, all at once.
Builders and model helpers are imported directly here; this module
does not import ``trusts.core`` or ``trusts.compile``. Object methods
take the runtime user, content, and permission.
"""

__all__ = []

from trusts.commons import _concrete_model, _content_model, _require_instance
from trusts.errors import TrustsConfigurationError
from trusts.plan.relations import RelationPlan, _candidate_model
from trusts.plan.standards import (
    builtin_user_conditions,
    compile_override_q,
    compile_user_rules,
)


class FrozenRegistry(object):
    """Query-time registry built whole from lowered values.

    ``records`` and ``delegations`` are the lowered rows.
    ``conditions`` is the named-filter store (shared, not copied);
    a new empty store is created when omitted. ``user_conditions``
    is the stored user-condition tuple, or ``None`` for the built-in
    per-model rule. ``user_override`` is the stored override or
    ``None``. ``condition_lookup`` is derived from ``conditions``
    when ``None``.
    """

    def __init__(
        self, *, records, delegations, conditions=None,
        user_conditions=None, user_override=None, condition_lookup=None,
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
        if condition_lookup is None:
            from trusts.plan.conditions import RegistryConditionLookup

            condition_lookup = RegistryConditionLookup(self.conditions)
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
