"""Frozen registry constructed from already-lowered state.

The factory passes records, the compiler, the sibling handle list, and
the plan builders. This module does not import ``trusts.core`` or
``trusts.compile``. Object methods take the runtime user, content, and
permission and call the injected builders.
"""

__all__ = []

from functools import reduce
from operator import or_

from django.db.models import Exists, OuterRef, Q

from trusts.errors import TrustsConfigurationError


class FrozenRegistry(object):
    """Query-time registry. Registration has already been lowered."""

    def __init__(
        self, *, records, delegations, compiler, handles, relation_plan,
        bind_record_qs, grant_reach, content_model, concrete_model,
        require_instance, candidate_model, rule_fragment, override_fragment,
    ):
        self.records = tuple(records)
        self.delegations = tuple(delegations)
        self.compiler = compiler
        self.handles = tuple(handles)
        self.relation_plan = relation_plan
        self.bind_record_qs = bind_record_qs
        self.grant_reach = grant_reach
        self.content_model = content_model
        self.concrete_model = concrete_model
        self.require_instance = require_instance
        self.candidate_model = candidate_model
        self.rule_fragment = rule_fragment
        self.override_fragment = override_fragment

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

    def plan_for(self, content, *, user=None, permission=None):
        """Same terminal selection as ``TrustsRegistry.plan_for``.

        Builders and lowered rows come from construction. ``content``,
        ``user``, and ``permission`` are the runtime parameters.
        """
        content_model = self.content_model(content)
        user_model = None
        if user is not None:
            user_model = self.concrete_model(
                self.require_instance(user, 'user'),
            )
        permission_model = None
        if permission is not None:
            permission_model = self.concrete_model(
                self.require_instance(permission, 'permission'),
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
            rules = self.rule_fragment(subject, role='user')
            closed = rules
            override = self.override_fragment(subject)
        return self.relation_plan(
            records=records,
            delegations=delegations,
            permission_model=plan_permission,
            content_identity=self.candidate_model(content),
            user_rules=rules,
            user_rules_closed=closed,
            user_override_q=override,
        )

    def compile_content_exists(self, plan, user, permission):
        """Content correlation for one plan, via the injected builders."""
        user = self.require_instance(user, 'user')
        permission = self.require_instance(permission, 'permission')
        if not plan.records:
            return None
        parts = []
        for record in plan.records:
            if record.along is not None:
                parts.append(self.grant_reach(
                    record, user, permission,
                    content_identity=plan.content_identity,
                ))
                continue
            inner = self.bind_record_qs(
                record,
                correlation=Q(**{
                    record.content_field: OuterRef(record.content_target),
                }),
                content_identity=plan.content_identity,
                user=user,
                permission=permission,
            )
            parts.append(Exists(inner))
        if len(parts) == 1:
            return parts[0]
        return reduce(or_, parts)
