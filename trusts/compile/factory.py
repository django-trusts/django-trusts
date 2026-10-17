"""Marshal a registration front end into a frozen registry.

``TrustsRegistry`` in ``trusts.core`` still collects ``register`` and
``set_*`` calls. This module does not import ``trusts.core``. The caller
passes the plan builders in, and the frozen registry never looks them up.
"""

__all__ = []

from trusts.plan.registry import FrozenRegistry


def assemble_frozen(
    registry, *, compiler, handles, relation_plan, bind_record_qs,
    grant_reach, content_model, concrete_model, require_instance,
    candidate_model,
):
    """Build the query-time registry from already-lowered rows."""
    return FrozenRegistry(
        records=registry.records,
        delegations=registry.delegations,
        compiler=compiler,
        handles=tuple(handles),
        relation_plan=relation_plan,
        bind_record_qs=bind_record_qs,
        grant_reach=grant_reach,
        content_model=content_model,
        concrete_model=concrete_model,
        require_instance=require_instance,
        candidate_model=candidate_model,
        rule_fragment=registry._rule_fragment,
        override_fragment=registry._override_fragment,
    )
