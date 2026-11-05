"""Sponsor and delegate matching.

One home for whether an ordinary sponsor record can satisfy a
delegation, and for the sponsor-rule eligibility and row condition
every delegation query shape ANDs on. Callers keep their own reach
and sponsor SQL.
"""

__all__ = []

from django.db.models import Q

from trusts.plan.predicates import compile_predicate
from trusts.plan.relations import bind_checked_user
from trusts.plan.standards import principal_identity_lookups
from trusts.plan.via import selects_reached_users


def _sponsor_record_matches(ordinary, delegation):
    """Content, sponsor, and condition-permission model and target."""
    if ordinary.content_model is not delegation.content_model:
        return False
    if ordinary.user_model is not delegation.sponsor_model:
        return False
    expected = delegation.condition_permission_model
    if expected is not None and ordinary.permission_model is not expected:
        return False
    if (
        expected is not None
        and ordinary.permission_target
        != delegation.condition_permission_target
    ):
        return False
    return True


def _compatible_sponsor_records(delegations, sponsor_records):
    """Ordinary records that can satisfy at least one delegation row."""
    compatible = []
    for ordinary in sponsor_records:
        for delegation in delegations:
            if not _sponsor_record_matches(ordinary, delegation):
                continue
            compatible.append(ordinary)
            break
    return tuple(compatible)


def _principal_eligibility_q(model, path, rules, values):
    """Sponsor rules compiled at registration, plus identity columns.

    ``rules`` is that fragment. A missing fragment contributes nothing.
    Anonymous and authenticated attributes use their runtime defaults
    when they are not concrete fields.
    """
    if rules is None:
        return None
    lookups = principal_identity_lookups(model, path, strict=True)
    identity = Q(**lookups) if lookups else Q()
    return bind_checked_user(
        model, identity, rules=rules, values=values,
    ).predicate


def _matched_delegation_q(record, sponsor_q, permission, skipped, bound):
    """AND sponsor eligibility and the row condition onto the caller's shape.

    ``sponsor_q`` is the caller's sponsor-authority query, or None when
    no ordinary record matches. ``bound`` is called only after those
    sponsor rules apply, and returns the delegate binding ANDed with
    the caller's reach predicate. Sponsor authority is tested first,
    then sponsor rules, then reach, then the row condition.
    """
    if sponsor_q is None:
        return None
    if selects_reached_users(record):
        eligibility = Q()
    else:
        eligibility = _principal_eligibility_q(
            record.sponsor_model, record.sponsor_field,
            record.sponsor_rules, skipped,
        )
    if eligibility is None:
        return None
    combined = bound()
    condition = compile_predicate(
        record.condition, record, permission=permission,
    )
    if condition is not None:
        combined &= condition
    combined &= eligibility
    combined &= sponsor_q
    return combined
