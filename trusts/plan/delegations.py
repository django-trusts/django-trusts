"""Sponsor and delegate matching.

One home for whether an ordinary sponsor record can satisfy a
delegation, and for the sponsor-rule eligibility and row condition
every delegation query shape ANDs on. Callers keep their own reach
and sponsor SQL. This module does not import ``trusts.compile``.
"""

__all__ = []

from django.core.exceptions import FieldDoesNotExist
from django.db.models import Q

from trusts.commons import _compile_predicate
from trusts.errors import TrustsConfigurationError
from trusts.plan.relations import bind_checked_user


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
    lookups = {}
    for name, expected in (('is_anonymous', False), ('is_authenticated', True)):
        try:
            field = model._meta.get_field(name)
        except FieldDoesNotExist:
            continue
        if (
            not getattr(field, 'concrete', False)
            or field.get_internal_type() != 'BooleanField'
        ):
            raise TrustsConfigurationError(
                '%s.%s must be a concrete BooleanField for delegated '
                'principal eligibility.' % (model._meta.label, name)
            )
        lookups['%s__%s' % (path, name)] = expected
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
    eligibility = _principal_eligibility_q(
        record.sponsor_model, record.sponsor_field,
        record.sponsor_rules, skipped,
    )
    if eligibility is None:
        return None
    combined = bound()
    condition = _compile_predicate(
        record.condition, record, permission=permission,
    )
    if condition is not None:
        combined &= condition
    combined &= eligibility
    combined &= sponsor_q
    return combined
