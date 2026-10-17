"""Sponsor and delegate matching.

One home for whether an ordinary sponsor record can satisfy a
delegation. Query shapes stay with their callers. This module does not
import ``trusts.core`` or ``trusts.compile``.
"""

__all__ = []


def _compatible_sponsor_records(delegations, sponsor_records):
    """Ordinary records that can satisfy at least one delegation row."""
    compatible = []
    for ordinary in sponsor_records:
        for delegation in delegations:
            if ordinary.content_model is not delegation.content_model:
                continue
            if ordinary.user_model is not delegation.sponsor_model:
                continue
            expected = delegation.condition_permission_model
            if expected is not None and ordinary.permission_model is not expected:
                continue
            if (
                expected is not None
                and ordinary.permission_target
                != delegation.condition_permission_target
            ):
                continue
            compatible.append(ordinary)
            break
    return tuple(compatible)
