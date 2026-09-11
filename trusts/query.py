"""SQL grant filters shared by list APIs and trust-row checks.

These expressions JOIN the same trustee / TrustGroup / ceiling tables
that Trusts group/trustee proofs read. Callers must apply
them on a QuerySet (then paginate). They are not Python predicates.

Group-derived access is fail-closed. A group permission matches only when
the user is a member, a ``TrustGroup`` row exists, the permission is in
``TrustGroup.permissions``, and the permission is in the group's global
ceiling (``Group.permissions`` or role-derived). Incomplete rows deny.
"""

from functools import reduce
from operator import or_

from django.core.exceptions import FieldDoesNotExist
from django.db.models import Exists, OuterRef, Q


def is_active_principal(user):
    """Match ``User.has_perm``: anonymous and inactive principals are denied.

    Superuser short-circuit on ``has_perm`` is a Django ``ModelBackend``
    behavior and is not duplicated in SQL list filters.
    """
    if user is None:
        return False
    if getattr(user, 'is_anonymous', False):
        return False
    if not getattr(user, 'is_authenticated', True):
        return False
    if not getattr(user, 'is_active', False):
        return False
    return True


def _trust_lookup(trusts):
    if trusts is None:
        return {}
    if hasattr(trusts, 'pk') and not hasattr(trusts, 'model'):
        return {'trust': trusts}
    return {'trust__in': trusts}


def group_local_grant_exists(user, permission, trust_id_outerref):
    """Exists: same TrustGroup, member, local grant, and global ceiling.

    ``trust_id_outerref`` is the outer row's Trust PK column (``pk`` on
    Trust, ``trust_id`` on Content).
    """
    from trusts.models import TrustGroup

    return Exists(
        TrustGroup.objects.filter(
            trust_id=OuterRef(trust_id_outerref),
            group__user=user,
            permissions=permission,
        ).filter(
            Q(group__permissions=permission) |
            Q(group__roles__permissions=permission)
        )
    )


def _hop_target_model(model, name):
    """Next model on ``name`` via Django ``_meta`` / ``get_path_info()``."""
    field = model._meta.get_field(name)
    infos = field.get_path_info()
    if not infos:
        raise FieldDoesNotExist(name)
    to_opts = infos[-1].to_opts
    return to_opts.concrete_model


def _record_group_grant_exists(record, user, permission):
    """TrustGroup EXISTS for one registered content path.

    Candidates that expose a ``trust`` field keep the historical
    ``trust_id`` correlation. A suffix past that Trust (Junction-backed
    Group) correlates ``TrustGroup.trust`` through the remaining
    registered hops, taken from the stored path and Django ``_meta``.
    The EXISTS stays one nest deep so permission ``OuterRef`` depth
    matches Category/Ticket. No static content map.
    """
    from trusts.models import TrustGroup

    try:
        record.content_model._meta.get_field('trust')
    except FieldDoesNotExist:
        pass
    else:
        return group_local_grant_exists(user, permission, 'trust_id')

    path = record.content_path
    if len(path) < 2:
        return Exists(record.root._default_manager.none())
    # path[0] is TUP→Trust; the rest is Trust→…→content.
    suffix = path[1:]
    model = _hop_target_model(record.root, path[0])
    for name in suffix[:-1]:
        model = _hop_target_model(model, name)
    last = model._meta.get_field(suffix[-1])
    hop = getattr(last, 'attname', None) or suffix[-1]
    lookup = 'trust__%s__%s' % ('__'.join(suffix[:-1]), hop)
    return Exists(
        TrustGroup.objects.filter(
            **{lookup: OuterRef(record.content_target)},
            group__user=user,
            permissions=permission,
        ).filter(
            Q(group__permissions=permission) |
            Q(group__roles__permissions=permission)
        )
    )


def historical_group_grant_exists(plan, user, permission):
    """OR TrustGroup EXISTS predicates for every record on ``plan``.

    Built in the historical reader, not in ``trusts.core``. Empty
    ``plan.records`` is ``None``.
    """
    if not plan.records:
        return None
    parts = [
        _record_group_grant_exists(record, user, permission)
        for record in plan.records
    ]
    if len(parts) == 1:
        return parts[0]
    return reduce(or_, parts)


def permission_granted_via_group_exists(user, trusts):
    """Exists against an outer Permission queryset for ``user`` on ``trusts``.

    ``trusts`` is a Trust instance, queryset, or id list. Empty ``trust__in``
    matches nothing.
    """
    from trusts.models import TrustGroup

    return Exists(
        TrustGroup.objects.filter(
            group__user=user,
            permissions=OuterRef('pk'),
            **_trust_lookup(trusts)
        ).filter(
            Q(group__permissions=OuterRef('pk')) |
            Q(group__roles__permissions=OuterRef('pk'))
        )
    )


def trust_grant_q(user, permission, trust_fk=''):
    """Return a Q matching trustee grants or the group local/global intersection.

    ``trust_fk`` is the lookup prefix to the Trust row:
    - ``''`` filters ``Trust`` rows themselves (create-under-trust).
    - ``'trust'`` filters Content rows via ``Content.trust``.
    """
    prefix = ('%s__' % trust_fk) if trust_fk else ''
    trust_id_ref = 'pk' if not trust_fk else '%s_id' % trust_fk
    return (
        Q(**{
            '%strustees__entity' % prefix: user,
            '%strustees__permission' % prefix: permission,
        }) |
        group_local_grant_exists(user, permission, trust_id_ref)
    )
