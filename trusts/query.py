"""SQL grant filters shared by list APIs and trust-row checks.

These expressions JOIN the same trustee / TrustGroup / ceiling tables
that ``TrustModelBackend.get_all_permissions`` reads. Callers must apply
them on a QuerySet (then paginate). They are not Python predicates.

Group-derived access is fail-closed. A group permission matches only when
the user is a member, a ``TrustGroup`` row exists, the permission is in
``TrustGroup.permissions``, and the permission is in the group's global
ceiling (``Group.permissions`` or role-derived). Incomplete rows deny.
"""

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
