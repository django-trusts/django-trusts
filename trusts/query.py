"""SQL grant filters shared by list APIs and trust-row checks.

These expressions JOIN the same trustee / TrustGroup / ceiling tables
that ``TrustModelBackend.get_all_permissions`` reads. They are compiled
from the frozen Trustee adapter set. Callers must apply them on a
QuerySet (then paginate). They are not Python predicates.

Group-derived access is fail-closed. A group permission matches only when
the user is a member, a ``TrustGroup`` row exists, the permission is in
``TrustGroup.permissions``, and the permission is in the group's global
ceiling (``Group.permissions`` or role-derived). Incomplete rows deny.
"""

from django.db.models import Exists, Q


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


def _never_exists():
    from trusts.models import TrustGroup

    return Exists(TrustGroup.objects.none())


def _group_permission_queries_allowed():
    from trusts import (
        supported_entity_contract,
        supported_group_contract,
        supported_permission_contract,
    )

    return (
        supported_entity_contract()
        and supported_group_contract()
        and supported_permission_contract()
    )


def enabled_trustee_adapter_names():
    """django-trusts adapter names enabled by the live auth-model contract."""
    from trusts import supported_entity_contract, supported_permission_contract
    from trusts.models import DIRECT_TRUSTEE, GROUP_TRUSTEE

    names = []
    if supported_entity_contract() and supported_permission_contract():
        names.append(DIRECT_TRUSTEE)
    if _group_permission_queries_allowed():
        names.append(GROUP_TRUSTEE)
    return tuple(names)


def _scope_from_row_for_outerref(trust_id_outerref):
    if trust_id_outerref == 'pk':
        return ''
    if isinstance(trust_id_outerref, str) and trust_id_outerref.endswith('_id'):
        return trust_id_outerref[:-3]
    return trust_id_outerref


def group_local_grant_exists(user, permission, trust_id_outerref):
    """Exists: same TrustGroup, member, local grant, and global ceiling.

    ``trust_id_outerref`` is the outer row's Trust PK column (``pk`` on
    Trust, ``trust_id`` on Content). Compiled from the Group Trustee
    adapter.
    """
    from trusts.models import GROUP_TRUSTEE, prepare_trustee_registry
    from trusts.trustee import Trustee

    if not _group_permission_queries_allowed():
        return _never_exists()

    prepare_trustee_registry()
    return Trustee.get(GROUP_TRUSTEE).exists_q(
        user, permission, _scope_from_row_for_outerref(trust_id_outerref),
    )


def permission_granted_via_group_exists(user, trusts):
    """Exists against an outer Permission queryset for ``user`` on ``trusts``.

    ``trusts`` is a Trust instance, queryset, or id list. Empty ``trust__in``
    matches nothing. Compiled from the Group Trustee adapter.
    """
    from trusts.models import GROUP_TRUSTEE, prepare_trustee_registry
    from trusts.trustee import Trustee

    if not _group_permission_queries_allowed():
        return _never_exists()

    prepare_trustee_registry()
    return Trustee.get(GROUP_TRUSTEE).operation_exists_q(user, trusts)


def trust_grant_q(user, permission, trust_fk=''):
    """Return a Q matching trustee grants or the group local/global intersection.

    ``trust_fk`` is the lookup prefix to the Trust row:
    - ``''`` filters ``Trust`` rows themselves (create-under-trust).
    - ``'trust'`` filters Content rows via ``Content.trust``.

    Direct-object checks and permitted querysets share this compiled
    predicate.
    """
    from trusts.models import prepare_trustee_registry
    from trusts.trustee import Trustee

    prepare_trustee_registry()
    names = enabled_trustee_adapter_names()
    if not names:
        return Q(pk__in=[])
    return Trustee.grant_q(
        user, permission, scope_from_row=trust_fk, names=names,
    )
