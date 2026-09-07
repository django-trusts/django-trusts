"""SQL grant filters shared by list APIs and trust-row checks.

These Q objects JOIN the same trustee / group.permissions / role tables
that ``TrustModelBackend.get_all_permissions`` reads. Callers must apply
them on a QuerySet (then paginate). They are not Python predicates.
"""

from django.db.models import Q


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


def trust_grant_q(user, permission, trust_fk=''):
    """Return a Q matching trustee, group.permissions, and role-derived grants.

    ``trust_fk`` is the lookup prefix to the Trust row:
    - ``''`` filters ``Trust`` rows themselves (create-under-trust).
    - ``'trust'`` filters Content rows via ``Content.trust``.
    """
    prefix = ('%s__' % trust_fk) if trust_fk else ''
    return (
        Q(**{
            '%strustees__entity' % prefix: user,
            '%strustees__permission' % prefix: permission,
        }) |
        Q(**{
            '%sgroups__user' % prefix: user,
            '%sgroups__permissions' % prefix: permission,
        }) |
        Q(**{
            '%sgroups__user' % prefix: user,
            '%sgroups__roles__permissions' % prefix: permission,
        })
    )
