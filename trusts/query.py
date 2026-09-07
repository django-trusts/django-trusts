"""SQL grant filters shared by list helpers and team administration.

These Q objects match ``TrustModelBackend.get_all_permissions``:
trustee rows, Django ``Group.permissions`` on a trust-attached group, and
role-derived grants. They do not evaluate ``:own`` predicates (those stay
Python-side on ``has_perm``).
"""

from django.db.models import Q

from trusts import ROOT_PK, get_permission_model


def user_is_permission_principal(user):
    """Active authenticated users only. Matches Django ``has_perm`` deny for inactive."""
    if user is None:
        return False
    if getattr(user, 'is_anonymous', False):
        return False
    if not getattr(user, 'is_authenticated', False):
        return False
    if not getattr(user, 'is_active', True):
        return False
    return True


def permission_codename(model, perm):
    """Accept ``codename`` or ``app_label.codename``, strip ``:condition``."""
    if not perm:
        raise ValueError('perm is required')
    perm = str(perm)
    if '.' in perm:
        perm = perm.split('.', 1)[1]
    return perm.split(':', 1)[0]


def get_model_permission(model, perm):
    """Resolve a permission using ``TRUSTS_PERMISSION_MODEL``, not a hardcoded class."""
    permission_model = get_permission_model()
    codename = permission_codename(model, perm)
    return permission_model.objects.get_by_natural_key(
        codename,
        model._meta.app_label,
        model._meta.model_name,
    )


def grants_q(user, permission, prefix=''):
    """Q matching trustee / group.permissions / role grants on a Trust.

    ``prefix`` is ``''`` when filtering ``Trust`` rows, or ``'trust__'`` when
    filtering Content/Junction rows via their ``trust`` FK.
    """
    p = prefix or ''
    return (
        Q(**{'%strustees__entity' % p: user, '%strustees__permission' % p: permission}) |
        Q(**{'%sgroups__user' % p: user, '%sgroups__permissions' % p: permission}) |
        Q(**{'%sgroups__user' % p: user, '%sgroups__roles__permissions' % p: permission})
    )


def content_permitted(queryset, perm, user):
    """Filter a Content queryset to rows ``user`` may access via Trusts grants.

    Apply this before pagination. Inactive and anonymous principals get no rows.
    Superuser short-circuit is Django's ``has_perm`` behavior and is not applied
    here; list membership is grant-backed only.
    """
    if not user_is_permission_principal(user):
        return queryset.none()
    permission = get_model_permission(queryset.model, perm)
    return queryset.filter(grants_q(user, permission, prefix='trust__')).distinct()


def trusts_with_content_perm(manager, user, content, perm_name, exclude_root=True, **kwargs):
    """Trusts under which ``user`` holds ``perm_name`` for ``content``.

    Create-under-trust: the queryset for choosing a trust when creating
    content of that type. Settlor identity alone is not a grant. Root is
    excluded by default.
    """
    if 'group__user' in kwargs:
        raise TypeError('"%s" are invalid keyword arguments' % 'group__user')
    if not user_is_permission_principal(user):
        return manager.none()
    from trusts.models import Content

    if not Content.is_content_model(content):
        return manager.none()

    permission = get_model_permission(content, perm_name)
    qs = manager.filter(grants_q(user, permission), **kwargs)
    if exclude_root and ROOT_PK is not None:
        qs = qs.exclude(pk=ROOT_PK)
    return qs.distinct()


def user_can_view_group(user, group):
    """Members may view a team. Managers may also view."""
    if not user_is_permission_principal(user):
        return False
    if group.user_set.filter(pk=user.pk).exists():
        return True
    return user_can_manage_group(user, group)


def user_can_manage_group(user, group):
    """Adding members requires a trustee ``change_trust`` grant on a trust that includes the group.

    Ordinary group membership or a content-read grant is not enough.
    """
    from trusts.models import Trust

    if not user_is_permission_principal(user):
        return False
    permission = get_model_permission(Trust, 'change_trust')
    return Trust.objects.filter(
        groups=group,
        trustees__entity=user,
        trustees__permission=permission,
    ).exists()
