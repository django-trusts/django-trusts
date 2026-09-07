"""Administrative authority for trust-scoped mutations.

Ordinary ``read`` and mere group membership are not enough to mutate
collaborators, group associations, or team membership. Callers must use
these helpers (or equivalent ``change`` checks) before writing.

``Group.permissions`` is a global Django M2M. Helpers here never write it.
Associating a group with a trust is ``Trust.groups.add`` only. Genuine
per-trust group permission *levels* are not expressible with the current
schema; that redesign is flagged for Thomas and is not implemented here.

``Group.user_set`` is also global. Adding a member to a group that two
trusts share grants that group's rights in both. Membership changes
therefore require administrative ``change`` on every trust that uses the
group.
"""

from django.core.exceptions import PermissionDenied

from trusts import get_entity_model, get_group_model
from trusts.query import is_active_principal, trust_grant_q
from trusts.models import Trust


class AuthorizationDenied(PermissionDenied):
    """Raised when a mutation is refused. Callers must not write after this."""


def content_permission_code(model, action):
    return '%s.%s_%s' % (model._meta.app_label, action, model._meta.model_name)


def can_read_content(user, obj):
    if not is_active_principal(user):
        return False
    return user.has_perm(content_permission_code(obj.__class__, 'read'), obj)


def can_administer_content(user, obj):
    """True only when ``user`` has ``change`` on ``obj``.

    ``read`` and group membership alone are insufficient.
    """
    if not is_active_principal(user):
        return False
    return user.has_perm(content_permission_code(obj.__class__, 'change'), obj)


def has_trust_row_perm(user, trust, perm):
    """Grant on this Trust row (trustee / group.permissions / role).

    This does **not** follow ``Trust.trust`` parent resolution used by
    ``has_perm`` when the object itself is a ``Trust``. Create-under-trust
    and trust-row administration use this check.
    """
    if not is_active_principal(user) or trust is None:
        return False
    permission = Trust.objects.get_permission(perm) if isinstance(perm, str) else perm
    return Trust.objects.filter(pk=trust.pk).filter(
        trust_grant_q(user, permission)
    ).exists()


def can_administer_trust(user, trust, via_content=None):
    """Administrative ``change`` on a Trust.

    If ``via_content`` is given, the actor must have ``change`` on that
    content and the content must belong to ``trust``. Otherwise the actor
    needs a ``change_trust`` grant on the trust row itself.
    """
    if via_content is not None:
        if getattr(via_content, 'trust_id', None) != trust.pk:
            return False
        return can_administer_content(user, via_content)
    return has_trust_row_perm(user, trust, 'change')


def trusts_using_group(group):
    return Trust.objects.filter(groups=group).distinct()


def can_manage_group_membership(user, group, via_content=None):
    """True when ``user`` can change members of ``group``.

    Membership is global. The actor must administer every trust that
    currently uses the group. An unused group has no trust scope and
    cannot be managed here. Being a member of the group is not enough.
    """
    if not is_active_principal(user) or group is None:
        return False
    trusts = list(trusts_using_group(group))
    if not trusts:
        return False
    return all(
        can_administer_trust(
            user,
            trust,
            via_content=via_content if (
                via_content is not None and getattr(via_content, 'trust_id', None) == trust.pk
            ) else None,
        )
        for trust in trusts
    )


def _require(condition, message):
    if not condition:
        raise AuthorizationDenied(message)


def resolve_entity_id(model, pk, queryset=None):
    """Resolve a submitted primary key against an authorized queryset."""
    qs = queryset if queryset is not None else model._default_manager.all()
    try:
        return qs.get(pk=pk)
    except (model.DoesNotExist, ValueError, TypeError):
        raise AuthorizationDenied('Submitted entity is outside the authorized scope.')


def grant_trustee(actor, content, user, perm):
    """Grant a TrustUserPermission on ``content.trust``. Requires ``change``."""
    _require(can_administer_content(actor, content),
             'change permission is required to grant collaborators.')
    Entity = get_entity_model()
    if not isinstance(user, Entity):
        user = resolve_entity_id(Entity, user)
    content.grant(perm, user)
    return user


def revoke_trustee(actor, content, user, perm=None):
    """Revoke trustee rows on ``content.trust`` only. Requires ``change``."""
    _require(can_administer_content(actor, content),
             'change permission is required to revoke collaborators.')
    Entity = get_entity_model()
    scope = Entity._default_manager.filter(
        trustpermissions__trust=content.trust
    ).distinct()
    if not isinstance(user, Entity):
        user = resolve_entity_id(Entity, user, queryset=scope)
    elif not scope.filter(pk=user.pk).exists():
        raise AuthorizationDenied('Submitted entity is outside the authorized scope.')
    content.revoke(perm, user)
    return user


def associate_group_with_trust(actor, content, group):
    """Attach ``group`` to ``content.trust``. Does not write Group.permissions."""
    _require(can_administer_content(actor, content),
             'change permission is required to associate a team.')
    Group = get_group_model()
    if not isinstance(group, Group):
        group = resolve_entity_id(Group, group)
    content.trust.groups.add(group)
    return group


def disassociate_group_from_trust(actor, content, group):
    """Detach ``group`` from ``content.trust`` only. Requires ``change``."""
    _require(can_administer_content(actor, content),
             'change permission is required to remove a team.')
    Group = get_group_model()
    scope = content.trust.groups.all()
    if not isinstance(group, Group):
        group = resolve_entity_id(Group, group, queryset=scope)
    elif not scope.filter(pk=group.pk).exists():
        raise AuthorizationDenied('Submitted entity is outside the authorized scope.')
    content.trust.groups.remove(group)
    return group


def refuse_group_permission_write():
    """Group.permissions is global; never treat it as project-local."""
    raise AuthorizationDenied(
        'Group.permissions is a global Django relation, not a per-trust '
        'setting. Associate the group with the trust (Trust.groups) and '
        'use Role permissions or TrustUserPermission. Genuine per-trust '
        'group rights need a model redesign and are not implemented.'
    )


def add_group_member(actor, group, user, via_content=None):
    """Add ``user`` to ``group``. Requires admin on every trust using the group."""
    Group = get_group_model()
    if not isinstance(group, Group):
        group = resolve_entity_id(Group, group)
    _require(
        can_manage_group_membership(actor, group, via_content=via_content),
        'Administrative change on every trust using this group is required '
        'to add members. Membership or read alone is not enough.',
    )
    Entity = get_entity_model()
    if not isinstance(user, Entity):
        user = resolve_entity_id(Entity, user)
    group.user_set.add(user)
    return user


def remove_group_member(actor, group, user, via_content=None):
    """Remove ``user`` from ``group``. Same authority as ``add_group_member``."""
    Group = get_group_model()
    if not isinstance(group, Group):
        group = resolve_entity_id(Group, group)
    _require(
        can_manage_group_membership(actor, group, via_content=via_content),
        'Administrative change on every trust using this group is required '
        'to remove members. Membership or read alone is not enough.',
    )
    Entity = get_entity_model()
    scope = group.user_set.all()
    if not isinstance(user, Entity):
        user = resolve_entity_id(Entity, user, queryset=scope)
    elif not scope.filter(pk=user.pk).exists():
        raise AuthorizationDenied('Submitted entity is outside the authorized scope.')
    group.user_set.remove(user)
    return user


def create_team(actor, trust, name, via_content=None):
    """Create a Group, attach it to ``trust``, and add ``actor`` as a member."""
    _require(
        can_administer_trust(actor, trust, via_content=via_content),
        'change permission is required to create a team on this trust.',
    )
    Group = get_group_model()
    group = Group.objects.create(name=name)
    trust.groups.add(group)
    group.user_set.add(actor)
    return group


# Imported by views; keep unused-import checkers from dropping the TUP symbol
# if a caller introspects this module for mutation targets.
__all__ = [
    'AuthorizationDenied',
    'add_group_member',
    'associate_group_with_trust',
    'can_administer_content',
    'can_administer_trust',
    'can_manage_group_membership',
    'can_read_content',
    'content_permission_code',
    'create_team',
    'disassociate_group_from_trust',
    'grant_trustee',
    'has_trust_row_perm',
    'refuse_group_permission_write',
    'remove_group_member',
    'resolve_entity_id',
    'revoke_trustee',
    'trusts_using_group',
]
