"""Administrative authority for trust-scoped mutations.

Ordinary ``read`` and mere group membership are not enough to mutate
collaborators, group associations, local TrustGroup grants, or team
membership. Callers must use these helpers (or equivalent ``change``
checks) before writing.

``Group.permissions`` (and role assignments on a group) are the global
capability ceiling. Per-trust group rights are ``TrustGroup.permissions``,
a locally enabled subset. Helpers here never write ``Group.permissions``.
Associating a group without local grants grants nothing.

``Group.user_set`` is also global. Adding a member to a group that two
trusts share grants that group's *effective* rights in both (still subject
to each trust's local grants). Membership changes therefore require
administrative ``change`` on every trust that uses the group.
"""

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Group
from django.core.exceptions import PermissionDenied, ValidationError
from django.db.models import Model

from trusts.zero import supported_entity_contract, supported_group_contract
from trusts.zero.query import is_active_principal, trust_grant_q
from trusts.zero.models import Trust


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
    """Grant on this Trust row (trustee or TrustGroup local/global intersection).

    This does **not** follow ``Trust.trust`` parent resolution used by
    ``has_perm`` when the object itself is a ``Trust``. Create-under-trust
    and trust-row administration use this check.
    """
    from trusts.zero.query import require_configured_requester

    if user is None or getattr(user, 'is_anonymous', False) or trust is None:
        return False
    require_configured_requester(user)
    if not is_active_principal(user):
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
    if not supported_group_contract():
        return Trust.objects.none()
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


def _configured_or_pk(obj, model, queryset=None):
    """Resolve ``obj`` as ``model`` or a PK. Other model instances fail closed."""
    if isinstance(obj, model):
        return obj
    if isinstance(obj, Model):
        raise AuthorizationDenied('Submitted entity is outside the authorized scope.')
    return resolve_entity_id(model, obj, queryset=queryset)


def _require_entity_contract():
    if not supported_entity_contract():
        raise AuthorizationDenied(
            'TRUSTS_ENTITY_MODEL must be AUTH_USER_MODEL; '
            'silencing trusts.E003 does not enable a non-user entity.'
        )
    return get_user_model()


def _require_group_contract():
    if not supported_group_contract():
        raise AuthorizationDenied(
            'TRUSTS_GROUP_MODEL must be auth.Group; '
            'silencing trusts.E004 does not enable a non-auth group model.'
        )
    return Group


def grant_trustee(actor, content, user, perm):
    """Grant a TrustUserPermission on ``content.trust``. Requires ``change``."""
    _require(can_administer_content(actor, content),
             'change permission is required to grant collaborators.')
    user = _configured_or_pk(user, _require_entity_contract())
    content.grant(perm, user)
    return user


def revoke_trustee(actor, content, user, perm=None):
    """Revoke trustee rows on ``content.trust`` only. Requires ``change``."""
    _require(can_administer_content(actor, content),
             'change permission is required to revoke collaborators.')
    Entity = _require_entity_contract()
    scope = Entity._default_manager.filter(
        trustpermissions__trust=content.trust
    ).distinct()
    if isinstance(user, Entity):
        if not scope.filter(pk=user.pk).exists():
            raise AuthorizationDenied('Submitted entity is outside the authorized scope.')
    elif isinstance(user, Model):
        raise AuthorizationDenied('Submitted entity is outside the authorized scope.')
    else:
        user = resolve_entity_id(Entity, user, queryset=scope)
    content.revoke(perm, user)
    return user


def _resolve_group(group, queryset=None):
    return _configured_or_pk(group, _require_group_contract(), queryset=queryset)


def _resolve_content_perm(content, perm):
    if perm is None:
        return None
    Permission = type(content).objects.get_permission(perm) if isinstance(perm, str) else perm
    return Permission


def associate_group_with_trust(actor, content, group, permissions=None):
    """Attach ``group`` to ``content.trust``. Does not write Group.permissions.

    Optional ``permissions`` are local TrustGroup grants and must be a
    subset of the group's global ceiling. Omitting them associates the
    group without granting anything. When ``permissions`` is given, the
    association is created only if every grant is accepted; a rejected
    set leaves no TrustGroup row for a previously unassociated group.
    """
    _require(can_administer_content(actor, content),
             'change permission is required to associate a team.')
    group = _resolve_group(group)
    if permissions:
        try:
            content.trust.set_group_permissions(group, [
                _resolve_content_perm(content, perm) for perm in permissions
            ])
        except ValidationError as exc:
            raise AuthorizationDenied(str(exc))
    else:
        content.trust.groups.add(group)
    return group


def disassociate_group_from_trust(actor, content, group):
    """Detach ``group`` from ``content.trust`` only. Requires ``change``."""
    _require(can_administer_content(actor, content),
             'change permission is required to remove a team.')
    Group = _require_group_contract()
    scope = content.trust.groups.all()
    if isinstance(group, Group):
        if not scope.filter(pk=group.pk).exists():
            raise AuthorizationDenied('Submitted entity is outside the authorized scope.')
    elif isinstance(group, Model):
        raise AuthorizationDenied('Submitted entity is outside the authorized scope.')
    else:
        group = resolve_entity_id(Group, group, queryset=scope)
    content.trust.groups.remove(group)
    return group


def grant_trust_group_permission(actor, content, group, perm):
    """Enable a local TrustGroup grant. Requires ``change``; ceiling-enforced."""
    _require(can_administer_content(actor, content),
             'change permission is required to grant team permissions.')
    group = _resolve_group(group)
    if not content.trust.groups.filter(pk=group.pk).exists():
        raise AuthorizationDenied('Submitted entity is outside the authorized scope.')
    permission = _resolve_content_perm(content, perm)
    try:
        content.trust.grant_group_permission(group, permission)
    except ValidationError as exc:
        raise AuthorizationDenied(str(exc))
    return group


def revoke_trust_group_permission(actor, content, group, perm):
    """Remove a local TrustGroup grant. Requires ``change``."""
    _require(can_administer_content(actor, content),
             'change permission is required to revoke team permissions.')
    group = _resolve_group(group, queryset=content.trust.groups.all())
    permission = _resolve_content_perm(content, perm)
    content.trust.revoke_group_permission(group, permission)
    return group


def set_trust_group_permissions(actor, content, group, permissions):
    """Replace local TrustGroup grants. Requires ``change``; ceiling-enforced."""
    _require(can_administer_content(actor, content),
             'change permission is required to set team permissions.')
    group = _resolve_group(group, queryset=content.trust.groups.all())
    resolved = [_resolve_content_perm(content, perm) for perm in permissions]
    try:
        content.trust.set_group_permissions(group, resolved)
    except ValidationError as exc:
        raise AuthorizationDenied(str(exc))
    return group


def refuse_group_permission_write():
    """Group.permissions is the global ceiling; never treat it as project-local."""
    raise AuthorizationDenied(
        'Group.permissions is a global Django relation (the capability '
        'ceiling), not a per-trust setting. Associate the group with the '
        'trust and grant a local subset on TrustGroup.permissions.'
    )


def add_group_member(actor, group, user, via_content=None):
    """Add ``user`` to ``group``. Requires admin on every trust using the group."""
    group = _configured_or_pk(group, _require_group_contract())
    _require(
        can_manage_group_membership(actor, group, via_content=via_content),
        'Administrative change on every trust using this group is required '
        'to add members. Membership or read alone is not enough.',
    )
    user = _configured_or_pk(user, _require_entity_contract())
    group.user_set.add(user)
    return user


def remove_group_member(actor, group, user, via_content=None):
    """Remove ``user`` from ``group``. Same authority as ``add_group_member``."""
    group = _configured_or_pk(group, _require_group_contract())
    _require(
        can_manage_group_membership(actor, group, via_content=via_content),
        'Administrative change on every trust using this group is required '
        'to remove members. Membership or read alone is not enough.',
    )
    Entity = _require_entity_contract()
    scope = group.user_set.all()
    if isinstance(user, Entity):
        if not scope.filter(pk=user.pk).exists():
            raise AuthorizationDenied('Submitted entity is outside the authorized scope.')
    elif isinstance(user, Model):
        raise AuthorizationDenied('Submitted entity is outside the authorized scope.')
    else:
        user = resolve_entity_id(Entity, user, queryset=scope)
    group.user_set.remove(user)
    return user


def create_team(actor, trust, name, via_content=None):
    """Create a Group, attach it to ``trust``, and add ``actor`` as a member.

    The new association has an empty local grant set (fail closed).
    """
    _require(
        can_administer_trust(actor, trust, via_content=via_content),
        'change permission is required to create a team on this trust.',
    )
    Group = _require_group_contract()
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
    'grant_trust_group_permission',
    'has_trust_row_perm',
    'refuse_group_permission_write',
    'remove_group_member',
    'resolve_entity_id',
    'revoke_trustee',
    'revoke_trust_group_permission',
    'set_trust_group_permissions',
    'trusts_using_group',
]
