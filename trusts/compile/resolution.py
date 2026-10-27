"""Registration path and hop resolution.

Metadata only: Django ``_meta`` and path info, no SQL. Shared hop math
lives in ``trusts.plan.hops``. The registration resolvers that need
registry-shaped validation stay here.
"""

from django.contrib.contenttypes.fields import (
    GenericForeignKey,
    GenericRelation,
)
from django.core.exceptions import FieldDoesNotExist

from django.contrib.auth.models import Group, Permission

from trusts.plan.hops import (
    lookup_text,
    path_text,
    resolved_hop,
)
from trusts.compile.graph import _is_model_class
from trusts.errors import TrustsConfigurationError
from trusts.plan.grammar import missing_field


def _classify_field(field):
    if isinstance(field, (GenericForeignKey, GenericRelation)):
        return 'gfk'
    if not getattr(field, 'is_relation', False):
        return 'scalar'
    if getattr(field, 'many_to_many', False):
        return 'm2m'
    if getattr(field, 'one_to_one', False) and not getattr(field, 'concrete', False):
        return 'reverse_o2o'
    if getattr(field, 'one_to_many', False):
        return 'reverse_o2m'
    if getattr(field, 'auto_created', False) and not getattr(field, 'concrete', False):
        return 'reverse'
    related = getattr(field, 'related_model', None)
    if related is None:
        return 'gfk'
    return 'single'


def _group_permissions_field():
    """The ``auth.Group`` relation the compiler walks to ``Permission``."""
    try:
        field = Group._meta.get_field('permissions')
    except FieldDoesNotExist:
        raise TrustsConfigurationError(
            'auth.Group has no permissions relation for the compiler '
            'to follow.'
        )
    return field


def _resolve_group_path(root, path):
    """Forward single-valued hops that must end at ``auth.Group``.

    Applications stop at the group. ``Group.permissions`` is not part
    of this path; ``_append_group_permissions`` owns that hop. Zero SQL.
    """
    if not path:
        raise TrustsConfigurationError(
            'group must be a non-empty root-relative path from %s '
            'ending at auth.Group.' % root._meta.label
        )
    permissions_field = _group_permissions_field()
    current = root
    related = None
    target_attname = None
    n = len(path)
    for index, name in enumerate(path):
        is_last = index == n - 1
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist:
            raise TrustsConfigurationError(
                'group path %r refers to missing field %r on %s. '
                'The path must end at auth.Group.'
                % (path_text(path), name, current._meta.label)
            )
        kind = _classify_field(field)
        on_group = (
            current._meta.concrete_model is Group._meta.concrete_model
        )
        if (
            on_group
            and name == permissions_field.name
            and kind == 'm2m'
        ):
            raise TrustsConfigurationError(
                'group path %r must end at auth.Group. The compiler '
                'follows Group.permissions; do not append permissions.'
                % (path_text(path),)
            )
        if kind != 'single':
            raise TrustsConfigurationError(
                'group path %r must be forward single-valued hops '
                'ending at auth.Group; %r on %s is not allowed.'
                % (path_text(path), name, current._meta.label)
            )
        related, target_attname = resolved_hop(field, 'group', path)
        if not is_last:
            current = related
    if related._meta.concrete_model is not Group._meta.concrete_model:
        raise TrustsConfigurationError(
            'group path %r must end at auth.Group; got %s.'
            % (path_text(path), related._meta.label)
        )
    return (
        tuple(path),
        related._meta.concrete_model,
        lookup_text(path),
        target_attname,
    )


def _append_group_permissions(group_path, group_field):
    """Compiler-owned ``Group.permissions`` hop onto ``auth.Permission``."""
    field = _group_permissions_field()
    if _classify_field(field) != 'm2m':
        raise TrustsConfigurationError(
            'auth.Group.permissions must be a many-to-many relation '
            'to auth.Permission.'
        )
    hop = tuple(group_path) + (field.name,)
    related, target = _resolve_m2m_terminal(field, 'group', hop)
    if related._meta.concrete_model is not Permission._meta.concrete_model:
        raise TrustsConfigurationError(
            'auth.Group.permissions must terminate on auth.Permission; '
            'got %s.' % related._meta.label
        )
    return (
        hop,
        Permission._meta.concrete_model,
        '%s__%s' % (group_field, field.name),
        target,
    )


def _require_one_permission_source(permission, group):
    """``permission=`` and ``group=`` are mutually exclusive and required."""
    if permission is not None and group is not None:
        raise TrustsConfigurationError(
            'register accepts permission= or group=, not both.'
        )
    if permission is None and group is None:
        raise TrustsConfigurationError(
            'register requires permission= or group=.'
        )


_SUFFIX_KINDS = frozenset(('single', 'reverse_o2o', 'reverse_o2m'))


_SUFFIX_MAX = 2


def _m2m_related_model(field):
    """Related model of a many-to-many field. Metadata only (zero SQL)."""
    related = getattr(field, 'related_model', None)
    if not _is_model_class(related):
        remote = getattr(field, 'remote_field', None)
        model = getattr(remote, 'model', None) if remote is not None else None
        if _is_model_class(model):
            related = model
    if not _is_model_class(related):
        return None
    return related._meta.concrete_model


def _m2m_related_target_attname(field, related):
    """Attname the M2M through-FK uses on ``related`` (PK or ``to_field``)."""
    through = getattr(getattr(field, 'remote_field', None), 'through', None)
    if through is None:
        pk = related._meta.pk
        return getattr(pk, 'attname', None)
    for hop in through._meta.get_fields():
        if not getattr(hop, 'is_relation', False):
            continue
        if getattr(hop, 'many_to_many', False):
            continue
        remote = getattr(hop, 'related_model', None)
        if not _is_model_class(remote):
            continue
        if remote._meta.concrete_model is not related._meta.concrete_model:
            continue
        target = getattr(hop, 'target_field', None)
        attname = getattr(target, 'attname', None)
        if attname:
            return attname
    pk = related._meta.pk
    return getattr(pk, 'attname', None)


def _resolve_m2m_terminal(field, role, path):
    """Resolve a terminal many-to-many hop without ``get_path_info()``.

    M2M path information is two joins (through table + target). Membership
    correlation uses the related model and its primary key only.
    """
    related = _m2m_related_model(field)
    if related is None:
        raise TrustsConfigurationError(
            '%s path %r does not terminate on a model.'
            % (role, path_text(path))
        )
    pk = related._meta.pk
    attname = getattr(pk, 'attname', None)
    if not attname:
        raise TrustsConfigurationError(
            '%s path %r does not expose one supported target field.'
            % (role, path_text(path))
        )
    return related, attname


def _resolve_permission_in_m2m(field, role, path, *, require_pk=False):
    """Resolve one permission_in M2M hop from ``_meta`` / through-FK metadata.

    Non-PK ``to_field`` targets are rejected so stored-column ``F()``
    comparison cannot fail open on colliding unique values.
    """
    related = _m2m_related_model(field)
    if related is None:
        raise TrustsConfigurationError(
            '%s path %r does not terminate on a model.'
            % (role, path_text(path))
        )
    attname = _m2m_related_target_attname(field, related)
    if not attname:
        raise TrustsConfigurationError(
            '%s path %r does not expose one supported target field.'
            % (role, path_text(path))
        )
    pk_attname = getattr(related._meta.pk, 'attname', None)
    if require_pk and attname != pk_attname:
        raise TrustsConfigurationError(
            '%s path %r must share one resolved comparison field; '
            'got %s.%s and %s.%s.'
            % (
                role, path_text(path),
                related._meta.label, attname,
                related._meta.label, pk_attname,
            )
        )
    return related, attname


def _resolve_permission_path(root, path):
    """Validate a ``permission=`` path and return lookup metadata.

    The direct shape is unchanged: exactly one forward single-valued
    hop, to whatever model that hop names. The collection shape is zero
    or more forward single-valued hops followed by exactly one forward
    many-to-many to ``auth.Permission``. The comparison field is that
    relation's primary key; a non-PK ``to_field`` on the through table
    fails closed. A collection that terminates on another model fails
    closed so a permission string cannot match a colliding primary key.
    A reverse many-to-many, a generic foreign key, a non-PK through
    target, a terminal other than ``auth.Permission``, and a multi-hop
    all-forward path fail closed. An intermediate many-to-many also
    fails closed; that shape is deferred, not rejected as a design
    direction. Zero SQL.
    """
    role = 'permission'
    if not path:
        raise TrustsConfigurationError(
            '%s must be a non-empty root-relative path from %s.'
            % (role, root._meta.label)
        )
    current = root
    n = len(path)
    for index, name in enumerate(path):
        is_last = index == n - 1
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist:
            raise missing_field(role, path, name, current)
        kind = _classify_field(field)
        if kind == 'scalar':
            raise TrustsConfigurationError(
                '%s path %r traverses scalar field %r on %s; only '
                'single-valued relations are supported.'
                % (role, path_text(path), name, current._meta.label)
            )
        if kind == 'gfk':
            raise TrustsConfigurationError(
                '%s path %r uses a generic foreign key %r on %s; generic '
                'foreign keys are not supported.'
                % (role, path_text(path), name, current._meta.label)
            )
        if kind == 'm2m':
            if getattr(field, 'auto_created', False):
                raise TrustsConfigurationError(
                    '%s path %r uses reverse relation %r on %s; '
                    'multi-valued and reverse traversals are not supported.'
                    % (role, path_text(path), name, current._meta.label)
                )
            if not is_last:
                raise TrustsConfigurationError(
                    '%s path %r uses intermediate multi-valued field %r '
                    'on %s; an intermediate many-to-many is not accepted '
                    'on this permission path.'
                    % (role, path_text(path), name, current._meta.label)
                )
            return _permission_m2m_result(field, path)
        if kind in ('reverse_o2o', 'reverse_o2m', 'reverse'):
            if kind == 'reverse_o2o':
                raise TrustsConfigurationError(
                    '%s path %r uses reverse one-to-one relation %r on %s; '
                    'reverse one-to-one traversals are not supported.'
                    % (role, path_text(path), name, current._meta.label)
                )
            if not is_last:
                raise TrustsConfigurationError(
                    '%s path %r uses reverse relation %r on %s before '
                    'the final hop; reverse relations are only '
                    'supported as the final content hop.'
                    % (role, path_text(path), name, current._meta.label)
                )
            raise TrustsConfigurationError(
                '%s path %r uses reverse relation %r on %s; multi-valued '
                'and reverse traversals are not supported.'
                % (role, path_text(path), name, current._meta.label)
            )
        if kind != 'single':
            raise TrustsConfigurationError(
                '%s path %r uses unsupported field %r on %s.'
                % (role, path_text(path), name, current._meta.label)
            )
        related, _target_attname = resolved_hop(field, role, path)
        if is_last:
            if index != 0:
                raise TrustsConfigurationError(
                    '%s path %r is not a direct single-valued relation; '
                    'only direct paths are supported.'
                    % (role, path_text(path))
                )
            return tuple(path), related, lookup_text(path), _target_attname
        current = related


def _permission_m2m_result(field, path):
    """Terminal forward M2M lookup: path, ``auth.Permission``, lookup, PK."""
    related, target_attname = _resolve_permission_in_m2m(
        field, 'permission', path, require_pk=True,
    )
    if related._meta.concrete_model is not Permission._meta.concrete_model:
        raise TrustsConfigurationError(
            'permission path %r terminates on %s, not auth.Permission.'
            % (path_text(path), related._meta.label)
        )
    return tuple(path), related, lookup_text(path), target_attname


def _resolve_path(root, path, role, *, trailing_reverse=False,
                  terminal_membership=False):
    """Validate a root-relative path and return lookup metadata.

    Permission paths are resolved by ``_resolve_permission_path``: one
    direct single-valued hop, or zero or more forward single-valued hops
    followed by exactly one terminal forward many-to-many. A user path
    may be that same direct hop, or zero or more forward single-valued
    hops followed by exactly one terminal M2M membership hop. Reverse
    one-to-many requester paths stay rejected. A content path may be a
    direct hop, or one or more single-valued hops, then a reverse
    one-to-many gateway, then zero to two suffix hops. Before the gateway,
    a single-valued hop may be forward or reverse one-to-one. A suffix hop
    is a forward single-valued, reverse one-to-one, or reverse one-to-many
    relation.
    """
    if not path:
        raise TrustsConfigurationError(
            '%s must be a non-empty root-relative path from %s.'
            % (role, root._meta.label)
        )

    current = root
    related = None
    target_attname = None
    gateway_index = None
    last_kind = None
    n = len(path)

    for index, name in enumerate(path):
        is_last = index == n - 1
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist:
            raise missing_field(role, path, name, current)

        kind = _classify_field(field)
        last_kind = kind
        if terminal_membership and is_last and kind == 'm2m':
            related, target_attname = _resolve_m2m_terminal(field, role, path)
            break
        if kind == 'scalar':
            raise TrustsConfigurationError(
                '%s path %r traverses scalar field %r on %s; only '
                'single-valued relations are supported.'
                % (role, path_text(path), name, current._meta.label)
            )
        if kind == 'm2m':
            raise TrustsConfigurationError(
                '%s path %r uses multi-valued field %r on %s; many-to-many '
                'and other multi-valued traversals are not supported.'
                % (role, path_text(path), name, current._meta.label)
            )
        if kind == 'gfk':
            raise TrustsConfigurationError(
                '%s path %r uses a generic foreign key %r on %s; generic '
                'foreign keys are not supported.'
                % (role, path_text(path), name, current._meta.label)
            )
        if trailing_reverse:
            if gateway_index is None:
                if kind == 'single':
                    pass
                elif kind == 'reverse_o2o' and not is_last:
                    # A reverse one-to-one is still a single-valued join.
                    # It may lead to the one reverse one-to-many gateway,
                    # but it is not itself a supported content terminal.
                    pass
                elif kind == 'reverse_o2m' and index > 0:
                    gateway_index = index
                elif kind == 'reverse_o2o':
                    raise TrustsConfigurationError(
                        '%s path %r uses reverse one-to-one relation %r on '
                        '%s; reverse one-to-one is not a valid content '
                        'terminal or gateway.'
                        % (role, path_text(path), name, current._meta.label)
                    )
                elif kind in ('reverse_o2m', 'reverse'):
                    if not is_last:
                        raise TrustsConfigurationError(
                            '%s path %r uses reverse relation %r on %s '
                            'before the gateway; reverse relations require '
                            'a preceding forward hop.'
                            % (
                                role, path_text(path), name,
                                current._meta.label,
                            )
                        )
                    raise TrustsConfigurationError(
                        '%s path %r uses reverse relation %r on %s; '
                        'multi-valued and reverse traversals are not '
                        'supported.'
                        % (role, path_text(path), name, current._meta.label)
                    )
                else:
                    raise TrustsConfigurationError(
                        '%s path %r uses unsupported field %r on %s.'
                        % (role, path_text(path), name, current._meta.label)
                    )
            else:
                suffix_depth = index - gateway_index
                if suffix_depth > _SUFFIX_MAX:
                    raise TrustsConfigurationError(
                        '%s path %r has more than two hops after the '
                        'reverse one-to-many gateway.'
                        % (role, path_text(path))
                    )
                if kind not in _SUFFIX_KINDS:
                    raise TrustsConfigurationError(
                        '%s path %r uses unsupported field %r on %s after '
                        'the gateway; suffix hops must be forward '
                        'single-valued, reverse one-to-one, or reverse '
                        'one-to-many.'
                        % (role, path_text(path), name, current._meta.label)
                    )
        elif kind in ('reverse_o2o', 'reverse_o2m', 'reverse'):
            if kind == 'reverse_o2o':
                raise TrustsConfigurationError(
                    '%s path %r uses reverse one-to-one relation %r on %s; '
                    'reverse one-to-one traversals are not supported.'
                    % (role, path_text(path), name, current._meta.label)
                )
            if not is_last:
                raise TrustsConfigurationError(
                    '%s path %r uses reverse relation %r on %s before '
                    'the final hop; reverse relations are only '
                    'supported as the final content hop.'
                    % (role, path_text(path), name, current._meta.label)
                )
            raise TrustsConfigurationError(
                '%s path %r uses reverse relation %r on %s; multi-valued '
                'and reverse traversals are not supported.'
                % (role, path_text(path), name, current._meta.label)
            )
        elif kind != 'single':
            raise TrustsConfigurationError(
                '%s path %r uses unsupported field %r on %s.'
                % (role, path_text(path), name, current._meta.label)
            )

        related, target_attname = resolved_hop(field, role, path)
        if not is_last:
            current = related

    if n != 1 and gateway_index is None:
        if terminal_membership and last_kind == 'm2m':
            pass
        elif trailing_reverse:
            raise TrustsConfigurationError(
                '%s path %r is not a direct single-valued relation or a '
                'forward path ending in one reverse one-to-many; a reverse '
                'one-to-one may appear only as a single-valued hop before '
                'that gateway.'
                % (role, path_text(path))
            )
        else:
            raise TrustsConfigurationError(
                '%s path %r is not a direct single-valued relation; only '
                'direct paths are supported.'
                % (role, path_text(path))
            )
    return tuple(path), related, lookup_text(path), target_attname


def _resolve_forward_singles(root, path, role):
    """One or more forward single-valued hops. No multi-valued walks."""
    if not path:
        raise TrustsConfigurationError(
            '%s must be a non-empty root-relative path from %s.'
            % (role, root._meta.label)
        )
    current = root
    related = None
    target_attname = None
    n = len(path)
    for index, name in enumerate(path):
        is_last = index == n - 1
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist:
            raise missing_field(role, path, name, current)
        kind = _classify_field(field)
        if kind == 'scalar':
            raise TrustsConfigurationError(
                '%s path %r traverses scalar field %r on %s; only '
                'single-valued relations are supported.'
                % (role, path_text(path), name, current._meta.label)
            )
        if kind in ('m2m', 'reverse_o2m', 'reverse', 'reverse_o2o'):
            raise TrustsConfigurationError(
                '%s path %r uses extra or intermediate multi-valued '
                'field %r on %s.'
                % (role, path_text(path), name, current._meta.label)
            )
        if kind == 'gfk':
            raise TrustsConfigurationError(
                '%s path %r uses a generic foreign key %r on %s; generic '
                'foreign keys are not supported.'
                % (role, path_text(path), name, current._meta.label)
            )
        if kind != 'single':
            raise TrustsConfigurationError(
                '%s path %r uses unsupported field %r on %s.'
                % (role, path_text(path), name, current._meta.label)
            )
        related, target_attname = resolved_hop(field, role, path)
        if not is_last:
            current = related
    return tuple(path), related, lookup_text(path), target_attname


def _resolve_permission_in_path(root, path, role, permission_model,
                                permission_target=None):
    """Bounded ceiling path from ``_meta`` / stored path metadata.

    Accepted shapes, after zero or more forward single-valued hops:

    * optional intermediate reverse O2M, then a terminal M2M or reverse
      O2M on the registered permission model;
    * exactly one intermediate M2M, then a terminal M2M on the
      registered permission model.

    Extra multi-hops, M2M-then-single, GFK, wrong terminals, and
    non-PK ``to_field`` membership targets are rejected (zero SQL).
    """
    if not path:
        raise TrustsConfigurationError(
            '%s must be a non-empty root-relative path from %s.'
            % (role, root._meta.label)
        )
    current = root
    related = None
    target_attname = None
    intermediate_kind = None
    n = len(path)
    for index, name in enumerate(path):
        is_last = index == n - 1
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist:
            raise missing_field(role, path, name, current)
        kind = _classify_field(field)
        if kind == 'scalar':
            raise TrustsConfigurationError(
                '%s path %r traverses scalar field %r on %s.'
                % (role, path_text(path), name, current._meta.label)
            )
        if kind == 'gfk':
            raise TrustsConfigurationError(
                '%s path %r uses a generic foreign key %r on %s; generic '
                'foreign keys are not supported.'
                % (role, path_text(path), name, current._meta.label)
            )
        if kind == 'single':
            if intermediate_kind is not None:
                raise TrustsConfigurationError(
                    '%s path %r uses extra or intermediate multi-valued '
                    'walks; single-valued hops cannot follow a collection.'
                    % (role, path_text(path))
                )
            if is_last:
                raise TrustsConfigurationError(
                    '%s path %r must terminate on a multi-valued '
                    'membership hop.'
                    % (role, path_text(path))
                )
            related, target_attname = resolved_hop(field, role, path)
            current = related
            continue
        if kind == 'm2m' and not is_last:
            if intermediate_kind is not None:
                raise TrustsConfigurationError(
                    '%s path %r uses extra or intermediate multi-valued '
                    'field %r on %s.'
                    % (role, path_text(path), name, current._meta.label)
                )
            intermediate_kind = 'm2m'
            related, target_attname = _resolve_permission_in_m2m(
                field, role, path, require_pk=False,
            )
            current = related
            continue
        if kind == 'reverse_o2m' and not is_last:
            if intermediate_kind is not None:
                raise TrustsConfigurationError(
                    '%s path %r uses extra or intermediate multi-valued '
                    'field %r on %s.'
                    % (role, path_text(path), name, current._meta.label)
                )
            intermediate_kind = 'reverse_o2m'
            related, target_attname = resolved_hop(field, role, path)
            current = related
            continue
        if kind in ('m2m', 'reverse_o2m') and is_last:
            if intermediate_kind == 'm2m' and kind != 'm2m':
                raise TrustsConfigurationError(
                    '%s path %r uses extra or intermediate multi-valued '
                    'field %r on %s.'
                    % (role, path_text(path), name, current._meta.label)
                )
            if kind == 'm2m':
                related, target_attname = _resolve_permission_in_m2m(
                    field, role, path, require_pk=True,
                )
            else:
                related, target_attname = resolved_hop(field, role, path)
            if related is not permission_model:
                raise TrustsConfigurationError(
                    '%s path %r terminates on %s, not the registered '
                    'permission model %s.'
                    % (
                        role, path_text(path), related._meta.label,
                        permission_model._meta.label,
                    )
                )
            if (
                permission_target is not None
                and target_attname != permission_target
            ):
                raise TrustsConfigurationError(
                    '%s path %r must share one resolved comparison field; '
                    'got %s.%s and %s.%s.'
                    % (
                        role, path_text(path),
                        related._meta.label, target_attname,
                        permission_model._meta.label, permission_target,
                    )
                )
            return tuple(path), related, lookup_text(path), target_attname
        if kind in ('m2m', 'reverse_o2m', 'reverse', 'reverse_o2o'):
            raise TrustsConfigurationError(
                '%s path %r uses extra or intermediate multi-valued '
                'field %r on %s.'
                % (role, path_text(path), name, current._meta.label)
            )
        raise TrustsConfigurationError(
            '%s path %r uses unsupported field %r on %s.'
            % (role, path_text(path), name, current._meta.label)
        )
    raise TrustsConfigurationError(
        '%s path %r must terminate on a multi-valued membership hop.'
        % (role, path_text(path))
    )
