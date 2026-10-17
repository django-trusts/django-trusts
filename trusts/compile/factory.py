"""Registration marshaling and the builder-half registry.

``TrustsRegistry`` collects ``register`` and ``set_*`` calls and stores
lowered rows. ``assemble_frozen`` builds the query-time
``FrozenRegistry``. ``trusts.core`` re-exports these names. This module
does not import ``trusts.core``.
"""

__all__ = []

import inspect

from dataclasses import dataclass, field, replace

from django.core.exceptions import FieldDoesNotExist
from django.db.models import F, Model, Q
from django.db.models.query import QuerySet

from trusts.commons import (
    _auth_group_and_permission,
    _bind_record_qs,
    _lookup_text,
    _require_instance,
)
from trusts.compile.nodes import (
    All,
    Along,
    Equal,
    PermissionIn,
    Ref,
    _InquiryPermissionMatch,
    _is_model_class,
    _require_ref,
    _require_same_root,
    permission_in,
)
from trusts.compile.paths import AlongWalk, _PathBuilder
from trusts.compile.visitors import (
    ConditionAnd as _ConditionAnd,
    ConditionEq as _ConditionEq,
    ConditionIn as _ConditionIn,
    ConditionInquiryMatch as _ConditionInquiryMatch,
    ConditionProxy as _ConditionProxy,
    InquiryPermissionProxy as _InquiryPermissionProxy,
    _CONDITION_ARITY_PROBE,
    _CONDITION_EXPR_TYPES,
)
from trusts.errors import TrustsConfigurationError
from trusts.plan.contents import (
    _materialize_related_model,
    _path_text,
    _resolved_hop,
)
from trusts.plan.recursions import GrantReach
from trusts.plan.registry import FrozenRegistry
from trusts.plan.relations import (
    RelationPlan,
    _candidate_model,
    bind_checked_user,
)
from trusts.plan.standards import (
    UserCondition,
    assert_concrete_booleans,
    builtin_user_conditions,
    compile_override_q,
    compile_user_rules,
    concrete_rule,
    condition_names,
    normalize_on,
    normalize_override_on,
    rule_applies,
    validate_user_rule_name,
)


def assemble_frozen(
    registry, *, compiler, handles, relation_plan, bind_record_qs,
    grant_reach, content_model, concrete_model, require_instance,
    candidate_model,
):
    """Build the query-time registry from already-lowered rows."""
    return FrozenRegistry(
        records=registry.records,
        delegations=registry.delegations,
        compiler=compiler,
        handles=tuple(handles),
        relation_plan=relation_plan,
        bind_record_qs=bind_record_qs,
        grant_reach=grant_reach,
        content_model=content_model,
        concrete_model=concrete_model,
        require_instance=require_instance,
        candidate_model=candidate_model,
        rule_fragment=registry._rule_fragment,
        override_fragment=registry._override_fragment,
    )


def _generic_relation_types():
    """Load GFK types lazily so ``AppConfig.__init__`` can import this module.

    ``contenttypes.fields`` imports ``ContentType`` models and cannot run
    during ``Apps.populate`` phase 1.
    """
    try:
        from django.contrib.contenttypes.fields import (
            GenericForeignKey,
            GenericRelation,
        )
    except ImportError:  # pragma: no cover - contenttypes is a Django contrib app
        GenericForeignKey = type('GenericForeignKey', (), {})
        GenericRelation = type('GenericRelation', (), {})
    return GenericForeignKey, GenericRelation


def _classify_field(field):
    generic_foreign_key, generic_relation = _generic_relation_types()
    if isinstance(field, (generic_foreign_key, generic_relation)):
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
    Group, _Permission = _auth_group_and_permission()
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
    Group, _Permission = _auth_group_and_permission()
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
                % (_path_text(path), name, current._meta.label)
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
                % (_path_text(path),)
            )
        if kind != 'single':
            raise TrustsConfigurationError(
                'group path %r must be forward single-valued hops '
                'ending at auth.Group; %r on %s is not allowed.'
                % (_path_text(path), name, current._meta.label)
            )
        related, target_attname = _resolved_hop(field, 'group', path)
        if not is_last:
            current = related
    if related._meta.concrete_model is not Group._meta.concrete_model:
        raise TrustsConfigurationError(
            'group path %r must end at auth.Group; got %s.'
            % (_path_text(path), related._meta.label)
        )
    return (
        tuple(path),
        related._meta.concrete_model,
        _lookup_text(path),
        target_attname,
    )


def _append_group_permissions(group_path, group_field):
    """Compiler-owned ``Group.permissions`` hop onto ``auth.Permission``."""
    _Group, Permission = _auth_group_and_permission()
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
    _materialize_related_model(field)
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
            % (role, _path_text(path))
        )
    pk = related._meta.pk
    attname = getattr(pk, 'attname', None)
    if not attname:
        raise TrustsConfigurationError(
            '%s path %r does not expose one supported target field.'
            % (role, _path_text(path))
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
            % (role, _path_text(path))
        )
    attname = _m2m_related_target_attname(field, related)
    if not attname:
        raise TrustsConfigurationError(
            '%s path %r does not expose one supported target field.'
            % (role, _path_text(path))
        )
    pk_attname = getattr(related._meta.pk, 'attname', None)
    if require_pk and attname != pk_attname:
        raise TrustsConfigurationError(
            '%s path %r must share one resolved comparison field; '
            'got %s.%s and %s.%s.'
            % (
                role, _path_text(path),
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
            raise TrustsConfigurationError(
                '%s path %r refers to missing field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )
        kind = _classify_field(field)
        if kind == 'scalar':
            raise TrustsConfigurationError(
                '%s path %r traverses scalar field %r on %s; only '
                'single-valued relations are supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind == 'gfk':
            raise TrustsConfigurationError(
                '%s path %r uses a generic foreign key %r on %s; generic '
                'foreign keys are not supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind == 'm2m':
            if getattr(field, 'auto_created', False):
                raise TrustsConfigurationError(
                    '%s path %r uses reverse relation %r on %s; '
                    'multi-valued and reverse traversals are not supported.'
                    % (role, _path_text(path), name, current._meta.label)
                )
            if not is_last:
                raise TrustsConfigurationError(
                    '%s path %r uses intermediate multi-valued field %r '
                    'on %s; an intermediate many-to-many is not accepted '
                    'on this permission path.'
                    % (role, _path_text(path), name, current._meta.label)
                )
            return _permission_m2m_result(field, path)
        if kind in ('reverse_o2o', 'reverse_o2m', 'reverse'):
            if kind == 'reverse_o2o':
                raise TrustsConfigurationError(
                    '%s path %r uses reverse one-to-one relation %r on %s; '
                    'reverse one-to-one traversals are not supported.'
                    % (role, _path_text(path), name, current._meta.label)
                )
            if not is_last:
                raise TrustsConfigurationError(
                    '%s path %r uses reverse relation %r on %s before '
                    'the final hop; reverse relations are only '
                    'supported as the final content hop.'
                    % (role, _path_text(path), name, current._meta.label)
                )
            raise TrustsConfigurationError(
                '%s path %r uses reverse relation %r on %s; multi-valued '
                'and reverse traversals are not supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind != 'single':
            raise TrustsConfigurationError(
                '%s path %r uses unsupported field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )
        related, _target_attname = _resolved_hop(field, role, path)
        if is_last:
            if index != 0:
                raise TrustsConfigurationError(
                    '%s path %r is not a direct single-valued relation; '
                    'only direct paths are supported.'
                    % (role, _path_text(path))
                )
            return tuple(path), related, _lookup_text(path), _target_attname
        current = related


def _permission_m2m_result(field, path):
    """Terminal forward M2M lookup: path, ``auth.Permission``, lookup, PK."""
    related, target_attname = _resolve_permission_in_m2m(
        field, 'permission', path, require_pk=True,
    )
    _group, permission_model = _auth_group_and_permission()
    if related._meta.concrete_model is not permission_model._meta.concrete_model:
        raise TrustsConfigurationError(
            'permission path %r terminates on %s, not auth.Permission.'
            % (_path_text(path), related._meta.label)
        )
    return tuple(path), related, _lookup_text(path), target_attname


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
            raise TrustsConfigurationError(
                '%s path %r refers to missing field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )

        kind = _classify_field(field)
        last_kind = kind
        if terminal_membership and is_last and kind == 'm2m':
            related, target_attname = _resolve_m2m_terminal(field, role, path)
            break
        if kind == 'scalar':
            raise TrustsConfigurationError(
                '%s path %r traverses scalar field %r on %s; only '
                'single-valued relations are supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind == 'm2m':
            raise TrustsConfigurationError(
                '%s path %r uses multi-valued field %r on %s; many-to-many '
                'and other multi-valued traversals are not supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind == 'gfk':
            raise TrustsConfigurationError(
                '%s path %r uses a generic foreign key %r on %s; generic '
                'foreign keys are not supported.'
                % (role, _path_text(path), name, current._meta.label)
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
                        % (role, _path_text(path), name, current._meta.label)
                    )
                elif kind in ('reverse_o2m', 'reverse'):
                    if not is_last:
                        raise TrustsConfigurationError(
                            '%s path %r uses reverse relation %r on %s '
                            'before the gateway; reverse relations require '
                            'a preceding forward hop.'
                            % (
                                role, _path_text(path), name,
                                current._meta.label,
                            )
                        )
                    raise TrustsConfigurationError(
                        '%s path %r uses reverse relation %r on %s; '
                        'multi-valued and reverse traversals are not '
                        'supported.'
                        % (role, _path_text(path), name, current._meta.label)
                    )
                else:
                    raise TrustsConfigurationError(
                        '%s path %r uses unsupported field %r on %s.'
                        % (role, _path_text(path), name, current._meta.label)
                    )
            else:
                suffix_depth = index - gateway_index
                if suffix_depth > _SUFFIX_MAX:
                    raise TrustsConfigurationError(
                        '%s path %r has more than two hops after the '
                        'reverse one-to-many gateway.'
                        % (role, _path_text(path))
                    )
                if kind not in _SUFFIX_KINDS:
                    raise TrustsConfigurationError(
                        '%s path %r uses unsupported field %r on %s after '
                        'the gateway; suffix hops must be forward '
                        'single-valued, reverse one-to-one, or reverse '
                        'one-to-many.'
                        % (role, _path_text(path), name, current._meta.label)
                    )
        elif kind in ('reverse_o2o', 'reverse_o2m', 'reverse'):
            if kind == 'reverse_o2o':
                raise TrustsConfigurationError(
                    '%s path %r uses reverse one-to-one relation %r on %s; '
                    'reverse one-to-one traversals are not supported.'
                    % (role, _path_text(path), name, current._meta.label)
                )
            if not is_last:
                raise TrustsConfigurationError(
                    '%s path %r uses reverse relation %r on %s before '
                    'the final hop; reverse relations are only '
                    'supported as the final content hop.'
                    % (role, _path_text(path), name, current._meta.label)
                )
            raise TrustsConfigurationError(
                '%s path %r uses reverse relation %r on %s; multi-valued '
                'and reverse traversals are not supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        elif kind != 'single':
            raise TrustsConfigurationError(
                '%s path %r uses unsupported field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )

        related, target_attname = _resolved_hop(field, role, path)
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
                % (role, _path_text(path))
            )
        else:
            raise TrustsConfigurationError(
                '%s path %r is not a direct single-valued relation; only '
                'direct paths are supported.'
                % (role, _path_text(path))
            )
    return tuple(path), related, _lookup_text(path), target_attname


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
            raise TrustsConfigurationError(
                '%s path %r refers to missing field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )
        kind = _classify_field(field)
        if kind == 'scalar':
            raise TrustsConfigurationError(
                '%s path %r traverses scalar field %r on %s; only '
                'single-valued relations are supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind in ('m2m', 'reverse_o2m', 'reverse', 'reverse_o2o'):
            raise TrustsConfigurationError(
                '%s path %r uses extra or intermediate multi-valued '
                'field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind == 'gfk':
            raise TrustsConfigurationError(
                '%s path %r uses a generic foreign key %r on %s; generic '
                'foreign keys are not supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind != 'single':
            raise TrustsConfigurationError(
                '%s path %r uses unsupported field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )
        related, target_attname = _resolved_hop(field, role, path)
        if not is_last:
            current = related
    return tuple(path), related, _lookup_text(path), target_attname


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
            raise TrustsConfigurationError(
                '%s path %r refers to missing field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )
        kind = _classify_field(field)
        if kind == 'scalar':
            raise TrustsConfigurationError(
                '%s path %r traverses scalar field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind == 'gfk':
            raise TrustsConfigurationError(
                '%s path %r uses a generic foreign key %r on %s; generic '
                'foreign keys are not supported.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if kind == 'single':
            if intermediate_kind is not None:
                raise TrustsConfigurationError(
                    '%s path %r uses extra or intermediate multi-valued '
                    'walks; single-valued hops cannot follow a collection.'
                    % (role, _path_text(path))
                )
            if is_last:
                raise TrustsConfigurationError(
                    '%s path %r must terminate on a multi-valued '
                    'membership hop.'
                    % (role, _path_text(path))
                )
            related, target_attname = _resolved_hop(field, role, path)
            current = related
            continue
        if kind == 'm2m' and not is_last:
            if intermediate_kind is not None:
                raise TrustsConfigurationError(
                    '%s path %r uses extra or intermediate multi-valued '
                    'field %r on %s.'
                    % (role, _path_text(path), name, current._meta.label)
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
                    % (role, _path_text(path), name, current._meta.label)
                )
            intermediate_kind = 'reverse_o2m'
            related, target_attname = _resolved_hop(field, role, path)
            current = related
            continue
        if kind in ('m2m', 'reverse_o2m') and is_last:
            if intermediate_kind == 'm2m' and kind != 'm2m':
                raise TrustsConfigurationError(
                    '%s path %r uses extra or intermediate multi-valued '
                    'field %r on %s.'
                    % (role, _path_text(path), name, current._meta.label)
                )
            if kind == 'm2m':
                related, target_attname = _resolve_permission_in_m2m(
                    field, role, path, require_pk=True,
                )
            else:
                related, target_attname = _resolved_hop(field, role, path)
            if related is not permission_model:
                raise TrustsConfigurationError(
                    '%s path %r terminates on %s, not the registered '
                    'permission model %s.'
                    % (
                        role, _path_text(path), related._meta.label,
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
                        role, _path_text(path),
                        related._meta.label, target_attname,
                        permission_model._meta.label, permission_target,
                    )
                )
            return tuple(path), related, _lookup_text(path), target_attname
        if kind in ('m2m', 'reverse_o2m', 'reverse', 'reverse_o2o'):
            raise TrustsConfigurationError(
                '%s path %r uses extra or intermediate multi-valued '
                'field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )
        raise TrustsConfigurationError(
            '%s path %r uses unsupported field %r on %s.'
            % (role, _path_text(path), name, current._meta.label)
        )
    raise TrustsConfigurationError(
        '%s path %r must terminate on a multi-valued membership hop.'
        % (role, _path_text(path))
    )


def _validate_equal(predicate, root):
    left = _require_same_root(predicate.left, root, 'Equal left')
    right = _require_same_root(predicate.right, root, 'Equal right')
    _left_path, left_model, _left_field, left_target = _resolve_forward_singles(
        root, left._path, 'Equal left',
    )
    _right_path, right_model, _right_field, right_target = (
        _resolve_forward_singles(root, right._path, 'Equal right')
    )
    if left_model is not right_model:
        raise TrustsConfigurationError(
            'Equal paths must terminate on the same model; got %s and %s.'
            % (left_model._meta.label, right_model._meta.label)
        )
    # Compiler compares stored FK columns via F(). Distinct unique
    # fields (``to_field``) on the same model can collide across
    # objects and fail open if only the terminal model is checked.
    if left_target != right_target:
        raise TrustsConfigurationError(
            'Equal paths must share one resolved comparison field; '
            'got %s.%s and %s.%s.'
            % (
                left_model._meta.label, left_target,
                right_model._meta.label, right_target,
            )
        )


def _validate_permission_in(predicate, root, permission_model,
                            permission_target=None):
    if not predicate.refs:
        raise TrustsConfigurationError(
            'permission_in requires one or more refs.'
        )
    for ref in predicate.refs:
        bound = _require_same_root(ref, root, 'permission_in')
        _resolve_permission_in_path(
            root, bound._path, 'permission_in', permission_model,
            permission_target=permission_target,
        )


def _validate_condition(condition, root, permission_model,
                        permission_target=None):
    """Registration-time ``_meta`` validation. Zero SQL. None is a no-op."""
    if condition is None:
        return None
    if isinstance(condition, All):
        if not condition.predicates:
            raise TrustsConfigurationError(
                'All requires one or more predicates.'
            )
        for predicate in condition.predicates:
            _validate_condition(
                predicate, root, permission_model,
                permission_target=permission_target,
            )
        return condition
    if isinstance(condition, Equal):
        _validate_equal(condition, root)
        return condition
    if isinstance(condition, PermissionIn):
        _validate_permission_in(
            condition, root, permission_model,
            permission_target=permission_target,
        )
        return condition
    raise TrustsConfigurationError(
        'condition is not supported; omit it or pass None.'
    )


def _validate_delegated_condition(condition, root):
    """Validate delegated row predicates and return inquiry terminal metadata.

    Row-only equality has no permission terminal. Every inquiry-permission
    match must resolve to the same model and comparison target. Validation is
    metadata-only and therefore remains zero SQL.
    """
    if condition is None:
        return condition, None, None
    matches = []

    def visit(node):
        if isinstance(node, All):
            if not node.predicates:
                raise TrustsConfigurationError(
                    'All requires one or more predicates.'
                )
            for predicate in node.predicates:
                visit(predicate)
            return
        if isinstance(node, Equal):
            _validate_equal(node, root)
            return
        if isinstance(node, _InquiryPermissionMatch):
            ref = _require_same_root(
                node.ref, root, 'delegated inquiry permission',
            )
            _path, model, _field, target = _resolve_permission_path(
                root, ref._path,
            )
            matches.append((model, target))
            return
        raise TrustsConfigurationError(
            'delegated condition is not supported; omit it or use '
            'row equality and inquiry-permission matches.'
        )

    visit(condition)
    if not matches:
        return condition, None, None
    first_model, first_target = matches[0]
    for model, target in matches[1:]:
        if model is not first_model or target != first_target:
            raise TrustsConfigurationError(
                'Delegated inquiry-permission paths must share one model '
                'and comparison target.'
            )
    return condition, first_model, first_target


_ALONG_BOUND_MIN = 1


_ALONG_BOUND_MAX = 64


_INTEGER_IDENTITY_TYPES = frozenset((
    'AutoField',
    'BigAutoField',
    'SmallAutoField',
    'IntegerField',
    'BigIntegerField',
    'SmallIntegerField',
    'PositiveIntegerField',
    'PositiveSmallIntegerField',
    'PositiveBigIntegerField',
))


_TEXT_IDENTITY_TYPES = frozenset((
    'CharField',
    'TextField',
    'SlugField',
))


_UUID_IDENTITY_TYPES = frozenset(('UUIDField',))


def _common_prefix(left, right):
    n = 0
    for a, b in zip(left, right):
        if a != b:
            break
        n += 1
    return left[:n]


def _target_field(field, role, path):
    """Return ``(related_model, target_field)`` for one hop."""
    related, attname = _resolved_hop(field, role, path)
    target = related._meta.get_field(attname)
    if getattr(target, 'attname', None) != attname:
        for candidate in related._meta.concrete_fields:
            if candidate.attname == attname:
                target = candidate
                break
    return related, target


def _ident_family(field):
    kind = field.get_internal_type()
    if kind in _INTEGER_IDENTITY_TYPES:
        return 'integer'
    if kind in _TEXT_IDENTITY_TYPES:
        return 'text'
    if kind in _UUID_IDENTITY_TYPES:
        return 'uuid'
    raise TrustsConfigurationError(
        'Along identity field %s (%s) is not a V1 integer, text, or UUID '
        'identity.' % (field.attname, kind)
    )


def _concrete_fk(field):
    fk = getattr(field, 'field', None)
    if (
        fk is not None
        and getattr(fk, 'is_relation', False)
        and getattr(fk, 'concrete', False)
    ):
        return fk
    return field


def _resolve_along_edge(walk_model, edge_path):
    """Return S/C/E metadata for hops from ``walk_model`` along ``edge_path``."""
    n = len(edge_path)
    if n == 1:
        try:
            field = walk_model._meta.get_field(edge_path[0])
        except FieldDoesNotExist:
            raise TrustsConfigurationError(
                'along path %r refers to missing field %r on %s.'
                % (_path_text(edge_path), edge_path[0], walk_model._meta.label)
            )
        kind = _classify_field(field)
        related, target = _target_field(field, 'along', edge_path)
        if related is not walk_model:
            raise TrustsConfigurationError(
                'along edge %r must terminate on walk-site model %s, not %s.'
                % (
                    _path_text(edge_path),
                    walk_model._meta.label,
                    related._meta.label,
                )
            )
        if kind == 'single':
            return 'S', field.attname, None, None, None, target
        if kind == 'reverse_o2m':
            # Reverse PathInfo.target_fields is the related model's PK, not
            # the concrete self-FK's remote to_field. Identity comes from
            # the forward FK metadata; the reverse hop still proves the
            # edge is a self-relation on the walk-site.
            fk = _concrete_fk(field)
            dest, edge_target = _target_field(fk, 'along', edge_path)
            if dest is not walk_model:
                raise TrustsConfigurationError(
                    'along edge %r must terminate on walk-site model %s, not %s.'
                    % (
                        _path_text(edge_path),
                        walk_model._meta.label,
                        dest._meta.label,
                    )
                )
            return 'C', fk.attname, None, None, None, edge_target
        raise TrustsConfigurationError(
            'along edge %r is not a supported S/C/E hop.'
            % (_path_text(edge_path),)
        )
    if n == 2:
        try:
            reverse = walk_model._meta.get_field(edge_path[0])
        except FieldDoesNotExist:
            raise TrustsConfigurationError(
                'along path %r refers to missing field %r on %s.'
                % (_path_text(edge_path), edge_path[0], walk_model._meta.label)
            )
        if _classify_field(reverse) != 'reverse_o2m':
            raise TrustsConfigurationError(
                'along edge %r is not a supported S/C/E hop.'
                % (_path_text(edge_path),)
            )
        edge_model, _edge_pk = _target_field(
            reverse, 'along', edge_path[:1],
        )
        try:
            forward = edge_model._meta.get_field(edge_path[1])
        except FieldDoesNotExist:
            raise TrustsConfigurationError(
                'along path %r refers to missing field %r on %s.'
                % (
                    _path_text(edge_path), edge_path[1],
                    edge_model._meta.label,
                )
            )
        if _classify_field(forward) != 'single':
            raise TrustsConfigurationError(
                'along edge %r is not a supported S/C/E hop.'
                % (_path_text(edge_path),)
            )
        dest, parent_target = _target_field(forward, 'along', edge_path)
        if dest is not walk_model:
            raise TrustsConfigurationError(
                'along edge %r must terminate on walk-site model %s, not %s.'
                % (
                    _path_text(edge_path),
                    walk_model._meta.label,
                    dest._meta.label,
                )
            )
        child_fk = _concrete_fk(reverse)
        _child_related, child_target = _target_field(
            child_fk, 'along', edge_path[:1],
        )
        if child_target.attname != parent_target.attname:
            raise TrustsConfigurationError(
                'along edge %r mixes identity fields %r and %r.'
                % (
                    _path_text(edge_path),
                    child_target.attname,
                    parent_target.attname,
                )
            )
        return (
            'E',
            None,
            edge_model,
            forward.attname,
            child_fk.attname,
            parent_target,
        )
    raise TrustsConfigurationError(
        'along edge %r is not a supported S/C/E hop.'
        % (_path_text(edge_path),)
    )


def _re_resolve_suffix(walk_model, suffix_path, content_model):
    """Confirm stored suffix names compile from the walk-site model."""
    if not suffix_path:
        if walk_model is not content_model:
            raise TrustsConfigurationError(
                'along suffix path is empty but the content terminal %s '
                'is not the walk-site %s.'
                % (content_model._meta.label, walk_model._meta.label)
            )
        return
    current = walk_model
    for index, name in enumerate(suffix_path):
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist:
            raise TrustsConfigurationError(
                'along suffix path %r cannot be resolved from %s; '
                'missing field %r.'
                % (_path_text(suffix_path), walk_model._meta.label, name)
            )
        kind = _classify_field(field)
        if kind not in _SUFFIX_KINDS:
            raise TrustsConfigurationError(
                'along suffix path %r uses unsupported field %r on %s.'
                % (_path_text(suffix_path), name, current._meta.label)
            )
        related, _attname = _resolved_hop(field, 'along suffix', suffix_path)
        current = related
    if current is not content_model:
        raise TrustsConfigurationError(
            'along suffix path %r from %s terminates on %s, not %s.'
            % (
                _path_text(suffix_path),
                walk_model._meta.label,
                current._meta.label,
                content_model._meta.label,
            )
        )


def _suffix_rewrite_attname(walk_model, suffix_path, content_model, walk_ident):
    if len(suffix_path) != 1:
        return None
    try:
        field = walk_model._meta.get_field(suffix_path[0])
    except FieldDoesNotExist:
        return None
    if _classify_field(field) not in ('reverse_o2m', 'reverse_o2o'):
        return None
    fk = _concrete_fk(field)
    if fk.model._meta.concrete_model is not content_model:
        return None
    _related, target = _target_field(fk, 'along suffix', suffix_path)
    if target.attname != walk_ident:
        return None
    return fk.name


def _build_along_walk(root, content_path, content_model, along):
    along_ref = _require_ref(along.ref, 'along')
    if along_ref._root is not root:
        raise TrustsConfigurationError(
            'along ref must share the registration root %s; got %s.'
            % (root._meta.label, along_ref._root._meta.label)
        )
    bound = along.bound
    if isinstance(bound, bool) or not isinstance(bound, int):
        raise TrustsConfigurationError(
            'Along bound must be an integer in %s..%s.'
            % (_ALONG_BOUND_MIN, _ALONG_BOUND_MAX)
        )
    if bound < _ALONG_BOUND_MIN or bound > _ALONG_BOUND_MAX:
        raise TrustsConfigurationError(
            'Along bound must be an integer in %s..%s.'
            % (_ALONG_BOUND_MIN, _ALONG_BOUND_MAX)
        )
    walk_path = _common_prefix(tuple(along_ref._path), tuple(content_path))
    edge_path = tuple(along_ref._path[len(walk_path):])
    suffix_path = tuple(content_path[len(walk_path):])
    if not walk_path:
        raise TrustsConfigurationError(
            'along ref %r and content path %r do not share a walk-site prefix.'
            % (_path_text(along_ref._path), _path_text(content_path))
        )
    if not edge_path:
        raise TrustsConfigurationError(
            'along ref %r has no edge hop beyond the walk-site.'
            % (_path_text(along_ref._path),)
        )
    _walk_path, walk_model, walk_field, walk_ident = _resolve_path(
        root, walk_path, 'along', trailing_reverse=True,
    )
    last_walk_name = walk_path[-1]
    current = root
    for name in walk_path[:-1]:
        field = current._meta.get_field(name)
        current, _att = _resolved_hop(field, 'along', walk_path)
    grant_hop = current._meta.get_field(last_walk_name)
    _grant_related, grant_target = _target_field(grant_hop, 'along', walk_path)
    (
        shape, parent_attname, edge_model, edge_parent_attname,
        edge_child_attname, edge_target,
    ) = _resolve_along_edge(walk_model, edge_path)
    ident_fields = (grant_target, edge_target)
    attnames = {field.attname for field in ident_fields}
    if attnames != {walk_ident}:
        raise TrustsConfigurationError(
            'along identity fields must match across the grant walk hop '
            'and both edge ends; got %s.'
            % ', '.join(sorted(field.attname for field in ident_fields))
        )
    families = {_ident_family(field) for field in ident_fields}
    if len(families) != 1:
        raise TrustsConfigurationError(
            'along identity fields mix identity families %s.'
            % ', '.join(sorted(families))
        )
    ident_family = families.pop()
    _re_resolve_suffix(walk_model, suffix_path, content_model)
    rewrite_attname = _suffix_rewrite_attname(
        walk_model, suffix_path, content_model, walk_ident,
    )
    return AlongWalk(
        path=tuple(along_ref._path),
        bound=bound,
        shape=shape,
        walk_path=tuple(walk_path),
        walk_model=walk_model,
        walk_ident=walk_ident,
        walk_field=walk_field,
        suffix_path=suffix_path,
        suffix_field=_lookup_text(suffix_path) if suffix_path else '',
        ident_family=ident_family,
        parent_attname=parent_attname,
        edge_model=edge_model,
        edge_parent_attname=edge_parent_attname,
        edge_child_attname=edge_child_attname,
        rewrite_attname=rewrite_attname,
    )


def probe_along_capabilities(connection):
    """Execute a plain recursive CTE. Raises on failure."""
    with connection.cursor() as cursor:
        cursor.execute(
            'WITH RECURSIVE t(n) AS ('
            'SELECT 0 UNION ALL SELECT n + 1 FROM t WHERE n < 0'
            ') SELECT n FROM t'
        )
        cursor.fetchone()


@dataclass(frozen=True, slots=True)
class RegisteredRelation:
    """Immutable normalized record for one permission-bearing relation.

    ``*_field`` is the complete root-relative Django lookup
    (``'__'.join(path)``). ``*_target`` is the last hop's single
    comparison field (``attname``), taken from resolved path metadata.
    """

    root: type
    content_path: tuple
    content_model: type
    content_field: str
    content_target: str
    user_path: tuple
    user_model: type
    user_field: str
    user_target: str
    permission_path: tuple
    permission_model: type
    permission_field: str
    permission_target: str
    condition: object | None = None
    along: AlongWalk | None = None
    via_group: bool = False
    group_path: tuple = ()
    group_model: type | None = None
    group_field: str = ''
    group_target: str = ''


@dataclass(frozen=True, slots=True)
class RegisteredDelegation:
    """Immutable normalized bridge to a sponsor's ordinary authority.

    A delegation is not an ordinary grant and therefore stores no ordinary
    ``permission`` path. ``condition_permission_model`` is present only when
    the delegated condition refers to the requested permission.
    """

    root: type
    content_path: tuple
    content_model: type
    content_field: str
    content_target: str
    delegate_path: tuple
    delegate_model: type
    delegate_field: str
    delegate_target: str
    sponsor_path: tuple
    sponsor_model: type
    sponsor_field: str
    sponsor_target: str
    condition: object | None = None
    condition_permission_model: type | None = None
    condition_permission_target: str | None = None
    along: AlongWalk | None = None
    sponsor_rules: object | None = field(default=None, compare=False, repr=False)


def _same_terminal_bindings(existing, record):
    """True when two records share content/user/permission/along bindings."""
    return (
        existing.content_path == record.content_path
        and existing.content_model is record.content_model
        and existing.content_target == record.content_target
        and existing.user_path == record.user_path
        and existing.user_model is record.user_model
        and existing.user_target == record.user_target
        and existing.permission_path == record.permission_path
        and existing.permission_model is record.permission_model
        and existing.permission_target == record.permission_target
        and existing.along == record.along
        and existing.via_group == record.via_group
        and existing.group_path == record.group_path
    )


def _concrete_model(value):
    opts = getattr(value, '_meta', None)
    if opts is None:
        raise TrustsConfigurationError(
            'Expected a model class or instance, not %r.' % (value,)
        )
    return opts.concrete_model


def _content_model(content):
    if isinstance(content, QuerySet):
        return content.model._meta.concrete_model
    if _is_model_class(content):
        return content._meta.concrete_model
    if isinstance(content, Model):
        return content._meta.concrete_model
    raise TrustsConfigurationError(
        'content must be a model class, instance, or QuerySet, not %r.'
        % (content,)
    )


def _require_condition_arity(builder):
    """Reject 0-arg, 2+-required, and keyword-only-only before invoke."""
    try:
        signature = inspect.signature(builder)
    except (TypeError, ValueError):
        return
    try:
        signature.bind(_CONDITION_ARITY_PROBE)
    except TypeError as exc:
        raise TrustsConfigurationError(
            'condition builder must accept exactly one positional '
            'argument (the trust value): %s' % exc
        ) from exc


def _delegated_condition_arity(builder):
    """Return 1 or 2 without invoking a delegated condition builder."""
    try:
        signature = inspect.signature(builder)
    except (TypeError, ValueError):
        return 1
    if any(
        parameter.kind is inspect.Parameter.VAR_POSITIONAL
        for parameter in signature.parameters.values()
    ):
        raise TrustsConfigurationError(
            'delegated condition builder must accept one or two positional '
            'arguments, not *args.'
        )
    accepted = []
    for count in (1, 2, 3):
        try:
            signature.bind(*((_CONDITION_ARITY_PROBE,) * count))
        except TypeError:
            continue
        accepted.append(count)
    if 3 in accepted or not any(count in accepted for count in (1, 2)):
        raise TrustsConfigurationError(
            'delegated condition builder must accept one or two positional '
            'arguments (the relationship and optional requested permission).'
        )
    return 2 if 2 in accepted else 1


def _public_condition_path(proxy, token, role):
    if not isinstance(proxy, _ConditionProxy):
        raise TrustsConfigurationError(
            '%s must be a path rooted at the supplied trust value, '
            'not %r.' % (role, proxy)
        )
    if proxy._token is not token:
        raise TrustsConfigurationError(
            '%s used a path from another symbolic root.' % (role,)
        )
    if not proxy._path:
        raise TrustsConfigurationError(
            '%s returned an empty path.' % (role,)
        )
    return '__'.join(proxy._path)


def _flatten_public_all(*predicates):
    parts = []
    for predicate in predicates:
        if isinstance(predicate, All):
            parts.extend(predicate.predicates)
        else:
            parts.append(predicate)
    return All(*parts)


def _lower_public_condition(node, trust, token, permission_path):
    if isinstance(node, _ConditionAnd):
        return _flatten_public_all(
            _lower_public_condition(node.left, trust, token, permission_path),
            _lower_public_condition(node.right, trust, token, permission_path),
        )
    if isinstance(node, _ConditionEq):
        return Equal(
            _public_ref(
                trust,
                _public_condition_path(node.left, token, 'Equal left'),
                'Equal left',
            ),
            _public_ref(
                trust,
                _public_condition_path(node.right, token, 'Equal right'),
                'Equal right',
            ),
        )
    if isinstance(node, _ConditionIn):
        if permission_path is None:
            raise TrustsConfigurationError(
                'row-only delegated condition .contains() cannot bind the '
                'requested permission; accept a second argument and pass it '
                'as the member.'
            )
        member_path = _public_condition_path(
            node.member, token, 'condition .contains member',
        )
        permission_segments = _public_path_segments(
            permission_path, 'permission',
        )
        if tuple(member_path.split('__')) != permission_segments:
            raise TrustsConfigurationError(
                'condition .contains member must be the registered '
                'permission path %r, not %r.'
                % (permission_path, member_path)
            )
        return PermissionIn(
            _public_ref(
                trust,
                _public_condition_path(
                    node.collection, token, 'condition .contains collection',
                ),
                'permission_in',
            ),
        )
    if isinstance(node, _ConditionInquiryMatch):
        return _InquiryPermissionMatch(
            _public_ref(
                trust,
                _public_condition_path(
                    node.path, token, 'delegated inquiry permission path',
                ),
                'delegated inquiry permission',
            )
        )
    raise TrustsConfigurationError(
        'condition builder must return a boolean expression of path '
        'equality, collection.contains(member), or their conjunction, '
        'not %r.' % (node,)
    )


def _reject_public_condition_value(condition):
    """Public ``condition=`` is a callable, not a prebuilt IR node."""
    from trusts.plan.conditions import Expr

    if (
        condition is All
        or condition is Equal
        or condition is PermissionIn
        or condition is permission_in
    ):
        raise TypeError(
            'condition must be a symbolic callable, '
            'not a prebuilt All / Equal / permission_in value or other '
            'non-callable %r.' % (condition,)
        )
    if isinstance(condition, (All, Equal, PermissionIn, Expr, Ref, Q, str, bool)):
        raise TypeError(
            'condition must be a symbolic callable, '
            'not a prebuilt All / Equal / permission_in value or other '
            'non-callable %r.' % (condition,)
        )
    if not callable(condition):
        raise TypeError(
            'condition must be a symbolic callable, '
            'not %r.' % (condition,)
        )


def _normalize_public_condition(trust, condition, permission_path, *, token):
    """Invoke a public condition builder once and lower to private IR."""
    if condition is None:
        return None
    _reject_public_condition_value(condition)
    if inspect.iscoroutinefunction(condition) or inspect.isasyncgenfunction(
        condition,
    ):
        raise TrustsConfigurationError(
            'condition builder must return a boolean expression, not a '
            'coroutine or async generator.'
        )
    _require_condition_arity(condition)
    proxy = _ConditionProxy(trust, token=token)
    try:
        result = condition(proxy)
    except TrustsConfigurationError:
        raise
    except Exception as exc:
        raise TrustsConfigurationError(
            'condition builder failed: %s' % exc
        ) from exc
    if not isinstance(result, _CONDITION_EXPR_TYPES):
        raise TrustsConfigurationError(
            'condition builder must return a boolean expression of path '
            'equality, collection.contains(member), or their conjunction, '
            'not %r.' % (result,)
        )
    return _lower_public_condition(result, trust, token, permission_path)


def _normalize_delegated_condition(trust, condition, *, token):
    """Invoke a delegated condition builder once and lower to private IR."""
    if condition is None:
        return None
    _reject_public_condition_value(condition)
    if inspect.iscoroutinefunction(condition) or inspect.isasyncgenfunction(
        condition,
    ):
        raise TrustsConfigurationError(
            'condition builder must return a boolean expression, not a '
            'coroutine or async generator.'
        )
    arity = _delegated_condition_arity(condition)
    relationship = _ConditionProxy(trust, token=token)
    inquiry_permission = _InquiryPermissionProxy(token)
    try:
        if arity == 2:
            result = condition(relationship, inquiry_permission)
        else:
            result = condition(relationship)
    except TrustsConfigurationError:
        raise
    except Exception as exc:
        raise TrustsConfigurationError(
            'condition builder failed: %s' % exc
        ) from exc
    if not isinstance(result, _CONDITION_EXPR_TYPES):
        raise TrustsConfigurationError(
            'condition builder must return a boolean expression of path '
            'equality, collection.contains(permission), or their '
            'conjunction, not %r.' % (result,)
        )
    return _lower_public_condition(result, trust, token, None)


def _normalize_public_role(trust, value, role, *, token):
    """Normalize a public string or path builder to a Django ``__`` path."""
    if isinstance(value, Ref):
        raise TypeError(
            '%s must be a Django path string or a one-argument path '
            'builder, not a Ref.' % (role,)
        )
    if isinstance(value, str):
        return value
    if not callable(value):
        raise TrustsConfigurationError(
            '%s must be a Django path string or a one-argument path '
            'builder, not %r.' % (role, value)
        )
    builder = _PathBuilder(trust, token=token)
    try:
        result = value(builder)
    except TrustsConfigurationError:
        raise
    except Exception as exc:
        raise TrustsConfigurationError(
            '%s path builder failed: %s' % (role, exc)
        ) from exc
    if not isinstance(result, _PathBuilder):
        raise TrustsConfigurationError(
            '%s path builder must return a path rooted at the supplied '
            'trust value, not %r.' % (role, result)
        )
    if result._token is not token:
        raise TrustsConfigurationError(
            '%s path builder used a path from another symbolic root.'
            % (role,)
        )
    if not result._path:
        raise TrustsConfigurationError(
            '%s path builder returned an empty path.' % (role,)
        )
    return '__'.join(result._path)


def _public_path_segments(value, role, *, allow_empty=False):
    """Split a public Django ``__`` path. Reject before ``Ref`` / resolve."""
    if isinstance(value, Ref):
        raise TypeError(
            '%s must be a Django path string, not a Ref.' % (role,)
        )
    if not isinstance(value, str):
        raise TrustsConfigurationError(
            '%s must be a Django path string, not %r.' % (role, value)
        )
    if not value:
        if allow_empty:
            return ()
        raise TrustsConfigurationError(
            '%s path %r is not a valid Django __ relationship path.'
            % (role, value)
        )
    if (
        value.startswith('__')
        or value.endswith('__')
        or '.' in value
    ):
        raise TrustsConfigurationError(
            '%s path %r is not a valid Django __ relationship path.'
            % (role, value)
        )
    segments = value.split('__')
    if any(segment == '' for segment in segments):
        raise TrustsConfigurationError(
            '%s path %r is not a valid Django __ relationship path.'
            % (role, value)
        )
    return tuple(segments)


def _public_ref(root, value, role, *, allow_empty=False):
    return Ref(root, _public_path_segments(
        value, role, allow_empty=allow_empty,
    ))


def _bind_public_along(root, along):
    """Normalize ``(path, bound)`` to an internal ``Along``."""
    if along is None:
        return None
    if isinstance(along, Along):
        raise TypeError(
            'along must be a (path, bound) pair, not an Along instance.'
        )
    if isinstance(along, Ref):
        raise TypeError(
            'along must be a (path, bound) pair, not a Ref.'
        )
    if not isinstance(along, tuple) or len(along) != 2:
        raise TrustsConfigurationError(
            'along must be a (path, bound) pair, not %r.' % (along,)
        )
    path, bound = along
    return Along(_public_ref(root, path, 'along'), bound)

class TrustsRegistry(object):
    """Instantiable registry of permission-bearing relation declarations.

    Create a new instance per isolated context. There is no process-global
    singleton in this slice. ``register`` performs zero SQL. Projection
    methods compile one shared plan from stored records. One root may
    store several records when they terminate on different content
    models, or when the same bindings use a different closed condition.

        Frozen state is instance-owned. ``freeze()`` is idempotent.
        ``register`` and ``register_permission_condition`` on that exact
        frozen instance raise ``TrustsConfigurationError`` before
        validation, builder invoke, or mutation. Existing records,
        plans, compilers, and authorization reads stay usable.
    A standalone ``TrustsRegistry()`` never inspects Django readiness
    and never auto-freezes.
    """

    def __init__(self):
        # Stay lazy: importing this module must not load the condition IR.
        from trusts.plan.conditions import (
            ConditionRegistry,
            RegistryConditionLookup,
        )

        self._by_root = {}
        self._order = []
        self._delegations_by_root = {}
        self._delegation_order = []
        self._frozen = False
        self._condition_lookup = None
        self._user_conditions = None
        self._user_override = None
        self._rule_fragments = {}
        self._override_fragments = {}
        self.conditions = ConditionRegistry()
        self.set_condition_lookup(RegistryConditionLookup(self))

    @property
    def frozen(self):
        return self._frozen

    @property
    def condition_lookup(self):
        """Bound ``ConditionLookup``, or ``None`` after explicit unbind."""
        return self._condition_lookup

    def set_condition_lookup(self, lookup):
        """Bind a ``ConditionLookup`` on this instance (zero SQL).

        Construction already self-binds the private store adapter.
        Both ``record_for`` and ``compile_q`` must be callable. A missing
        method raises ``TrustsConfigurationError`` and does not bind
        (no partial bind). ``lookup is None`` clears the binding.
        Methods are not invoked at bind time.
        """
        if lookup is None:
            self._condition_lookup = None
            return
        record_for = getattr(lookup, 'record_for', None)
        compile_q = getattr(lookup, 'compile_q', None)
        if not callable(record_for) or not callable(compile_q):
            raise TrustsConfigurationError(
                'ConditionLookup must provide record_for and compile_q; '
                'no partial bind.'
            )
        self._condition_lookup = lookup

    def register_permission_condition(self, model, cond_code, condition):
        """Register a ``:cond_code`` condition on ``model`` for this instance.

        A callable is a registration-time builder. A frozen instance
        raises ``TrustsConfigurationError`` before the builder is
        invoked. A prebuilt ``Expr`` is rejected by the condition
        store with ``TypeError`` before mutation.
        """
        if self._frozen:
            raise TrustsConfigurationError(
                'Cannot register a permission condition on a frozen '
                'TrustsRegistry.'
            )
        return self.conditions.register_permission_condition(
            model, cond_code, condition,
        )

    def get_permission_condition_record(self, model, cond_code):
        """Return this instance's record for ``(model, cond_code)``, or ``None``."""
        return self.conditions.get_permission_condition_record(
            model, cond_code,
        )

    def iter_permission_conditions(self):
        """Yield ``(model, cond_code, record)`` registered on this instance."""
        return self.conditions.iter_permission_conditions()

    def compile_registered_condition_q(self, model, perm, user):
        """Compile a registered ``:condition`` to ``Q`` from this instance."""
        return self.conditions.compile_registered_condition_q(
            model, perm, user,
        )

    def evaluate_permission_condition(self, model, cond_code, user, perm, obj):
        """Evaluate a registered condition from this instance against ``obj``."""
        return self.conditions.evaluate_permission_condition(
            model, cond_code, user, perm, obj,
        )

    def user_conditions(self):
        """Effective user conditions.

        ``None`` store means the built-in ``is_active`` rule when the
        configured user model has that concrete boolean field, and no
        conditions otherwise. Compilation for a registered model uses
        that model's own fields.
        """
        if self._user_conditions is None:
            from django.contrib.auth import get_user_model

            return builtin_user_conditions(get_user_model())
        return tuple(self._user_conditions.values())

    def _stored_user_conditions(self):
        """``None`` when the registry still uses the built-in rule."""
        if self._user_conditions is None:
            return None
        return tuple(self._user_conditions.values())

    def _known_skip_names(self):
        return condition_names(
            self._stored_user_conditions(), self._user_override,
        )

    def _conditions_for_model(self, model):
        """Conditions compiled for ``model``.

        With no caller-set rules, the built-in ``is_active`` condition is
        included only when ``model`` has that concrete boolean field.
        A caller-set list is used as stored, including a replacement
        ``is_active`` condition. Every inquiry uses this same list.
        """
        stored = self._stored_user_conditions()
        if stored is not None:
            return stored
        return builtin_user_conditions(model)

    def _rule_fragment(self, model, *, role, path=''):
        """Registration-time ``(skip OR condition)`` for one model and role."""
        model = model._meta.concrete_model
        key = (model, role, path)
        try:
            return self._rule_fragments[key]
        except KeyError:
            compiled = compile_user_rules(
                model, path, self._conditions_for_model(model),
                role=role, values={},
            )
            self._rule_fragments[key] = compiled
            return compiled

    def _override_fragment(self, model):
        """Registration-time ``(NOT skip AND override)`` for the checked user."""
        model = model._meta.concrete_model
        try:
            return self._override_fragments[model]
        except KeyError:
            compiled = compile_override_q(
                model, '', self._user_override, {},
            )
            self._override_fragments[model] = compiled
            return compiled

    def _clear_compiled_rules(self):
        """Drop registration-time fragments after a successful rule edit."""
        self._rule_fragments.clear()
        self._override_fragments.clear()

    def _compiled_subject(self, records, delegations, user_model):
        if user_model is not None:
            return user_model
        models = {
            record.user_model._meta.concrete_model for record in records
        }
        models.update(
            record.delegate_model._meta.concrete_model
            for record in delegations
        )
        if len(models) == 1:
            return models.pop()
        return None

    def _open_for_rules(self, kind):
        if self._frozen:
            verb = (
                'set a user condition' if kind == 'condition'
                else 'set a user override'
            )
            raise TrustsConfigurationError(
                'Cannot %s on a frozen TrustsRegistry.' % verb
            )
        if self._order or self._delegation_order:
            raise TrustsConfigurationError(
                'Set user conditions and the user override before '
                'register() or register_delegation().'
            )

    def set_user_condition(self, name, expr, on='*'):
        """Set, replace, or remove one named user condition.

        Call this before ``register()`` or ``register_delegation()``.
        ``None`` removes that name. ``on`` is ``*``, ``user``, or ``sponsor``.
        The lambda is walked once and must use concrete boolean fields.
        """
        from django.contrib.auth import get_user_model

        self._open_for_rules('condition')
        validate_user_rule_name(name, kind='condition')
        target = normalize_on(on)
        if (
            expr is not None and self._user_override is not None
            and self._user_override.name == name
        ):
            raise TrustsConfigurationError(
                'User condition name %r collides with the user override.'
                % (name,)
            )
        created = self._user_conditions is None
        if created:
            self._user_conditions = {
                rule.name: rule
                for rule in builtin_user_conditions(get_user_model())
            }
        try:
            if expr is None:
                if name not in self._user_conditions:
                    raise TrustsConfigurationError(
                        'User condition %r is not registered.' % (name,)
                    )
                del self._user_conditions[name]
                self._clear_compiled_rules()
                return None
            rule = UserCondition(name, concrete_rule(expr, name), target)
        except TrustsConfigurationError:
            if created:
                self._user_conditions = None
            raise
        self._user_conditions[name] = rule
        self._clear_compiled_rules()
        return rule

    def _assert_rules_for_registration(self, *, user_model=None, sponsor_model=None):
        """Require each applicable rule's concrete booleans on these models."""
        pairs = []
        if user_model is not None:
            pairs.append((user_model, 'user'))
        if sponsor_model is not None:
            pairs.append((sponsor_model, 'sponsor'))
        for model, role in pairs:
            concrete = model._meta.concrete_model
            for rule in self._conditions_for_model(concrete):
                if not rule_applies(rule.on, role):
                    continue
                assert_concrete_booleans(concrete, rule.expr, rule.name)
        slot = self._user_override
        if slot is not None and user_model is not None:
            assert_concrete_booleans(
                user_model._meta.concrete_model, slot.expr, slot.name,
            )

    def set_user_override(self, name, expr, on='user'):
        """Store the one checked-user override, or clear it with ``None``.

        Call this before ``register()`` or ``register_delegation()``.
        ``on="sponsor"`` and ``on="*"`` raise. The name cannot match a
        registered condition.
        """
        self._open_for_rules('override')
        validate_user_rule_name(name, kind='override')
        normalize_override_on(on)
        if expr is not None and any(
            rule.name == name for rule in self.user_conditions()
        ):
            raise TrustsConfigurationError(
                'User override name %r collides with a user condition.'
                % (name,)
            )
        if expr is None:
            current = self._user_override
            if current is None or current.name != name:
                raise TrustsConfigurationError(
                    'User override %r is not the current override.' % (name,)
                )
            self._user_override = None
            self._clear_compiled_rules()
            return None
        self._user_override = UserCondition(
            name, concrete_rule(expr, name), 'user',
        )
        self._clear_compiled_rules()
        return self._user_override

    def freeze(self):
        """Seal relation and condition registration on this instance."""
        self._frozen = True

    @property
    def records(self):
        return tuple(self._order)

    @property
    def delegations(self):
        return tuple(self._delegation_order)

    def records_for_root(self, root):
        """Insertion-ordered records registered for ``root``.

        Raises ``TrustsConfigurationError`` when the root is absent.
        """
        try:
            return tuple(self._by_root[root])
        except KeyError:
            raise TrustsConfigurationError(
                'No registration for %r.' % (getattr(root, '__name__', root),)
            )

    def delegations_for_root(self, root):
        """Insertion-ordered delegated records registered for ``root``."""
        try:
            return tuple(self._delegations_by_root[root])
        except KeyError:
            raise TrustsConfigurationError(
                'No delegated registration for %r.'
                % (getattr(root, '__name__', root),)
            )

    def register_delegation(self, *, content, delegate, sponsor, condition=None,
                            along=None):
        """Register one non-granting delegation relationship.

        The three paths share one root. Delegate and sponsor are
        single-valued forward paths to the same persisted principal model.
        The condition is row-only or may contain a private symbolic match to
        the requested permission. Optional ``along`` is the same bounded
        walk as an ordinary registration: the delegation anchor reaches
        objects within that walk. Registration validates metadata only.
        """
        if self._frozen:
            raise TrustsConfigurationError(
                'Cannot register on a frozen TrustsRegistry.'
            )
        content_ref = _require_ref(content, 'content')
        delegate_ref = _require_ref(delegate, 'delegate')
        sponsor_ref = _require_ref(sponsor, 'sponsor')
        roots = (
            content_ref._root, delegate_ref._root, sponsor_ref._root,
        )
        if len(set(roots)) != 1:
            raise TrustsConfigurationError(
                'All refs in one delegated registration must share the same '
                'root model; got %s.'
                % ', '.join(root._meta.label for root in roots)
            )
        root = roots[0]
        content_path, content_model, content_field, content_target = _resolve_path(
            root, content_ref._path, 'content', trailing_reverse=True,
        )
        (
            delegate_path, delegate_model, delegate_field, delegate_target,
        ) = _resolve_forward_singles(root, delegate_ref._path, 'delegate')
        (
            sponsor_path, sponsor_model, sponsor_field, sponsor_target,
        ) = _resolve_forward_singles(root, sponsor_ref._path, 'sponsor')
        if (
            delegate_model is not sponsor_model
            or delegate_target != sponsor_target
        ):
            raise TrustsConfigurationError(
                'delegate and sponsor must resolve to the same principal '
                'model and comparison target; got %s.%s and %s.%s.'
                % (
                    delegate_model._meta.label, delegate_target,
                    sponsor_model._meta.label, sponsor_target,
                )
            )
        (
            condition, condition_permission_model,
            condition_permission_target,
        ) = _validate_delegated_condition(condition, root)
        if along is not None and not isinstance(along, Along):
            raise TrustsConfigurationError(
                'along must be an Along instance or None, not %r.' % (along,)
            )
        along_walk = None
        if along is not None:
            along_walk = _build_along_walk(
                root, content_path, content_model, along,
            )
        record = RegisteredDelegation(
            root=root,
            content_path=content_path,
            content_model=content_model,
            content_field=content_field,
            content_target=content_target,
            delegate_path=delegate_path,
            delegate_model=delegate_model,
            delegate_field=delegate_field,
            delegate_target=delegate_target,
            sponsor_path=sponsor_path,
            sponsor_model=sponsor_model,
            sponsor_field=sponsor_field,
            sponsor_target=sponsor_target,
            condition=condition,
            condition_permission_model=condition_permission_model,
            condition_permission_target=condition_permission_target,
            along=along_walk,
        )
        existing_rows = self._delegations_by_root.get(root)
        if existing_rows:
            if record in existing_rows:
                raise TrustsConfigurationError(
                    'Duplicate delegated registration for %s.'
                    % root._meta.label
                )
            for existing in existing_rows:
                if existing.content_model is record.content_model:
                    raise TrustsConfigurationError(
                        'Conflicting delegated registration for %s content '
                        'terminal %s: existing %r, new %r.'
                        % (
                            root._meta.label,
                            record.content_model._meta.label,
                            existing,
                            record,
                        )
                    )
        self._assert_rules_for_registration(
            user_model=delegate_model,
            sponsor_model=sponsor_model,
        )
        self._rule_fragment(delegate_model, role='user')
        self._override_fragment(delegate_model)
        record = replace(record, sponsor_rules=self._rule_fragment(
            sponsor_model, role='sponsor', path=sponsor_field,
        ))
        if existing_rows:
            existing_rows.append(record)
        else:
            self._delegations_by_root[root] = [record]
        self._delegation_order.append(record)
        return record

    def register(self, *, content, user, permission=None, group=None,
                 condition=None, along=None):
        """Register one permission-bearing relation from root-relative refs.

        ``permission`` and ``group`` are mutually exclusive. ``permission``
        is one direct single-valued hop, or zero or more forward
        single-valued hops followed by exactly one terminal many-to-many
        to ``auth.Permission``. ``group`` is a forward single-valued
        path that must end at ``auth.Group``; this method appends
        ``Group.permissions`` and stores that as the permission terminal.
        A ``permission=`` record stays ``via_group`` false.
        Supplying both, or neither, raises ``TrustsConfigurationError``.

        Exact duplicate normalized registration raises
        ``TrustsConfigurationError``. The same root plus the same content
        terminal with different content/user/permission/along bindings is
        a conflict and also raises. The same bindings with a *different*
        closed condition is an allowed alternative (the plan ORs complete
        records). The same root may register different content terminals.
        Both error outcomes leave stored records unchanged.

        Optional ``along`` is an ``Along`` that replaces equality at the
        walk-site with bounded reachability. Along validation uses
        ``_meta`` only (zero SQL) and runs after the frozen check.

        Optional ``condition`` is a closed predicate tree (``All``,
        ``Equal``, ``permission_in``) compiled as an AND overlay on the
        same root row. Validation uses ``_meta`` only (zero SQL).

        A frozen instance raises ``TrustsConfigurationError`` before
        validation or mutation. This method does not inspect Django's
        global ``apps.ready``.
        """
        if self._frozen:
            raise TrustsConfigurationError(
                'Cannot register on a frozen TrustsRegistry.'
            )
        _require_one_permission_source(permission, group)
        if along is not None and not isinstance(along, Along):
            raise TrustsConfigurationError(
                'along must be an Along instance or None, not %r.' % (along,)
            )

        content_ref = _require_ref(content, 'content')
        user_ref = _require_ref(user, 'user')
        group_ref = None
        permission_ref = None
        if group is not None:
            group_ref = _require_ref(group, 'group')
            roots = (content_ref._root, user_ref._root, group_ref._root)
        else:
            permission_ref = _require_ref(permission, 'permission')
            roots = (content_ref._root, user_ref._root, permission_ref._root)
        if len(set(roots)) != 1:
            raise TrustsConfigurationError(
                'All refs in one registration must share the same root model; '
                'got %s.' % ', '.join(root._meta.label for root in roots)
            )
        root = roots[0]

        content_path, content_model, content_field, content_target = _resolve_path(
            root, content_ref._path, 'content', trailing_reverse=True,
        )
        user_path, user_model, user_field, user_target = _resolve_path(
            root, user_ref._path, 'user', terminal_membership=True,
        )
        if group_ref is not None:
            (
                group_path, group_model, group_field, group_target,
            ) = _resolve_group_path(root, group_ref._path)
            (
                permission_path, permission_model, permission_field,
                permission_target,
            ) = _append_group_permissions(group_path, group_field)
            via_group = True
        else:
            permission_path, permission_model, permission_field, permission_target = (
                _resolve_permission_path(root, permission_ref._path)
            )
            group_path, group_model, group_field, group_target = (), None, '', ''
            via_group = False
        along_walk = None
        if along is not None:
            along_walk = _build_along_walk(
                root, content_path, content_model, along,
            )
        condition = _validate_condition(
            condition, root, permission_model,
            permission_target=permission_target,
        )

        record = RegisteredRelation(
            root=root,
            content_path=content_path,
            content_model=content_model,
            content_field=content_field,
            content_target=content_target,
            user_path=user_path,
            user_model=user_model,
            user_field=user_field,
            user_target=user_target,
            permission_path=permission_path,
            permission_model=permission_model,
            permission_field=permission_field,
            permission_target=permission_target,
            condition=condition,
            along=along_walk,
            via_group=via_group,
            group_path=group_path,
            group_model=group_model,
            group_field=group_field,
            group_target=group_target,
        )

        existing_rows = self._by_root.get(root)
        if existing_rows:
            for existing in existing_rows:
                if existing == record:
                    raise TrustsConfigurationError(
                        'Duplicate registration for %s.' % root._meta.label
                    )
                if existing.content_model is record.content_model:
                    if (
                        _same_terminal_bindings(existing, record)
                        and existing.condition != record.condition
                    ):
                        continue
                    raise TrustsConfigurationError(
                        'Conflicting registration for %s content terminal '
                        '%s: existing %r, new %r.'
                        % (
                            root._meta.label,
                            record.content_model._meta.label,
                            existing,
                            record,
                        )
                    )
        self._assert_rules_for_registration(user_model=user_model)
        self._rule_fragment(user_model, role='user')
        self._override_fragment(user_model)
        if existing_rows:
            existing_rows.append(record)
        else:
            self._by_root[root] = [record]
        self._order.append(record)
        return record

    def _register_public(
        self, *, trust, user=None, permission=None, content, group=None,
        delegate=None, sponsor=None, condition=None, along=None,
    ):
        """Public ``BackendHandle.register`` body, on the registry it stores.

        The handle forwards here so ``trusts.plan.handles`` does not import
        this module. Callers keep using ``BackendHandle.register``.
        """
        if getattr(self, 'frozen', False):
            raise TrustsConfigurationError(
                'Cannot register on a frozen TrustsRegistry.'
            )
        ordinary = user is not None or permission is not None or group is not None
        delegated = delegate is not None or sponsor is not None
        if ordinary and delegated:
            raise TrustsConfigurationError(
                'register accepts ordinary user=/permission=/group= or '
                'delegated delegate=/sponsor= arguments, not both modes.'
            )
        if delegated:
            if delegate is None or sponsor is None:
                raise TrustsConfigurationError(
                    'delegated register requires both delegate= and sponsor=.'
                )
            if user is not None or permission is not None or group is not None:
                raise TrustsConfigurationError(
                    'delegated register forbids user=, permission=, and group=.'
                )
        else:
            if user is None:
                raise TrustsConfigurationError(
                    'ordinary register requires user=.'
                )
            _require_one_permission_source(permission, group)
        if isinstance(trust, Ref):
            raise TypeError(
                'register trust must be a Django model class, '
                'not a Ref.'
            )
        if not _is_model_class(trust):
            raise TrustsConfigurationError(
                'register trust must be a Django model class, '
                'not %r.' % (trust,)
            )
        token = object()
        content_path = _normalize_public_role(
            trust, content, 'content', token=token,
        )
        if delegated:
            delegate_path = _normalize_public_role(
                trust, delegate, 'delegate', token=token,
            )
            sponsor_path = _normalize_public_role(
                trust, sponsor, 'sponsor', token=token,
            )
            return self.register_delegation(
                content=_public_ref(trust, content_path, 'content'),
                delegate=_public_ref(trust, delegate_path, 'delegate'),
                sponsor=_public_ref(trust, sponsor_path, 'sponsor'),
                condition=_normalize_delegated_condition(
                    trust, condition, token=token,
                ),
                along=_bind_public_along(trust, along),
            )
        user_path = _normalize_public_role(trust, user, 'user', token=token)
        if group is not None:
            group_text = _normalize_public_role(
                trust, group, 'group', token=token,
            )
            group_segments = _public_path_segments(group_text, 'group')
            _group_path, _group_model, group_field, _group_target = (
                _resolve_group_path(trust, group_segments)
            )
            _perm_path, _perm_model, permission_text, _perm_target = (
                _append_group_permissions(group_segments, group_field)
            )
            return self.register(
                content=_public_ref(trust, content_path, 'content'),
                user=_public_ref(trust, user_path, 'user'),
                group=_public_ref(trust, group_text, 'group'),
                condition=_normalize_public_condition(
                    trust, condition, permission_text, token=token,
                ),
                along=_bind_public_along(trust, along),
            )
        permission_path = _normalize_public_role(
            trust, permission, 'permission', token=token,
        )
        return self.register(
            content=_public_ref(trust, content_path, 'content'),
            user=_public_ref(trust, user_path, 'user'),
            permission=_public_ref(trust, permission_path, 'permission'),
            condition=_normalize_public_condition(
                trust, condition, permission_path, token=token,
            ),
            along=_bind_public_along(trust, along),
        )

    def _records_for(self, content_model, user_model=None, permission_model=None):
        chosen = []
        for record in self._order:
            if record.content_model is not content_model:
                continue
            if user_model is not None and record.user_model is not user_model:
                continue
            if (
                permission_model is not None
                and record.permission_model is not permission_model
            ):
                continue
            chosen.append(record)
        return tuple(chosen)

    def _delegations_for(self, content_model, delegate_model=None):
        chosen = []
        for record in self._delegation_order:
            if record.content_model is not content_model:
                continue
            if (
                delegate_model is not None
                and record.delegate_model is not delegate_model
            ):
                continue
            chosen.append(record)
        return tuple(chosen)

    def plan_for(self, content, *, user=None, permission=None):
        """Build the common relation plan for these terminals.

        ``content`` may be a model class, instance, or ``QuerySet``.
        Optional ``user`` / ``permission`` instances keep only registrations
        whose inferred terminals match those models. Construction is lazy.
        """
        return assemble_frozen(
            self,
            compiler=None,
            handles=(),
            relation_plan=RelationPlan,
            bind_record_qs=_bind_record_qs,
            grant_reach=GrantReach,
            content_model=_content_model,
            concrete_model=_concrete_model,
            require_instance=_require_instance,
            candidate_model=_candidate_model,
        ).plan_for(content, user=user, permission=permission)

    def permissions_for(self, user, content, **skip_flags):
        """Distinct permission rows granted to ``user`` on ``content``."""
        user = _require_instance(user, 'user')
        content = _require_instance(content, 'content')
        inquiry = bind_checked_user(
            user, skip_flags=skip_flags, registry=self)
        plan = self.plan_for(content, user=user)
        if inquiry.denied:
            if not plan.records or plan.permission_model is None:
                return ()
            return plan.permission_model._default_manager.none()
        skipped = inquiry.values
        return plan.permissions(
            user, content,
            skipped=skipped,
        )

    def has_permission(self, user, content, permission, **skip_flags):
        """Whether ``permission`` exists in the common plan for this pair."""
        user = _require_instance(user, 'user')
        content = _require_instance(content, 'content')
        permission = _require_instance(permission, 'permission')
        inquiry = bind_checked_user(
            user, skip_flags=skip_flags, registry=self)
        plan = self.plan_for(
            content, user=user, permission=permission,
        )
        if inquiry.denied:
            return False
        skipped = inquiry.values
        return plan.has_permission(
            user, content, permission,
            skipped=skipped,
        )

    def filter_authorized(self, queryset, user, permission, **skip_flags):
        """Lazy queryset of rows ``user`` holds ``permission`` on.

        Consumes ``RelationPlan.content_exists`` through ``filter_content``.
        """
        if not isinstance(queryset, QuerySet):
            raise TrustsConfigurationError(
                'filter_authorized requires a QuerySet, not %r.' % (queryset,)
            )
        user = _require_instance(user, 'user')
        permission = _require_instance(permission, 'permission')
        inquiry = bind_checked_user(
            user, skip_flags=skip_flags, registry=self)
        plan = self.plan_for(
            queryset, user=user, permission=permission,
        )
        if inquiry.denied:
            return queryset.none()
        skipped = inquiry.values
        return plan.filter_content(
            queryset, user, permission,
            skipped=skipped,
        )
