"""Registration marshaling and the builder-half registry.

``TrustsRegistry`` collects ``register`` and ``set_*`` calls and stores
lowered rows. Its ``build_*`` methods return the lowered shapes without
storing them; the ``register*`` methods own duplicate and
rule checks and append those shapes. ``build_registry`` builds the
query-time ``Registry`` from stored values. ``trusts.core`` re-exports
``TrustsRegistry``. This module does not import ``trusts.core``.
"""

__all__ = []

import inspect
from collections.abc import Callable
from typing import TypeVar

from dataclasses import dataclass, field, replace

from django.core.exceptions import FieldDoesNotExist
from django.db.models import F, Model, Q
from django.db.models.query import QuerySet

from trusts.commons import (
    _auth_group_and_permission,
    _concrete_model,
    _content_model,
    _lookup_text,
    _path_text,
    _require_instance,
    _resolved_hop,
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
from trusts.compile.resolution import (
    _SUFFIX_KINDS,
    _append_group_permissions,
    _classify_field,
    _require_one_permission_source,
    _resolve_forward_singles,
    _resolve_group_path,
    _resolve_path,
    _resolve_permission_in_path,
    _resolve_permission_path,
)
from trusts.errors import TrustsConfigurationError

T = TypeVar('T', bound=Model)
from trusts.plan.registry import Registry
from trusts.plan.relations import PlanQueryCompiler, bind_checked_user
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


@dataclass(frozen=True, slots=True)
class PublicRegistration:
    """Normalized public registration, before it is stored.

    ``build_public_registration`` returns this shape: root-relative refs
    for exactly one mode (ordinary ``user`` plus ``permission`` or
    ``group``, or delegated ``delegate`` plus ``sponsor``), the already
    lowered ``condition``, and the bound ``along``. The unused mode's
    refs are ``None``. Storing it is ``_register_public``'s job, via
    ``register`` or ``register_delegation``.
    """

    trust: type
    content: object
    user: object | None = None
    permission: object | None = None
    group: object | None = None
    delegate: object | None = None
    sponsor: object | None = None
    condition: object | None = None
    along: object | None = None


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

class _RecordAdapter(object):
    """Visitor ``Recorder.play`` drives. Forwards to this factory's public API."""

    def __init__(self, factory):
        self.factory = factory

    def register_principal(self, **kwargs):
        return self.factory.register(**kwargs)

    def register_delegate(self, **kwargs):
        return self.factory.register_delegation(**kwargs)

    def add_named_filter(self, model, code, predicate):
        return self.factory.register_permission_condition(model, code, predicate)

    def set_user_condition(self, name, expr, on='*'):
        return self.factory.set_user_condition(name, expr, on=on)

    def set_user_override(self, name, expr, on='user'):
        return self.factory.set_user_override(name, expr, on=on)


class RegistryFactory(object):
    """Instantiable registry of permission-bearing relation declarations.

    Create a new instance per isolated context. There is no process-global
    singleton in this slice. ``register`` performs zero SQL. Projection
    methods compile one shared plan from stored records. One root may
    store several records when they terminate on different content
    models, or when the same bindings use a different closed condition.

        Registration stays open for the life of the instance:
        ``build_registry()`` builds a fresh ``Registry`` from the
        current records on each call, so registering after a build
        takes effect on the next build. A standalone
        ``TrustsRegistry()`` never inspects Django readiness.
    """

    def __init__(self, *, compiler=None, path='', family='relationship'):
        # Stay lazy: importing this module must not load the condition IR.
        from trusts.plan.conditions import (
            ConditionRegistry,
            RegistryConditionLookup,
        )

        self._by_root = {}
        self._order = []
        self._delegations_by_root = {}
        self._delegation_order = []
        self._condition_lookup = None
        self._user_conditions = None
        self._user_override = None
        self._rule_fragments = {}
        self._override_fragments = {}
        self.conditions = ConditionRegistry()
        self.set_condition_lookup(RegistryConditionLookup(self))
        self._explicit_compiler = compiler is not None
        self._compiler = compiler if self._explicit_compiler else PlanQueryCompiler()
        self.path = path
        self.family = family

    @property
    def compiler(self):
        """Compiler handed to every registry this factory builds."""
        return self._compiler

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

    def get_record_adapter(self):
        """Adapter ``Recorder.play`` calls. Methods forward to this factory."""
        return _RecordAdapter(self)

    def register_permission_condition(self, model, cond_code, condition):
        """Register a ``:cond_code`` condition on ``model`` for this instance.

        A callable is a registration-time builder, invoked once
        here. A prebuilt ``Expr`` is rejected by the condition
        store with ``TypeError`` before mutation.
        """
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

    def build_delegation(self, *, content, delegate, sponsor, condition=None,
                         along=None):
        """Build one ``RegisteredDelegation`` without storing it.

        Pure shape-building half of ``register_delegation``: same ref,
        path, condition, and ``along`` validation and errors, but no
        duplicate check, no user-rule assertion or sponsor
        fragment (``sponsor_rules`` stays ``None``), and no append.
        ``register_delegation`` owns those steps and appends the shape.
        """
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
        return RegisteredDelegation(
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
        record = self.build_delegation(
            content=content, delegate=delegate, sponsor=sponsor,
            condition=condition, along=along,
        )
        root = record.root
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
            user_model=record.delegate_model,
            sponsor_model=record.sponsor_model,
        )
        self._rule_fragment(record.delegate_model, role='user')
        self._override_fragment(record.delegate_model)
        record = replace(record, sponsor_rules=self._rule_fragment(
            record.sponsor_model, role='sponsor', path=record.sponsor_field,
        ))
        if existing_rows:
            existing_rows.append(record)
        else:
            self._delegations_by_root[root] = [record]
        self._delegation_order.append(record)
        return record

    def build_relation(self, *, content, user, permission=None, group=None,
                       condition=None, along=None):
        """Build one ``RegisteredRelation`` without storing it.

        Pure shape-building half of ``register``: same permission-source,
        ref, path, condition, and ``along`` validation and errors, but no
        duplicate/conflict check, no user-rule assertion or
        fragment compilation, and no append. ``register`` owns those
        steps and appends the returned shape.
        """
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

        return RegisteredRelation(
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
        ``_meta`` only (zero SQL).

        Optional ``condition`` is a closed predicate tree (``All``,
        ``Equal``, ``permission_in``) compiled as an AND overlay on the
        same root row. Validation uses ``_meta`` only (zero SQL).

        This method does not inspect Django's global ``apps.ready``.
        """
        record = self.build_relation(
            content=content, user=user, permission=permission, group=group,
            condition=condition, along=along,
        )
        root = record.root

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
        self._assert_rules_for_registration(user_model=record.user_model)
        self._rule_fragment(record.user_model, role='user')
        self._override_fragment(record.user_model)
        if existing_rows:
            existing_rows.append(record)
        else:
            self._by_root[root] = [record]
        self._order.append(record)
        return record

    def build_public_registration(
        self, *, trust, user=None, permission=None, content, group=None,
        delegate=None, sponsor=None, condition=None, along=None,
    ):
        """Build a normalized ``PublicRegistration`` without storing it.

        Shape-building half of ``_register_public``: same mode, trust,
        path-builder, condition, and ``along`` validation and errors, in
        the same order, but no append. Path and
        condition builders are invoked exactly once, here; the returned
        shape carries only refs, lowered condition IR, and ``Along``.
        ``_register_public`` stores the shape
        via ``register`` or ``register_delegation``.
        """
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
            return PublicRegistration(
                trust=trust,
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
            return PublicRegistration(
                trust=trust,
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
        return PublicRegistration(
            trust=trust,
            content=_public_ref(trust, content_path, 'content'),
            user=_public_ref(trust, user_path, 'user'),
            permission=_public_ref(trust, permission_path, 'permission'),
            condition=_normalize_public_condition(
                trust, condition, permission_path, token=token,
            ),
            along=_bind_public_along(trust, along),
        )

    def register_public(
        self, *,
        trust: type[T],
        user: str | Callable[[T], object] | None = None,
        permission: str | Callable[[T], object] | None = None,
        content: str | Callable[[T], object],
        group: str | Callable[[T], object] | None = None,
        delegate: str | Callable[[T], object] | None = None,
        sponsor: str | Callable[[T], object] | None = None,
        condition: (
            Callable[[T], object] | Callable[[T, object], object] | None
        ) = None,
        along=None,
    ) -> RegisteredRelation | RegisteredDelegation:
        shape = self.build_public_registration(
            trust=trust, user=user, permission=permission, content=content,
            group=group, delegate=delegate, sponsor=sponsor,
            condition=condition, along=along,
        )
        if shape.delegate is not None:
            return self.register_delegation(
                content=shape.content,
                delegate=shape.delegate,
                sponsor=shape.sponsor,
                condition=shape.condition,
                along=shape.along,
            )
        if shape.group is not None:
            return self.register(
                content=shape.content,
                user=shape.user,
                group=shape.group,
                condition=shape.condition,
                along=shape.along,
            )
        return self.register(
            content=shape.content,
            user=shape.user,
            permission=shape.permission,
            condition=shape.condition,
            along=shape.along,
        )

    _register_public = register_public

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

    def build_registry(self):
        """Build a query-time ``Registry`` from stored values.

        Records, delegations, the shared condition store, stored user
        conditions, the user override, and the bound condition lookup
        are passed as data, all at once. No builders are injected.
        """
        return Registry(
            records=self.records,
            delegations=self.delegations,
            conditions=self.conditions,
            user_conditions=self._stored_user_conditions(),
            user_override=self._user_override,
            condition_lookup=self._condition_lookup,
            compiler=self._compiler if self._explicit_compiler else None,
            path=self.path or '',
            family=self.family,
        )

    def plan_for(self, content, *, user=None, permission=None):
        """Build the common relation plan for these terminals.

        ``content`` may be a model class, instance, or ``QuerySet``.
        Optional ``user`` / ``permission`` instances keep only registrations
        whose inferred terminals match those models. Construction is lazy.
        """
        return self.build_registry().plan_for(
            content, user=user, permission=permission,
        )

    def permissions_for(self, user, content, **skip_flags):
        """Distinct permission rows granted to ``user`` on ``content``.

        Delegates to the built registry.
        """
        return self.build_registry().permissions_for(
            user, content, **skip_flags,
        )

    def has_permission(self, user, content, permission, **skip_flags):
        """Whether ``permission`` is granted to ``user`` on ``content``."""
        return self.build_registry().has_permission(
            user, content, permission, **skip_flags,
        )

    def filter_authorized(self, queryset, user, permission, **skip_flags):
        """Lazy queryset of rows ``user`` holds ``permission`` on."""
        return self.build_registry().filter_authorized(
            queryset, user, permission, **skip_flags,
        )
