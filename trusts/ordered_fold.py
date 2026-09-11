"""Closed OrderedFold strategy types, validation, and PostgreSQL renderer.

Public names are re-exported from ``trusts.core``. Consumers import them
from ``trusts.core`` only. This module is not a second registration API.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from django.contrib.auth import get_user_model
from django.core.exceptions import FieldDoesNotExist
from django.db.models import BooleanField
from django.db.models.base import ModelBase
from django.db.models.expressions import Expression


_ACTION_RE = re.compile(r'^[A-Za-z][A-Za-z0-9]*$')

_CHAR_TYPES = frozenset(('CharField', 'SlugField', 'TextField'))
_INTEGER_TYPES = frozenset((
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
_POLARITY_TYPES = _INTEGER_TYPES | frozenset(('BooleanField',)) | _CHAR_TYPES

_MASK_RANGES = {
    'SmallIntegerField': (1, 32767),
    'PositiveSmallIntegerField': (1, 32767),
    'SmallAutoField': (1, 32767),
    'IntegerField': (1, 2147483647),
    'AutoField': (1, 2147483647),
    'PositiveIntegerField': (1, 2147483647),
    'BigIntegerField': (1, (1 << 63) - 1),
    'BigAutoField': (1, (1 << 63) - 1),
    'PositiveBigIntegerField': (1, (1 << 63) - 1),
}


def _is_model_class(value):
    return isinstance(value, ModelBase)


@dataclass(frozen=True)
class MaskEntry:
    """One public permission identity mapped to one remaining-bits seed."""

    action: str
    mask: int


@dataclass(frozen=True)
class PermissionMaskDomain:
    """Closed OrderedFold domain. One per OrderedFold plan. AnyPath has none."""

    permission_model: type
    entries: tuple

    def __init__(self, permission_model, entries):
        object.__setattr__(self, 'permission_model', permission_model)
        object.__setattr__(self, 'entries', tuple(entries))


@dataclass(frozen=True)
class PolarityMap:
    """Closed allow/deny constants for one source polarity field."""

    field: object
    allow_value: object
    deny_value: object

    def __init__(self, field, *, allow_value, deny_value):
        object.__setattr__(self, 'field', field)
        object.__setattr__(self, 'allow_value', allow_value)
        object.__setattr__(self, 'deny_value', deny_value)


@dataclass(frozen=True)
class FlatToken:
    """Requester → identity set. Flat. Not Along. Not nested groups."""

    principal: object
    principal_user: object
    principal_identity: object
    member: object | None = None
    member_identity: object | None = None
    member_group: object | None = None


@dataclass(frozen=True)
class OrderedFold:
    """Closed typed remaining-bits strategy for one content terminal."""

    content: object
    descriptor: object
    source: object
    source_descriptor: object
    order: object
    polarity: object
    mask: object
    trustee: object
    token: object
    domain: object


@dataclass(frozen=True, slots=True)
class _Hop:
    from_model: type
    name: str
    attname: str
    to_model: type
    target: str


@dataclass(frozen=True, slots=True)
class RegisteredStrategy:
    """Immutable compiled OrderedFold metadata. Renderer input only."""

    content_model: type
    permission_model: type
    user_model: type
    source_model: type
    policy_set_model: type
    policy_set_target: str
    content_desc_path: tuple
    content_desc_attname: str
    content_desc_hops: tuple
    source_desc_hops: tuple
    source_desc_attname: str
    order_attname: str
    polarity_attname: str
    allow_value: object
    deny_value: object
    mask_attname: str
    mask_internal_type: str
    trustee_hops: tuple
    trustee_attname: str
    identity_model: type
    identity_attname: str
    principal_model: type
    principal_user_hops: tuple
    principal_user_attname: str
    user_bind_attname: str
    principal_identity_hops: tuple
    principal_identity_attname: str
    principal_is_user: bool
    member_model: type | None
    member_identity_hops: tuple
    member_group_hops: tuple
    mask_rows: tuple
    has_content_type: bool


def ordered_fold_connection_supported(connection):
    """True when ``connection.vendor`` is PostgreSQL (no SQL)."""
    return getattr(connection, 'vendor', None) == 'postgresql'


def _require_postgresql_fold_renderer(connection):
    from trusts.core import TrustsConfigurationError

    if ordered_fold_connection_supported(connection):
        return
    engine = (getattr(connection, 'settings_dict', None) or {}).get('ENGINE')
    raise TrustsConfigurationError(
        'OrderedFold remaining-bits rendering requires PostgreSQL; '
        'got ENGINE=%r vendor=%r alias=%r.'
        % (
            engine,
            getattr(connection, 'vendor', None),
            getattr(connection, 'alias', None),
        )
    )


def _require_ref(value, role):
    from trusts.core import Ref, TrustsConfigurationError

    if not isinstance(value, Ref):
        raise TrustsConfigurationError(
            '%s must be a root-relative Ref, not %r.' % (role, value)
        )
    return value


def _require_same_root(ref, root, role):
    from trusts.core import TrustsConfigurationError

    ref = _require_ref(ref, role)
    if ref._root is not root:
        raise TrustsConfigurationError(
            '%s must share the registration root %s; got %s.'
            % (role, root._meta.label, ref._root._meta.label)
        )
    return ref


def _require_empty_ref(ref, role):
    from trusts.core import TrustsConfigurationError

    if ref._path:
        raise TrustsConfigurationError(
            '%s must be an empty-path Ref(%s), not %r.'
            % (role, ref._root.__name__, ref)
        )
    return ref


def _path_text(path):
    return '.'.join(path)


def _hops_for_path(root, path, role, *, require_nonnull=True):
    from trusts.core import (
        TrustsConfigurationError,
        _classify_field,
        _resolve_forward_singles,
        _resolved_hop,
    )

    _resolve_forward_singles(root, path, role)
    hops = []
    current = root
    for name in path:
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist:
            raise TrustsConfigurationError(
                '%s path %r refers to missing field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if require_nonnull and getattr(field, 'null', False):
            raise TrustsConfigurationError(
                '%s path %r includes nullable field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )
        if _classify_field(field) != 'single':
            raise TrustsConfigurationError(
                '%s path %r uses unsupported field %r on %s.'
                % (role, _path_text(path), name, current._meta.label)
            )
        related, target = _resolved_hop(field, role, path)
        hops.append(_Hop(
            from_model=current._meta.concrete_model,
            name=name,
            attname=field.attname,
            to_model=related,
            target=target,
        ))
        current = related
    return tuple(hops)


def _resolve_source_scalar(root, ref, role, *, families, allow_null=False):
    from trusts.core import TrustsConfigurationError, _classify_field

    ref = _require_same_root(ref, root, role)
    if len(ref._path) != 1:
        raise TrustsConfigurationError(
            '%s must be a scalar field on %s.' % (role, root._meta.label)
        )
    name = ref._path[0]
    try:
        field = root._meta.get_field(name)
    except FieldDoesNotExist:
        raise TrustsConfigurationError(
            '%s path %r refers to missing field %r on %s.'
            % (role, name, name, root._meta.label)
        )
    if _classify_field(field) != 'scalar':
        raise TrustsConfigurationError(
            '%s path %r is not a scalar field on %s.'
            % (role, name, root._meta.label)
        )
    if not allow_null and getattr(field, 'null', False):
        raise TrustsConfigurationError(
            '%s field %s.%s must be non-null.'
            % (role, root._meta.label, name)
        )
    internal = field.get_internal_type()
    if internal not in families:
        raise TrustsConfigurationError(
            '%s field %s.%s has unsupported type %s.'
            % (role, root._meta.label, name, internal)
        )
    return field


def _identity_key_message(left_model, left_att, right_model, right_att):
    from trusts.core import TrustsConfigurationError

    raise TrustsConfigurationError(
        'Token paths must share one resolved comparison field; '
        'got %s.%s and %s.%s.'
        % (
            left_model._meta.label, left_att,
            right_model._meta.label, right_att,
        )
    )


def _bind_identity(ref, role, identity_model, identity_attname):
    from trusts.core import TrustsConfigurationError

    ref = _require_ref(ref, role)
    if not ref._path:
        if ref._root._meta.concrete_model is not identity_model:
            raise TrustsConfigurationError(
                '%s empty-path identity must be %s; got %s.'
                % (role, identity_model._meta.label, ref._root._meta.label)
            )
        try:
            ref._root._meta.get_field(identity_attname)
        except FieldDoesNotExist:
            raise TrustsConfigurationError(
                '%s empty-path identity %s has no field %r.'
                % (role, ref._root._meta.label, identity_attname)
            )
        return (), identity_attname
    hops = _hops_for_path(ref._root, ref._path, role, require_nonnull=True)
    last = hops[-1]
    if last.to_model is not identity_model or last.target != identity_attname:
        _identity_key_message(
            identity_model, identity_attname, last.to_model, last.target,
        )
    return hops, last.attname


def _compatible_polarity(field, value, role):
    from trusts.core import TrustsConfigurationError

    if value is None:
        raise TrustsConfigurationError(
            'Polarity %s must not be None.' % role
        )
    internal = field.get_internal_type()
    if internal == 'BooleanField':
        if type(value) is not bool:
            raise TrustsConfigurationError(
                'Polarity %s must be bool for BooleanField, not %r.'
                % (role, value)
            )
        return
    if internal in _INTEGER_TYPES:
        if type(value) is bool or not isinstance(value, int):
            raise TrustsConfigurationError(
                'Polarity %s must be int (not bool) for %s, not %r.'
                % (role, internal, value)
            )
        return
    if internal in _CHAR_TYPES:
        if not isinstance(value, str):
            raise TrustsConfigurationError(
                'Polarity %s must be str for %s, not %r.'
                % (role, internal, value)
            )
        return
    raise TrustsConfigurationError(
        'Polarity field type %s is not supported.' % internal
    )


def _validate_domain(domain, content_model, mask_field):
    from trusts.core import TrustsConfigurationError, _classify_field

    if not isinstance(domain, PermissionMaskDomain):
        raise TrustsConfigurationError(
            'domain must be a PermissionMaskDomain, not %r.' % (domain,)
        )
    permission_model = domain.permission_model
    if not _is_model_class(permission_model):
        raise TrustsConfigurationError(
            'PermissionMaskDomain.permission_model must be a Django model '
            'class, not %r.' % (permission_model,)
        )
    try:
        codename = permission_model._meta.get_field('codename')
    except FieldDoesNotExist:
        raise TrustsConfigurationError(
            'Permission model %s must expose a scalar codename field.'
            % permission_model._meta.label
        )
    if _classify_field(codename) != 'scalar':
        raise TrustsConfigurationError(
            'Permission model %s.codename must be a scalar char-like field.'
            % permission_model._meta.label
        )
    if codename.get_internal_type() not in _CHAR_TYPES:
        raise TrustsConfigurationError(
            'Permission model %s.codename must be CharField, SlugField, '
            'or TextField.' % permission_model._meta.label
        )
    has_content_type = False
    try:
        ct = permission_model._meta.get_field('content_type')
    except FieldDoesNotExist:
        ct = None
    if ct is not None:
        if _classify_field(ct) != 'single':
            raise TrustsConfigurationError(
                'Permission model %s.content_type must be a single-valued '
                'foreign key.' % permission_model._meta.label
            )
        has_content_type = True
    entries = domain.entries
    if not entries:
        raise TrustsConfigurationError(
            'PermissionMaskDomain.entries must be non-empty.'
        )
    seen = set()
    mask_rows = []
    mask_type = mask_field.get_internal_type()
    low, high = _MASK_RANGES[mask_type]
    app_label = content_model._meta.app_label.lower()
    model_name = content_model._meta.model_name
    for entry in entries:
        if not isinstance(entry, MaskEntry):
            raise TrustsConfigurationError(
                'PermissionMaskDomain.entries must contain MaskEntry '
                'instances, not %r.' % (entry,)
            )
        if not isinstance(entry.action, str) or not _ACTION_RE.fullmatch(entry.action):
            raise TrustsConfigurationError(
                'MaskEntry.action %r is not a valid Django action fragment.'
                % (entry.action,)
            )
        if entry.action in seen:
            raise TrustsConfigurationError(
                'PermissionMaskDomain actions must be unique; got '
                'duplicate %r.' % (entry.action,)
            )
        seen.add(entry.action)
        if type(entry.mask) is bool or not isinstance(entry.mask, int):
            raise TrustsConfigurationError(
                'MaskEntry.mask must be a non-boolean int, not %r.'
                % (entry.mask,)
            )
        if entry.mask < low or entry.mask > high:
            raise TrustsConfigurationError(
                'MaskEntry.mask %s does not fit %s range %s..%s.'
                % (entry.mask, mask_type, low, high)
            )
        mask_rows.append((
            app_label,
            '%s_%s' % (entry.action, model_name),
            entry.mask,
        ))
    return tuple(mask_rows), has_content_type, permission_model


def validate_ordered_fold(strategy):
    """Zero-SQL ``_meta`` validation. Returns ``RegisteredStrategy``."""
    from trusts.core import TrustsConfigurationError

    if not isinstance(strategy, OrderedFold):
        raise TrustsConfigurationError(
            'register_strategy requires OrderedFold, not %r.' % (strategy,)
        )
    if not isinstance(strategy.token, FlatToken):
        raise TrustsConfigurationError(
            'token must be a FlatToken, not %r.' % (strategy.token,)
        )
    if not isinstance(strategy.polarity, PolarityMap):
        raise TrustsConfigurationError(
            'polarity must be a PolarityMap, not %r.' % (strategy.polarity,)
        )

    content_ref = _require_empty_ref(_require_ref(strategy.content, 'content'), 'content')
    content_model = content_ref._root._meta.concrete_model
    source_ref = _require_empty_ref(_require_ref(strategy.source, 'source'), 'source')
    source_model = source_ref._root._meta.concrete_model

    descriptor = _require_same_root(strategy.descriptor, content_ref._root, 'descriptor')
    if descriptor._path:
        content_desc_hops = _hops_for_path(
            content_ref._root, descriptor._path, 'descriptor',
            require_nonnull=False,
        )
        policy_set_model = content_desc_hops[-1].to_model
        policy_set_target = content_desc_hops[-1].target
        content_desc_attname = content_desc_hops[0].attname if len(content_desc_hops) == 1 else ''
    else:
        content_desc_hops = ()
        policy_set_model = content_model
        policy_set_target = None
        content_desc_attname = ''

    source_descriptor = _require_same_root(
        strategy.source_descriptor, source_ref._root, 'source_descriptor',
    )
    if not source_descriptor._path:
        raise TrustsConfigurationError(
            'source_descriptor must be one or more forward single-valued hops.'
        )
    source_desc_hops = _hops_for_path(
        source_ref._root, source_descriptor._path, 'source_descriptor',
        require_nonnull=True,
    )
    src_policy_model = source_desc_hops[-1].to_model
    src_policy_target = source_desc_hops[-1].target
    if policy_set_target is None:
        policy_set_target = src_policy_target
        content_desc_attname = src_policy_target
        try:
            content_model._meta.get_field(src_policy_target)
        except FieldDoesNotExist:
            raise TrustsConfigurationError(
                'Empty-path descriptor binds to source_descriptor target '
                '%s.%s, which is missing on %s.'
                % (
                    src_policy_model._meta.label, src_policy_target,
                    content_model._meta.label,
                )
            )
    if src_policy_model is not policy_set_model or src_policy_target != policy_set_target:
        raise TrustsConfigurationError(
            'descriptor and source_descriptor must share one resolved '
            'comparison field; got %s.%s and %s.%s.'
            % (
                policy_set_model._meta.label, policy_set_target,
                src_policy_model._meta.label, src_policy_target,
            )
        )
    source_desc_attname = source_desc_hops[0].attname

    order_field = _resolve_source_scalar(
        source_model, strategy.order, 'order', families=_INTEGER_TYPES,
    )
    mask_field = _resolve_source_scalar(
        source_model, strategy.mask, 'mask', families=_INTEGER_TYPES,
    )
    polarity_field = _resolve_source_scalar(
        source_model, strategy.polarity.field, 'polarity',
        families=_POLARITY_TYPES,
    )
    if strategy.polarity.allow_value == strategy.polarity.deny_value:
        raise TrustsConfigurationError(
            'Polarity allow_value and deny_value must be distinct.'
        )
    _compatible_polarity(polarity_field, strategy.polarity.allow_value, 'allow_value')
    _compatible_polarity(polarity_field, strategy.polarity.deny_value, 'deny_value')

    trustee = _require_same_root(strategy.trustee, source_ref._root, 'trustee')
    if not trustee._path:
        raise TrustsConfigurationError(
            'trustee must be a non-empty forward single-valued path from source.'
        )
    trustee_hops = _hops_for_path(
        source_ref._root, trustee._path, 'trustee', require_nonnull=True,
    )
    identity_model = trustee_hops[-1].to_model
    identity_attname = trustee_hops[-1].target
    trustee_attname = trustee_hops[0].attname

    token = strategy.token
    principal = _require_empty_ref(
        _require_ref(token.principal, 'principal'), 'principal',
    )
    principal_model = principal._root._meta.concrete_model
    user_model = get_user_model()._meta.concrete_model
    principal_user = _require_same_root(
        token.principal_user, principal._root, 'principal_user',
    )
    if principal_user._path:
        user_hops = _hops_for_path(
            principal._root, principal_user._path, 'principal_user',
            require_nonnull=True,
        )
        if user_hops[-1].to_model is not user_model:
            raise TrustsConfigurationError(
                'principal_user must terminate on AUTH_USER_MODEL %s; got %s.'
                % (user_model._meta.label, user_hops[-1].to_model._meta.label)
            )
        principal_user_hops = user_hops
        principal_user_attname = user_hops[0].attname
        user_bind_attname = user_hops[-1].target
        principal_is_user = False
    else:
        if principal_model is not user_model:
            raise TrustsConfigurationError(
                'Empty-path principal_user requires principal root %s; got %s.'
                % (user_model._meta.label, principal_model._meta.label)
            )
        principal_user_hops = ()
        principal_user_attname = ''
        user_bind_attname = user_model._meta.pk.attname
        principal_is_user = True

    principal_identity = _require_same_root(
        token.principal_identity, principal._root, 'principal_identity',
    )
    principal_identity_hops, principal_identity_attname = _bind_identity(
        principal_identity, 'principal_identity',
        identity_model, identity_attname,
    )

    member_names = (token.member, token.member_identity, token.member_group)
    if any(name is not None for name in member_names) and not all(
        name is not None for name in member_names
    ):
        raise TrustsConfigurationError(
            'FlatToken member triad must be all set or all None.'
        )
    member_model = None
    member_identity_hops = ()
    member_group_hops = ()
    if token.member is not None:
        member = _require_empty_ref(_require_ref(token.member, 'member'), 'member')
        member_model = member._root._meta.concrete_model
        member_identity = _require_same_root(
            token.member_identity, member._root, 'member_identity',
        )
        member_group = _require_same_root(
            token.member_group, member._root, 'member_group',
        )
        if not member_identity._path or not member_group._path:
            raise TrustsConfigurationError(
                'member_identity and member_group must be forward singles '
                'from the member root.'
            )
        member_identity_hops, _ident_att = _bind_identity(
            member_identity, 'member_identity',
            identity_model, identity_attname,
        )
        member_group_hops, _group_att = _bind_identity(
            member_group, 'member_group',
            identity_model, identity_attname,
        )

    mask_rows, has_content_type, permission_model = _validate_domain(
        strategy.domain, content_model, mask_field,
    )

    return RegisteredStrategy(
        content_model=content_model,
        permission_model=permission_model,
        user_model=user_model,
        source_model=source_model,
        policy_set_model=policy_set_model,
        policy_set_target=policy_set_target,
        content_desc_path=tuple(descriptor._path),
        content_desc_attname=content_desc_attname,
        content_desc_hops=content_desc_hops,
        source_desc_hops=source_desc_hops,
        source_desc_attname=source_desc_attname,
        order_attname=order_field.attname,
        polarity_attname=polarity_field.attname,
        allow_value=strategy.polarity.allow_value,
        deny_value=strategy.polarity.deny_value,
        mask_attname=mask_field.attname,
        mask_internal_type=mask_field.get_internal_type(),
        trustee_hops=trustee_hops,
        trustee_attname=trustee_attname,
        identity_model=identity_model,
        identity_attname=identity_attname,
        principal_model=principal_model,
        principal_user_hops=principal_user_hops,
        principal_user_attname=principal_user_attname,
        user_bind_attname=user_bind_attname,
        principal_identity_hops=principal_identity_hops,
        principal_identity_attname=principal_identity_attname,
        principal_is_user=principal_is_user,
        member_model=member_model,
        member_identity_hops=member_identity_hops,
        member_group_hops=member_group_hops,
        mask_rows=mask_rows,
        has_content_type=has_content_type,
    )


def _qn(connection, name):
    return connection.ops.quote_name(name)


def _table(model):
    return model._meta.db_table


def _pk_attname(model):
    return model._meta.pk.attname


def _terminal_expr(connection, hops, root_alias, prefix, *, empty_attname=''):
    """SQL for the stored terminal identity of one forward-single path.

    Zero hops bind ``root_alias.empty_attname``. One hop is that FK on the
    root row (the first hop *is* the terminal). Two or more hops are a
    correlated scalar subquery that walks every intermediate model and
    selects the last hop's attname. ``prefix`` must be unique among
    sibling paths so independent multi-hop walks cannot collide.
    """
    if not hops:
        return '%s.%s' % (
            _qn(connection, root_alias),
            _qn(connection, empty_attname),
        )
    if len(hops) == 1:
        return '%s.%s' % (
            _qn(connection, root_alias),
            _qn(connection, hops[0].attname),
        )
    froms = []
    wheres = []
    for index, hop in enumerate(hops[:-1]):
        alias = '%s_%s' % (prefix, index)
        froms.append('%s %s' % (
            _qn(connection, _table(hop.to_model)),
            _qn(connection, alias),
        ))
        if index == 0:
            left_alias = root_alias
        else:
            left_alias = '%s_%s' % (prefix, index - 1)
        wheres.append(
            '%s.%s = %s.%s'
            % (
                _qn(connection, alias),
                _qn(connection, hop.target),
                _qn(connection, left_alias),
                _qn(connection, hop.attname),
            )
        )
    last = hops[-1]
    last_src = '%s_%s' % (prefix, len(hops) - 2)
    return '(SELECT %s FROM %s WHERE %s)' % (
        '%s.%s' % (_qn(connection, last_src), _qn(connection, last.attname)),
        ', '.join(froms),
        ' AND '.join(wheres),
    )


def _content_desc_sql(strategy, compiler, connection):
    alias = compiler.query.get_initial_alias()
    return _terminal_expr(
        connection,
        strategy.content_desc_hops,
        alias,
        'of_cdesc',
        empty_attname=strategy.content_desc_attname,
    ), ()


def _maskmap_sql(strategy, perm_sql, perm_params, connection):
    value_sql = ', '.join('(%s, %s, %s)' for _ in strategy.mask_rows)
    params = []
    for app_label, codename, mask in strategy.mask_rows:
        params.extend([app_label, codename, mask])
    perm_table = _qn(connection, _table(strategy.permission_model))
    perm_pk = _qn(connection, _pk_attname(strategy.permission_model))
    sql = (
        'SELECT maskmap.mask FROM (VALUES %s) AS maskmap(app_label, codename, mask) '
        'INNER JOIN %s of_perm ON of_perm.codename = maskmap.codename'
        % (value_sql, perm_table)
    )
    if strategy.has_content_type:
        from django.contrib.contenttypes.models import ContentType

        ct_field = strategy.permission_model._meta.get_field('content_type')
        sql += (
            ' INNER JOIN %s of_ct ON of_ct.%s = of_perm.%s'
            ' AND of_ct.app_label = maskmap.app_label'
            ' AND of_ct.model = %s'
            % (
                _qn(connection, ContentType._meta.db_table),
                _qn(connection, _pk_attname(ContentType)),
                _qn(connection, ct_field.attname),
                '%s',
            )
        )
        params.append(strategy.content_model._meta.model_name)
    sql += ' WHERE of_perm.%s = %s' % (perm_pk, perm_sql)
    params.extend(perm_params)
    return sql, params


def render_ordered_fold_sql(strategy, user, permission, compiler, connection):
    """Compile the Allowed predicate. Raises before fold SQL on other vendors."""
    from trusts.core import _is_lookup_expression

    _require_postgresql_fold_renderer(connection)
    content_sql, content_params = _content_desc_sql(strategy, compiler, connection)
    if _is_lookup_expression(permission):
        perm_sql, perm_params = compiler.compile(permission)
        perm_params = tuple(perm_params)
    else:
        perm_sql, perm_params = '%s', (permission.pk,)

    if strategy.principal_is_user:
        ident_value = getattr(user, strategy.identity_attname)
        user_sql, user_params = '%s', (ident_value,)
    else:
        user_sql, user_params = '%s', (getattr(user, strategy.user_bind_attname),)

    src = _qn(connection, 'of_src')
    src_table = _qn(connection, _table(strategy.source_model))
    src_pk = _qn(connection, _pk_attname(strategy.source_model))
    order_col = '%s.%s' % (src, _qn(connection, strategy.order_attname))
    polarity_col = '%s.%s' % (src, _qn(connection, strategy.polarity_attname))
    mask_col = '%s.%s' % (src, _qn(connection, strategy.mask_attname))
    trustee_col = _terminal_expr(
        connection, strategy.trustee_hops, 'of_src', 'of_strust',
        empty_attname=strategy.trustee_attname,
    )
    src_desc_col = _terminal_expr(
        connection, strategy.source_desc_hops, 'of_src', 'of_sdesc',
        empty_attname=strategy.source_desc_attname,
    )

    token_direct, extra_member, token_params = _token_parts(
        strategy, user_sql, connection,
    )
    maskmap_sql, maskmap_params = _maskmap_sql(
        strategy, perm_sql, perm_params, connection,
    )

    invalid_sql = (
        'EXISTS ('
        'SELECT 1 FROM %s %s WHERE %s = %s AND ('
        '(%s IS DISTINCT FROM %s AND %s IS DISTINCT FROM %s)'
        ' OR %s IS NULL OR %s IS NULL OR %s < 0 OR %s IS NULL'
        '))'
        % (
            src_table, src, src_desc_col, content_sql,
            polarity_col, '%s', polarity_col, '%s',
            order_col, mask_col, mask_col, trustee_col,
        )
    )
    applicable_where = (
        '%s = %s AND %s IN (SELECT ident FROM of_token) '
        'AND %s IN (%s, %s) '
        'AND %s IS NOT NULL AND %s IS NOT NULL AND %s >= 0 AND %s IS NOT NULL'
        % (
            src_desc_col, content_sql,
            trustee_col,
            polarity_col, '%s', '%s',
            order_col, mask_col, mask_col, trustee_col,
        )
    )
    fold_sql = (
        'EXISTS ('
        'WITH RECURSIVE '
        'of_token_direct AS (%s), '
        'of_token AS (%s), '
        'requested AS (%s), '
        'applicable AS ('
        'SELECT %s AS ord, %s AS pk, %s AS polarity, %s::bigint AS mask '
        'FROM %s %s WHERE %s'
        '), '
        'numbered AS ('
        'SELECT ord, pk, polarity, mask, '
        'ROW_NUMBER() OVER (ORDER BY ord, pk) AS rn FROM applicable'
        '), '
        'scan AS ('
        'SELECT 0::bigint AS step, '
        '(SELECT mask FROM requested)::bigint AS remaining, '
        'FALSE AS denied '
        'UNION ALL '
        'SELECT n.rn, '
        'CASE WHEN s.remaining IS NULL THEN NULL '
        'WHEN n.polarity IS NOT DISTINCT FROM %s THEN s.remaining & ~n.mask '
        'ELSE s.remaining END, '
        'COALESCE(s.denied, FALSE) OR ('
        'n.polarity IS NOT DISTINCT FROM %s AND s.remaining IS NOT NULL '
        'AND (s.remaining & n.mask) <> 0'
        ') '
        'FROM scan s INNER JOIN numbered n ON n.rn = s.step + 1 '
        'WHERE NOT COALESCE(s.denied, FALSE) AND s.remaining IS DISTINCT FROM 0'
        ') '
        'SELECT 1 FROM requested WHERE ('
        'SELECT remaining = 0 AND NOT denied FROM scan '
        'ORDER BY step DESC LIMIT 1'
        '))'
        % (
            token_direct,
            extra_member,
            maskmap_sql,
            order_col, '%s.%s' % (src, src_pk), polarity_col, mask_col,
            src_table, src, applicable_where,
            '%s', '%s',
        )
    )
    sql = '(NOT %s AND %s)' % (invalid_sql, fold_sql)
    params = []
    params.extend(content_params)
    params.extend([strategy.allow_value, strategy.deny_value])
    params.extend(user_params)
    params.extend(maskmap_params)
    params.extend(content_params)
    params.extend([strategy.allow_value, strategy.deny_value])
    params.extend([strategy.allow_value, strategy.deny_value])
    return sql, tuple(params)


def _token_parts(strategy, user_sql, connection):
    ident_col = _terminal_expr(
        connection,
        strategy.principal_identity_hops,
        'of_p',
        'of_pident',
        empty_attname=strategy.principal_identity_attname,
    )
    if strategy.principal_is_user:
        token_direct = 'SELECT %s AS ident' % user_sql
    else:
        user_col = _terminal_expr(
            connection,
            strategy.principal_user_hops,
            'of_p',
            'of_puser',
            empty_attname=strategy.principal_user_attname or strategy.user_bind_attname,
        )
        token_direct = (
            'SELECT %s AS ident FROM %s %s WHERE %s = %s'
            % (
                ident_col,
                _qn(connection, _table(strategy.principal_model)),
                _qn(connection, 'of_p'),
                user_col,
                user_sql,
            )
        )
    if strategy.member_model is None:
        return token_direct, 'SELECT ident FROM of_token_direct', ()
    mem_ident_col = _terminal_expr(
        connection,
        strategy.member_identity_hops,
        'of_m',
        'of_mident',
    )
    mem_group_col = _terminal_expr(
        connection,
        strategy.member_group_hops,
        'of_m',
        'of_mgroup',
    )
    member_sql = (
        'SELECT %s AS ident FROM %s %s '
        'WHERE %s IN (SELECT ident FROM of_token_direct)'
        % (
            mem_group_col,
            _qn(connection, _table(strategy.member_model)),
            _qn(connection, 'of_m'),
            mem_ident_col,
        )
    )
    token = (
        'SELECT ident FROM of_token_direct UNION %s'
        % member_sql
    )
    return token_direct, token, ()


class OrderedFoldAllowed(Expression):
    """Candidate-row Allowed predicate for one compiled OrderedFold plan."""

    filterable = True
    subquery = True

    def __init__(self, strategy, user, permission):
        super().__init__(output_field=BooleanField())
        self.strategy = strategy
        self.user = user
        self.permission = permission

    def get_source_expressions(self):
        from trusts.core import _is_lookup_expression

        if _is_lookup_expression(self.permission):
            return [self.permission]
        return []

    def set_source_expressions(self, exprs):
        exprs = list(exprs)
        if exprs:
            self.permission = exprs[0]

    def as_sql(self, compiler, connection):
        return render_ordered_fold_sql(
            self.strategy, self.user, self.permission, compiler, connection,
        )
