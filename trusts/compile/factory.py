"""Registration marshaling and the ready-time sweep."""

__all__ = []

import inspect
from collections.abc import Callable
from typing import TypeVar

from dataclasses import dataclass, field, replace

from django.core.exceptions import FieldDoesNotExist
from django.db.models import Model, Q

from trusts.plan.hops import (
    concrete_model,
    content_model,
    lookup_text,
    path_text,
    require_instance,
    resolved_hop,
)
from trusts.compile.nodes import (
    Along,
    Ref,
    _is_model_class,
    _require_ref,
)
from trusts.plan.grammar import (
    Symbol,
    Tree,
    inquiry_partner,
    invoke,
    is_inquiry,
    symbol_path,
    symbol_token,
    unsupported,
)
from trusts.compile.paths import AlongWalk
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
from trusts.errors import PermissionConditionError, TrustsConfigurationError

T = TypeVar('T', bound=Model)
from trusts.compile.catalogs import Catalog, CatalogShape
from trusts.plan.conditions import (
    check_comparison_types,
    check_const_member,
    condition_model_key,
    condition_model_label,
    normalize_expression,
    parse_named_filter,
    require_boolean_field,
)
from trusts.plan.relations import PlanQueryCompiler, RelationPlan, bind_checked_user
from trusts.plan.standards import (
    UserCondition,
    validate_user_rule,
    builtin_user_conditions,
    compile_override_q,
    compile_user_rules,
    concrete_rule,
    normalize_on,
    normalize_override_on,
    rule_applies,
    validate_user_rule_name,
)


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
    refs are ``None``. Storing it is ``register``'s job, via
    ``register_relation`` or ``register_delegation``.
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


def relation_plan(records, delegations, content, user, permission,
                  catalog_user, user_conditions, user_rules, override_q):
    """One plan for ``(content, user, permission)``. An empty selection is a plan."""
    chosen = tuple(
        record for record in records
        if record.content_model is content
        and (user is None or record.user_model is user)
        and (permission is None or record.permission_model is permission))
    bridges = tuple(
        record for record in delegations
        if record.content_model is content
        and (user is None or record.delegate_model is user))
    plan_permission = permission
    column = 'pk'
    if chosen:
        models = {record.permission_model for record in chosen}
        if len(models) != 1:
            raise TrustsConfigurationError(
                'Applicable registrations must share one permission '
                'model; got %s.'
                % ', '.join(sorted(model._meta.label for model in models)))
        plan_permission = models.pop()
        targets = {record.permission_target for record in chosen}
        if len(targets) != 1:
            raise TrustsConfigurationError(
                'Applicable registrations must share one permission '
                'comparison target; got %s.'
                % ', '.join(sorted(targets)))
        stored = targets.pop()
        if stored not in (plan_permission._meta.pk.attname, 'pk'):
            column = stored
    subject = user
    if subject is None:
        subjects = {
            record.user_model._meta.concrete_model for record in chosen}
        subjects.update(
            record.delegate_model._meta.concrete_model for record in bridges)
        if len(subjects) == 1:
            subject = subjects.pop()
    rules = closed = override = None
    if subject is not None:
        primary, absent = user_rules
        rules = primary if (
            user_conditions is not None or builtin_user_conditions(subject)
        ) else absent
        closed, override = rules, override_q
    return RelationPlan(
        records=chosen, delegations=bridges, permission_model=plan_permission,
        content_identity=content, user_rules=rules, user_rules_closed=closed,
        user_override_q=override, user_model=catalog_user,
        permission_column=column)


def plan_table(records, delegations, catalog_user, user_conditions,
               user_rules, override_q):
    """Selectable keys in first-seen order. ``None`` is the default plan."""
    users, perms, order = {}, {}, []
    observed = [
        (record.content_model, record.user_model, record.permission_model)
        for record in records]
    observed.extend(
        (record.content_model, record.delegate_model, None)
        for record in delegations)
    for content, user, perm in observed:
        seen = users.get(content)
        if seen is None:
            order.append(content)
            users[content] = seen = []
            perms[content] = []
        if user not in seen:
            seen.append(user)
        if perm is not None and perm not in perms[content]:
            perms[content].append(perm)
    table = {
        (content, user, perm): relation_plan(
            records, delegations, content, user, perm, catalog_user,
            user_conditions, user_rules, override_q)
        for content in order
        for user in (None, *users[content])
        for perm in (None, *perms[content])}
    table[None] = relation_plan(
        records, delegations, None, None, None, catalog_user,
        user_conditions, user_rules, override_q)
    return table


class Compiler(object):
    """Replay target for one recorder.

    The app recorder stores every registration call. ``ready`` replays
    that log onto this compiler. ``register`` performs zero SQL.
    ``compile`` freezes this compiler and returns a ``Catalog``. A later
    ``compile`` returns another catalog from the same stored rows.
    After that, ``register``, ``register_delegation``,
    ``add_named_filter``, ``set_user_condition``, and
    ``set_user_override`` raise ``TrustsConfigurationError``.
    """

    def __init__(self, *, user_model, query_compiler, path, family):
        self._by_root = {}
        self._order = []
        self._delegations_by_root = {}
        self._delegation_order = []
        self.frozen = False
        self._user_conditions = None
        self._user_override = None
        self._named_filters = {}
        self.query_compiler = query_compiler
        self.path = path
        self.family = family
        self.user_model = user_model

    @staticmethod
    def default_query_compiler():
        """Plan compiler ``ready`` stores when the config does not set one."""
        return PlanQueryCompiler()

    def get_recorder_target(self):
        return self

    def add_named_filter(self, model, code, predicate):
        """Register a ``:code`` condition on ``model`` for this instance.

        A callable is a registration-time builder. This method asks
        the condition language to parse it once and stores the checked
        tree. A prebuilt ``Tree`` raises ``TypeError`` before the
        mapping changes.
        """
        self._open('add_named_filter')
        if isinstance(predicate, Tree) or not callable(predicate):
            raise TypeError(
                'add_named_filter expected a builder callable, '
                'got %r.' % (type(predicate).__name__,)
            )
        key = (condition_model_key(model), code)
        if key in self._named_filters:
            raise PermissionConditionError(
                'Named filter %r is already registered on %s.'
                % (code, condition_model_label(model))
            )
        tree = parse_named_filter(predicate, model, code, self.user_model)
        self._named_filters[key] = (model, tree)
        return tree

    def user_conditions(self):
        """Effective user conditions.

        ``None`` store means the built-in ``is_active`` rule when the
        configured user model has that concrete boolean field, and no
        conditions otherwise. Compilation for a registered model uses
        that model's own fields.
        """
        if self._user_conditions is None:
            return builtin_user_conditions(self.user_model)
        return tuple(self._user_conditions.values())

    def set_user_condition(self, name, expr, on='*'):
        """Set, replace, or remove one named user condition.

        Record this before ``register()``. The catalog sweep checks the
        order at ready. ``None`` removes that name. ``on`` is ``*``,
        ``user``, or ``sponsor``.
        The lambda is walked once against this factory's ``user_model``.
        """
        self._open('set_user_condition')
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
                for rule in builtin_user_conditions(self.user_model)
            }
        try:
            if expr is None:
                if name not in self._user_conditions:
                    raise TrustsConfigurationError(
                        'User condition %r is not registered.' % (name,)
                    )
                del self._user_conditions[name]
                return None
            rule = UserCondition(
                name, concrete_rule(expr, name, self.user_model), target,
            )
        except TrustsConfigurationError:
            if created:
                self._user_conditions = None
            raise
        self._user_conditions[name] = rule
        return rule

    def set_user_override(self, name, expr, on='user'):
        """Store the one checked-user override, or clear it with ``None``.

        Record this before ``register()``. The catalog sweep checks the
        order at ready. ``on="sponsor"`` and ``on="*"`` raise. The name cannot match a
        registered condition.
        """
        self._open('set_user_override')
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
            return None
        self._user_override = UserCondition(
            name, concrete_rule(expr, name, self.user_model), 'user',
        )
        return self._user_override

    @property
    def records(self):
        return tuple(self._order)

    @property
    def delegations(self):
        return tuple(self._delegation_order)

    @staticmethod
    def build_delegation(*, content, delegate, sponsor, condition=None,
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
        (
            condition, condition_permission_model,
            condition_permission_target,
        ) = _validate_delegated_condition(condition, root)
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
        self._open('register_delegation')
        record = self.build_delegation(
            content=content, delegate=delegate, sponsor=sponsor,
            condition=condition, along=along,
        )
        root = record.root
        existing = self._delegations_by_root.get(root, ())
        conditions = self._stored_user_conditions()
        override = self._user_override
        same_root = [row for row in existing if row.root is record.root]
        if record in same_root:
            raise TrustsConfigurationError(
                'Duplicate delegated registration for %s.'
                % record.root._meta.label
            )
        for prior in same_root:
            if prior.content_model is record.content_model:
                raise TrustsConfigurationError(
                    'Conflicting delegated registration for %s content '
                    'terminal %s: existing %r, new %r.'
                    % (
                        record.root._meta.label,
                        record.content_model._meta.label,
                        prior,
                        record,
                    )
                )
        _assert_registration_rules(
            user_model=record.delegate_model,
            sponsor_model=record.sponsor_model,
            conditions=conditions, override=override,
        )
        sponsor_model = record.sponsor_model._meta.concrete_model
        record = replace(record, sponsor_rules=compile_user_rules(
            sponsor_model, record.sponsor_field,
            _rules_for_model(conditions, sponsor_model),
            role='sponsor', values={},
            scope=record.root,
        ))
        existing_rows = self._delegations_by_root.get(root)
        if existing_rows:
            existing_rows.append(record)
        else:
            self._delegations_by_root[root] = [record]
        self._delegation_order.append(record)
        return record

    @staticmethod
    def build_relation(*, content, user, permission=None, group=None,
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
        condition = _validate_condition(
            condition, root, permission_model,
            permission_target=permission_target,
            registered_permission=permission_path,
        )
        content_path, content_model, content_field, content_target = _resolve_path(
            root, content_ref._path, 'content', trailing_reverse=True,
        )
        user_path, user_model, user_field, user_target = _resolve_path(
            root, user_ref._path, 'user', terminal_membership=True,
        )
        along_walk = None
        if along is not None:
            along_walk = _build_along_walk(
                root, content_path, content_model, along,
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

    def register_relation(self, *, content, user, permission=None, group=None,
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

        Optional ``condition`` is a shared condition tree compiled as an
        AND overlay on the same root row. Validation uses ``_meta`` only
        (zero SQL).

        This method does not inspect Django's global ``apps.ready``.
        """
        self._open('register')
        record = self.build_relation(
            content=content, user=user, permission=permission, group=group,
            condition=condition, along=along,
        )
        root = record.root
        existing = self._by_root.get(root, ())
        conditions = self._stored_user_conditions()
        override = self._user_override
        for prior in existing:
            if prior.root is not record.root:
                continue
            if prior == record:
                raise TrustsConfigurationError(
                    'Duplicate registration for %s.' % record.root._meta.label
                )
            if prior.content_model is not record.content_model:
                continue
            if (
                _same_terminal_bindings(prior, record)
                and prior.condition != record.condition
            ):
                continue
            raise TrustsConfigurationError(
                'Conflicting registration for %s content terminal '
                '%s: existing %r, new %r.'
                % (
                    record.root._meta.label,
                    record.content_model._meta.label,
                    prior,
                    record,
                )
            )
        _assert_registration_rules(
            user_model=record.user_model, sponsor_model=None,
            conditions=conditions, override=override,
        )
        existing_rows = self._by_root.get(root)
        if existing_rows:
            existing_rows.append(record)
        else:
            self._by_root[root] = [record]
        self._order.append(record)
        return record

    @staticmethod
    def build_public_registration(
        *, trust, user=None, permission=None, content, group=None,
        delegate=None, sponsor=None, condition=None, along=None,
    ):
        """Build a normalized ``PublicRegistration`` without storing it.

        Shape-building half of ``register``: same mode, trust,
        path-builder, condition, and ``along`` validation and errors, in
        the same order, but no append. Path and
        condition builders are invoked exactly once, here; the returned
        shape carries only refs, lowered condition IR, and ``Along``.
        ``register`` stores the shape
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
                    trust, condition,
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
            _perm_path, _perm_model, _permission_text, _perm_target = (
                _append_group_permissions(group_segments, group_field)
            )
            return PublicRegistration(
                trust=trust,
                content=_public_ref(trust, content_path, 'content'),
                user=_public_ref(trust, user_path, 'user'),
                group=_public_ref(trust, group_text, 'group'),
                condition=_normalize_public_condition(trust, condition),
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
            condition=_normalize_public_condition(trust, condition),
            along=_bind_public_along(trust, along),
        )

    def register(
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
            return self.register_relation(
                content=shape.content,
                user=shape.user,
                group=shape.group,
                condition=shape.condition,
                along=shape.along,
            )
        return self.register_relation(
            content=shape.content,
            user=shape.user,
            permission=shape.permission,
            condition=shape.condition,
            along=shape.along,
        )

    def compile(self):
        """Freeze this compiler and return its ``Catalog``.

        Named filters are copied into a new mapping, so the catalog
        does not share this compiler's store. User-rule and override
        fragments and the plan table are compiled here. A later call
        compiles another catalog from the same stored rows.
        """
        named_filters = dict(self._named_filters)
        stored = self._stored_user_conditions()
        model = self.user_model
        primary = compile_user_rules(
            model, '', None if stored is None else stored, role='user', values={},
        )
        absent = primary if stored is not None else compile_user_rules(
            model, '', (), role='user', values={})
        slot = self._user_override
        override_q = None
        if slot is not None:
            seen = set()
            candidates = [model]
            candidates.extend(record.user_model for record in self.records)
            candidates.extend(record.delegate_model for record in self.delegations)
            for candidate in candidates:
                concrete = candidate._meta.concrete_model
                if concrete in seen:
                    continue
                seen.add(concrete)
                validate_user_rule(concrete, slot.expr, slot.name)
            override_q = compile_override_q(model, '', slot, {})
        rules = (primary, absent)
        plans = plan_table(
            self.records, self.delegations, model, stored, rules, override_q)
        self.frozen = True
        shape = CatalogShape(
            records=self.records, delegations=self.delegations,
            named_filters=named_filters,
            user_conditions=stored, user_override=self._user_override,
            compiler=self.query_compiler,
            path=self.path, family=self.family, user_model=model,
            user_rules=rules, override_q=override_q, plans=plans,
        )
        return Catalog(shape, user_model=model)

    def _stored_user_conditions(self):
        """``None`` when the registry still uses the built-in rule."""
        if self._user_conditions is None:
            return None
        return tuple(self._user_conditions.values())

    def _open(self, method):
        if self.frozen:
            raise TrustsConfigurationError(
                '%s refused: this compiler is frozen.' % method
            )

    def _open_for_rules(self, kind):
        if self._order or self._delegation_order:
            raise TrustsConfigurationError(
                'Record user conditions and the override before '
                'register(). The catalog sweep checks this at ready().'
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


def _validate_equal_paths(left_path, right_path, root):
    _left_path, left_model, _left_field, left_target = _resolve_forward_singles(
        root, left_path, 'condition',
    )
    _right_path, right_model, _right_field, right_target = (
        _resolve_forward_singles(root, right_path, 'condition')
    )
    if left_model is not right_model:
        raise PermissionConditionError(
            'Equal paths must terminate on the same model; got %s and %s.'
            % (left_model._meta.label, right_model._meta.label)
        )
    # Compiler compares stored FK columns via F(). Distinct unique
    # fields (``to_field``) on the same model can collide across
    # objects and fail open if only the terminal model is checked.
    if left_target != right_target:
        raise PermissionConditionError(
            'Equal paths must share one resolved comparison field; '
            'got %s.%s and %s.%s.'
            % (
                left_model._meta.label, left_target,
                right_model._meta.label, right_target,
            )
        )

def _relation_where(delegated):
    if delegated:
        return 'a delegated condition'
    return 'a relation condition'


def _row_paths_comparable(left_path, right_path, root):
    """True when two row paths share one relation target.

    A scalar terminal is not a relation walk. ``_validate_equal_paths``
    reports that with ``traverses scalar``. A multi-valued walk, a
    mismatched model, and a mismatched ``to_field`` propagate unchanged.
    """
    try:
        _validate_equal_paths(left_path, right_path, root)
    except TrustsConfigurationError as exc:
        if 'traverses scalar' not in str(exc):
            raise
        return False
    return True


def _compares_bare_inquiry(node):
    return is_inquiry(node.left) or is_inquiry(node.right)


def _require_row_field(node):
    if node.kind != 'field' or node.root != 'row' or not node.path:
        raise PermissionConditionError(
            'A relation condition compares field paths on the trust row.'
        )
    return node.path


def _reject_inquiry_hop(node, where, *, member):
    if not (
        isinstance(node, Tree)
        and node.kind == 'field'
        and node.root == 'inquiry'
        and node.path
    ):
        return
    if member:
        hint = 'Pass the permission itself as the member.'
    else:
        hint = 'Compare the permission itself to a column on the trust row.'
    raise unsupported(
        'A field on the requested permission', where, hint=hint,
    )


def _validate_relation_node(node, root, permission_model, *,
                            permission_target=None, delegated=False,
                            matches=None, registered_permission=None):
    where = _relation_where(delegated)
    if not isinstance(node, Tree):
        raise unsupported('This condition', where)
    if node.kind in ('and', 'or'):
        _validate_relation_node(
            node.left, root, permission_model,
            permission_target=permission_target, delegated=delegated,
            matches=matches, registered_permission=registered_permission,
        )
        _validate_relation_node(
            node.right, root, permission_model,
            permission_target=permission_target, delegated=delegated,
            matches=matches, registered_permission=registered_permission,
        )
        return
    if node.kind == 'not':
        _validate_relation_node(
            node.item, root, permission_model,
            permission_target=permission_target, delegated=delegated,
            matches=matches, registered_permission=registered_permission,
        )
        return
    if node.kind == 'bare':
        _require_row_field(node.item)
        require_boolean_field(
            root, node.item.path, 'condition', where='a relation condition',
        )
        return
    if node.kind in ('eq', 'ne'):
        _validate_row_comparison(
            node, root, delegated=delegated, matches=matches,
        )
        return
    if node.kind == 'contains':
        _validate_row_contains(
            node, root, permission_model,
            permission_target=permission_target, delegated=delegated,
            matches=matches,
            registered_permission=registered_permission,
        )
        return
    raise unsupported(node.kind, where)


def _validate_row_comparison(node, root, *, delegated, matches):
    where = _relation_where(delegated)
    _reject_inquiry_hop(node.left, where, member=False)
    _reject_inquiry_hop(node.right, where, member=False)
    if _compares_bare_inquiry(node):
        column = inquiry_partner(node)
        if column is None or column.kind != 'field' or not column.path:
            raise unsupported(
                'Comparing the requested permission to a constant',
                where,
                hint=(
                    'The permission binding is sometimes an SQL expression, '
                    'not a loaded row.'
                ),
            )
        _require_row_field(column)
        _path, model, _field, target = _resolve_permission_path(
            root, column.path,
        )
        if matches is not None:
            matches.append((model, target))
        return
    for side in (node.left, node.right):
        if side.kind == 'const':
            continue
        _require_row_field(side)
    if node.left.kind == 'field' and node.right.kind == 'field':
        if _row_paths_comparable(node.left.path, node.right.path, root):
            return
    check_comparison_types(node, root, root)


def _validate_row_contains(node, root, permission_model, *,
                           permission_target, delegated, matches,
                           registered_permission):
    where = _relation_where(delegated)
    _require_row_field(node.left)
    member = node.right
    _reject_inquiry_hop(member, where, member=True)
    if member.kind == 'const':
        check_const_member(root, node.left.path, node.right.value)
        return
    if is_inquiry(member):
        _path, model, _field, target = _resolve_permission_path(
            root, node.left.path,
        )
        if matches is not None:
            matches.append((model, target))
        return
    member_path = _require_row_field(member)
    if delegated or registered_permission is None:
        raise PermissionConditionError(
            'row-only delegated condition .contains() cannot bind the '
            'requested permission; accept a second argument and pass it '
            'as the member.'
        )
    if tuple(member_path) != tuple(registered_permission):
        raise PermissionConditionError(
            'condition .contains member must be the registered '
            'permission path %r, not %r.'
            % ('__'.join(registered_permission), '__'.join(member_path))
        )
    _resolve_permission_in_path(
        root, node.left.path, 'condition', permission_model,
        permission_target=permission_target,
    )


def _validate_condition(condition, root, permission_model,
                        permission_target=None, registered_permission=None):
    """Registration-time ``_meta`` validation. Zero SQL. None is a no-op."""
    if condition is None:
        return None
    _validate_relation_node(
        condition, root, permission_model,
        permission_target=permission_target, delegated=False,
        registered_permission=registered_permission,
    )
    return condition

def _validate_delegated_condition(condition, root):
    """Validate a delegated predicate and return inquiry terminal metadata.

    Row-only predicates have no permission terminal. Every match against
    the requested permission must resolve to the same model and comparison
    target. Validation is metadata-only and therefore remains zero SQL.
    """
    if condition is None:
        return condition, None, None
    matches = []
    _validate_relation_node(
        condition, root, None, delegated=True, matches=matches,
    )
    if not matches:
        return condition, None, None
    first_model, first_target = matches[0]
    for model, target in matches[1:]:
        if model is not first_model or target != first_target:
            raise PermissionConditionError(
                'Delegated inquiry-permission paths must share one model '
                'and comparison target.'
            )
    return condition, first_model, first_target

def _common_prefix(left, right):
    n = 0
    for a, b in zip(left, right):
        if a != b:
            break
        n += 1
    return left[:n]

def _target_field(field, role, path):
    """Return ``(related_model, target_field)`` for one hop."""
    related, attname = resolved_hop(field, role, path)
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
                % (path_text(edge_path), edge_path[0], walk_model._meta.label)
            )
        kind = _classify_field(field)
        related, target = _target_field(field, 'along', edge_path)
        if related is not walk_model:
            raise TrustsConfigurationError(
                'along edge %r must terminate on walk-site model %s, not %s.'
                % (
                    path_text(edge_path),
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
                        path_text(edge_path),
                        walk_model._meta.label,
                        dest._meta.label,
                    )
                )
            return 'C', fk.attname, None, None, None, edge_target
        raise TrustsConfigurationError(
            'along edge %r is not a supported S/C/E hop.'
            % (path_text(edge_path),)
        )
    if n == 2:
        try:
            reverse = walk_model._meta.get_field(edge_path[0])
        except FieldDoesNotExist:
            raise TrustsConfigurationError(
                'along path %r refers to missing field %r on %s.'
                % (path_text(edge_path), edge_path[0], walk_model._meta.label)
            )
        if _classify_field(reverse) != 'reverse_o2m':
            raise TrustsConfigurationError(
                'along edge %r is not a supported S/C/E hop.'
                % (path_text(edge_path),)
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
                    path_text(edge_path), edge_path[1],
                    edge_model._meta.label,
                )
            )
        if _classify_field(forward) != 'single':
            raise TrustsConfigurationError(
                'along edge %r is not a supported S/C/E hop.'
                % (path_text(edge_path),)
            )
        dest, parent_target = _target_field(forward, 'along', edge_path)
        if dest is not walk_model:
            raise TrustsConfigurationError(
                'along edge %r must terminate on walk-site model %s, not %s.'
                % (
                    path_text(edge_path),
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
                    path_text(edge_path),
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
        % (path_text(edge_path),)
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
                % (path_text(suffix_path), walk_model._meta.label, name)
            )
        kind = _classify_field(field)
        if kind not in _SUFFIX_KINDS:
            raise TrustsConfigurationError(
                'along suffix path %r uses unsupported field %r on %s.'
                % (path_text(suffix_path), name, current._meta.label)
            )
        related, _attname = resolved_hop(field, 'along suffix', suffix_path)
        current = related
    if current is not content_model:
        raise TrustsConfigurationError(
            'along suffix path %r from %s terminates on %s, not %s.'
            % (
                path_text(suffix_path),
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
            % (path_text(along_ref._path), path_text(content_path))
        )
    if not edge_path:
        raise TrustsConfigurationError(
            'along ref %r has no edge hop beyond the walk-site.'
            % (path_text(along_ref._path),)
        )
    _walk_path, walk_model, walk_field, walk_ident = _resolve_path(
        root, walk_path, 'along', trailing_reverse=True,
    )
    last_walk_name = walk_path[-1]
    current = root
    for name in walk_path[:-1]:
        field = current._meta.get_field(name)
        current, _att = resolved_hop(field, 'along', walk_path)
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
        suffix_field=lookup_text(suffix_path) if suffix_path else '',
        ident_family=ident_family,
        parent_attname=parent_attname,
        edge_model=edge_model,
        edge_parent_attname=edge_parent_attname,
        edge_child_attname=edge_child_attname,
        rewrite_attname=rewrite_attname,
    )

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

def _rules_for_model(conditions, model):
    """Stored rules, or the built-in ``is_active`` rule for ``model``."""
    if conditions is not None:
        return conditions
    return builtin_user_conditions(model)

def _assert_registration_rules(*, user_model, sponsor_model, conditions,
                               override):
    """Require each applicable rule's concrete booleans on these models.

    ``conditions`` is the recorded rule tuple, or ``None`` for the
    built-in rule. ``override`` is the recorded override, or ``None``.
    """
    pairs = []
    if user_model is not None:
        pairs.append((user_model, 'user'))
    if sponsor_model is not None:
        pairs.append((sponsor_model, 'sponsor'))
    for model, role in pairs:
        concrete = model._meta.concrete_model
        for rule in _rules_for_model(conditions, concrete):
            if not rule_applies(rule.on, role):
                continue
            validate_user_rule(concrete, rule.expr, rule.name)
    if override is not None and user_model is not None:
        validate_user_rule(
            user_model._meta.concrete_model, override.expr, override.name,
        )

_CONDITION_ARITY_PROBE = object()


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

def _reject_public_condition_value(condition):
    """Public ``condition=`` is a callable, not a prebuilt tree."""
    if isinstance(condition, (Tree, Ref, Q, str, bool)):
        raise TypeError(
            'condition must be a symbolic callable, '
            'not a prebuilt condition or other non-callable %r.'
            % (condition,)
        )
    if not callable(condition):
        raise TypeError(
            'condition must be a symbolic callable, '
            'not %r.' % (condition,)
        )

def _prepare_condition_builder(condition):
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
    return condition


def _normalize_public_condition(trust, condition):
    """Invoke a public condition builder once. The relation walk is later."""
    if _prepare_condition_builder(condition) is None:
        return None
    _require_condition_arity(condition)
    return normalize_expression(invoke(condition, ('row',)))


def _normalize_delegated_condition(trust, condition):
    """Invoke a delegated condition builder once. The relation walk is later."""
    if _prepare_condition_builder(condition) is None:
        return None
    if _delegated_condition_arity(condition) == 2:
        roots = ('row', 'inquiry')
    else:
        roots = ('row',)
    return normalize_expression(invoke(condition, roots))

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
    symbol = Symbol('row', token=token)
    try:
        result = value(symbol)
    except TrustsConfigurationError:
        raise
    except Exception as exc:
        raise TrustsConfigurationError(
            '%s path builder failed: %s' % (role, exc)
        ) from exc
    if not isinstance(result, Symbol):
        raise PermissionConditionError(
            '%s path builder must return a path rooted at the supplied '
            'trust value, not %r.' % (role, result)
        )
    if symbol_token(result) is not token:
        raise PermissionConditionError(
            '%s path builder used a path from another symbolic root.'
            % (role,)
        )
    if not symbol_path(result):
        raise PermissionConditionError(
            '%s path builder returned an empty path.' % (role,)
        )
    return '__'.join(symbol_path(result))

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
