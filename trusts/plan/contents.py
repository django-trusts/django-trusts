"""Content grants and permitted-content filters.

Not a public import surface. ``trusts.core`` re-exports these names.
"""

__all__ = []

from functools import reduce
from operator import or_

from django.apps import apps as django_apps
from django.core.exceptions import FieldDoesNotExist
from django.db.models import Exists, F, Model, OuterRef, Q
from django.db.models.base import ModelBase
from django.db.models.query import QuerySet

from trusts._bind_once import bind_once
from trusts.commons import (
    _bind_record_qs,
    _bind_terminal,
    _lookup_text,
    _require_instance,
)
from trusts.errors import TrustsConfigurationError
from trusts.plan.delegations import (
    _matched_delegation_q,
    _sponsor_record_matches,
)
from trusts.plan.walk import _delegation_walk_seed, _sponsor_walk_seed
from trusts.plan.recursions import (
    GrantReach,
    _AnchorInInverseReach,
    _KeyedReach,
    _PrefixInForwardWalk,
)
from trusts.plan.relations import (
    _bound_permission_identity,
    _candidate_model,
    _or_q,
    bind_checked_user,
)


def _as_q(predicate):
    if predicate is None:
        return None
    if isinstance(predicate, Q):
        return predicate
    return Q(predicate)


def _plan_for_permission(handle, candidates, user, permission):
    if isinstance(permission, Model):
        return handle.registry.plan_for(
            candidates, user=user, permission=permission,
        )
    return handle.registry.plan_for(candidates, user=user)


def _relationship_handles(handles):
    from trusts.apps import _relationship_family_handles

    return _relationship_family_handles(handles)


def _apply_checked_user(grant, plan, user, values, permission, content_identity,
                        permission_model, *, complete):
    """Bind this plan's registration-time rules around ``grant``."""
    with_override = complete and bool(plan.records or plan.delegations)
    identity = None
    if with_override and plan.user_override_q is not None:
        identity = _bound_permission_identity(
            permission, content_identity,
            permission_model or plan.permission_model,
        )
    return bind_checked_user(
        user, grant, plan=plan, identity=identity, values=values,
        with_override=with_override,
    ).predicate


def _compile_granted(handles, candidates, user, permission, *, kind='complete',
                     sponsor_handles=None, permission_model=None,
                     skipped=()):
    """OR ordinary predicates and one-level delegated predicates.

    ``handles`` owns the direct and delegation branches being projected.
    ``sponsor_handles`` supplies the complete ordinary-authority union inside
    each delegation branch and defaults to the same handles.
    """
    handles = tuple(handles)
    sponsor_handles = handles if sponsor_handles is None else tuple(sponsor_handles)
    if permission_model is None and isinstance(permission, Model):
        permission_model = permission._meta.concrete_model
    parts = []
    content_identity = _candidate_model(candidates)
    sponsor_records = None
    for handle in handles:
        plan = _plan_for_permission(handle, candidates, user, permission)
        if kind == 'complete':
            fn = handle.compiler.complete_exists
        else:
            fn = handle.compiler.group_exists
        part = _as_q(fn(plan, candidates, user, permission))
        delegated = None
        if kind == 'complete' and getattr(plan, 'delegations', None):
            if sponsor_records is None:
                sponsor_records = _ordinary_records(
                    sponsor_handles, candidates, permission_model,
                )
            delegated = _delegated_content_exists(
                tuple(plan.delegations), sponsor_records, user, permission,
                content_identity=content_identity,
                skipped=skipped,
            )
        wrapped = _apply_checked_user(
            _or_q(part, delegated), plan, user, skipped, permission,
            content_identity, permission_model, complete=(kind == 'complete'),
        )
        if wrapped is not None:
            parts.append(wrapped)
    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return reduce(or_, parts)


def granted(handles, candidates, user, permission, *, kind='complete',
            sponsor_handles=None, permission_model=None,
            skipped=()):
    """OR each applicable relationship-family handle's complete (or group) predicate.

    Core-owned aggregate: fold-family handles are omitted. Noun-blind
    among relationship handles: this builder does not know Trust, Group,
    Guardian, or ceiling. A valid compiler returning ``None`` is
    inapplicable and is omitted. Compiler exceptions propagate. An empty
    result is ``None`` so the caller may use the transitional undeclared
    fallback.

    Mixin instance / QuerySet evaluation uses ``_compile_granted`` on
    ``self._own_handle()`` so an extension family can still project
    through the mixin.

    ``permission`` may be a permission instance or an unevaluated lookup
    (``Subquery`` / ``OuterRef``). Expressions are not passed to
    ``plan_for``; the plan is selected by content and user terminals.

    Only relationship-family handles participate.
    """
    participating = _relationship_handles(handles)
    return _compile_granted(
        participating, candidates, user, permission, kind=kind,
        sponsor_handles=(
            participating if sponsor_handles is None
            else _relationship_handles(sponsor_handles)
        ),
        permission_model=permission_model,
        skipped=skipped,
    )


def _scope_prefix_lookups(record, scope_model):
    """Root-relative lookups to proper prefix nodes matching ``scope_model``.

    A proper prefix is a hop on ``content_path`` whose related model is
    ``scope_model`` and that is not the content terminal. Each item is
    ``(root-relative lookup, target attname)``. The attname is the
    hop's resolved identity (``to_field`` when set), not assumed to
    be ``pk``. Uses stored path names and ``_meta`` only (zero SQL).
    """
    path = record.content_path
    if not path:
        return ()
    current = record.root
    lookups = []
    last = len(path) - 1
    for index, name in enumerate(path):
        try:
            field = current._meta.get_field(name)
        except FieldDoesNotExist:
            return ()
        related, target_attname = _resolved_hop(field, 'content', path)
        if related._meta.concrete_model is scope_model and index != last:
            lookups.append((_lookup_text(path[:index + 1]), target_attname))
        current = related
    return tuple(lookups)


def _prefix_lookup_hops(lookup):
    return tuple(lookup.split('__'))


def _prefix_walk_position(record, lookup):
    """Where this prefix sits relative to an ``along=`` walk site.

    ``exact`` is a registration with no walk. ``before`` is an ancestor
    of the walk site on the content path. ``site`` is the walk site.
    ``after`` is a later proper prefix, still short of the content terminal.
    """
    walk = getattr(record, 'along', None)
    if walk is None:
        return 'exact'
    hops = _prefix_lookup_hops(lookup)
    walk_hops = tuple(walk.walk_path)
    if hops == walk_hops:
        return 'site'
    if len(hops) < len(walk_hops) and walk_hops[:len(hops)] == hops:
        return 'before'
    if hops[:len(walk_hops)] == walk_hops:
        return 'after'
    return 'exact'


def _prefix_partial_suffix(record, lookup):
    """Path from the walk site to this prefix, not including the site."""
    hops = _prefix_lookup_hops(lookup)
    return '__'.join(hops[len(record.along.walk_path):])


def _exact_prefix_exists(record, lookup, target_attname, user, permission,
                        content_identity):
    """Grant row whose stored prefix is the outer row."""
    inner = _bind_record_qs(
        record,
        user=user,
        permission=permission,
        correlation=Q(**{lookup: OuterRef(target_attname)}),
        content_identity=content_identity,
    )
    return Exists(inner)


def _ordinary_prefix_predicate(record, lookup, target_attname, user, permission,
                              content_identity):
    """One ordinary permitted-content predicate, including an ``along=`` walk."""
    position = _prefix_walk_position(record, lookup)
    if position in ('exact', 'before'):
        return _exact_prefix_exists(
            record, lookup, target_attname, user, permission, content_identity,
        )
    suffix = None
    if position == 'after':
        suffix = _prefix_partial_suffix(record, lookup)
    return _PrefixInForwardWalk(
        record, user, permission, target_attname,
        content_identity=content_identity,
        suffix_lookup=suffix,
    )


def _prefix_sponsor_q(record, sponsor_records, permission, content_identity,
                     prefix_model, candidate, lookup):
    """Sponsor ordinary-authority OR for one permitted-content prefix.

    Placed on the delegation row. An ordinary ``along=`` walk must reach
    the same prefix identity the delegation reaches. An ordinary row
    without ``along=`` keeps an exact prefix comparison. An ancestor of
    the walk site stays that stored prefix, including when the ordinary
    grant is the walk. A sponsor ``along=`` whose content suffix is longer
    than one reverse hop raises ``TrustsConfigurationError``, the same
    failure as the forward check.
    """
    parts = []
    for ordinary in sponsor_records:
        if not _sponsor_record_matches(ordinary, record):
            continue
        for ordinary_lookup, _attname in _scope_prefix_lookups(
            ordinary, prefix_model,
        ):
            ordinary_pos = _prefix_walk_position(ordinary, ordinary_lookup)
            if ordinary.along is not None:
                _reject_unsupported_delegated_suffix(ordinary.along)
                if ordinary_pos == 'site':
                    parts.append(_KeyedReach(
                        ordinary.along,
                        _sponsor_walk_seed(
                            ordinary, _shift_outer_ref(permission),
                            content_identity,
                        ),
                        F(_root_relative_column(
                            record.root, record.sponsor_field,
                        )),
                        candidate,
                    ))
                    continue
            if record.along is None:
                binding = OuterRef(lookup)
            else:
                binding = _shift_outer_ref(candidate)
            parts.append(Exists(_bind_record_qs(
                ordinary,
                content_identity=content_identity,
                user=OuterRef(record.sponsor_field),
                permission=_shift_outer_ref(permission),
                correlation=Q(**{ordinary_lookup: binding}),
            )))
    if not parts:
        return None
    return parts[0] if len(parts) == 1 else reduce(or_, parts)


def _delegation_prefix_reach_q(record, user, lookup, target_attname, candidate,
                              position):
    """Delegation row reaches this prefix."""
    if record.along is None or position == 'before':
        return Q(**{lookup: OuterRef(target_attname)})
    return Q(_KeyedReach(
        record.along,
        _delegation_walk_seed(record, user),
        F(record.root._meta.pk.attname),
        candidate,
    ))


def _delegation_prefix_exists(record, sponsor_records, user, permission,
                             content_identity, prefix_model, lookup,
                             target_attname, candidate, position,
                             skipped=()):
    """``EXISTS`` delegation row correlated to ``candidate``."""
    sponsor_q = _prefix_sponsor_q(
        record, sponsor_records, permission, content_identity, prefix_model,
        candidate, lookup,
    )

    def bound():
        combined = Q(**{
            record.delegate_field: _bind_terminal(user, 'delegate'),
        })
        combined &= _delegation_prefix_reach_q(
            record, user, lookup, target_attname, candidate, position,
        )
        return combined

    combined = _matched_delegation_q(
        record, sponsor_q, permission, skipped, bound,
    )
    if combined is None:
        return None
    return Exists(record.root._default_manager.filter(combined))


def _delegated_prefix_predicates(delegations, sponsor_records, user, permission,
                                prefix_model, *, content_identity,
                                skipped=()):
    """Permitted-content predicates for one-level delegated authority.

    The delegate is included on a prefix only where the delegation and
    the sponsor's ordinary permission both reach it. A second delegation
    level has no ordinary sponsor grant, so it contributes nothing. A
    delegated ``along=`` suffix longer than one reverse hop raises
    ``TrustsConfigurationError``, the same failure as the forward check.
    The caller applies the inactive-user gate before this helper runs.
    """
    parts = []
    for record in delegations:
        lookups = _scope_prefix_lookups(record, prefix_model)
        if not lookups:
            continue
        if record.along is not None:
            _reject_unsupported_delegated_suffix(record.along)
        for lookup, target_attname in lookups:
            position = _prefix_walk_position(record, lookup)
            candidate = OuterRef(target_attname)
            found = _delegation_prefix_exists(
                record, sponsor_records, user, permission, content_identity,
                prefix_model, lookup, target_attname, candidate, position,
                skipped=skipped,
            )
            if found is not None:
                parts.append(found)
    return parts


def _compile_permitted_content_queryset(
    queryset, user, permission, *, content, handles, sponsor_handles,
    skipped=(),
):
    """Compile the permitted-content queryset for resolved handles.

    ``handles`` owns the ordinary and delegation branches being listed.
    ``sponsor_handles`` supplies the ordinary grants a delegation may
    use. Callers resolve relationship handles and apply the inactive-user
    gate before this helper runs.
    """
    handles = tuple(handles)
    sponsor_handles = tuple(sponsor_handles)
    scope_model = queryset.model._meta.concrete_model

    parts = []
    content_identity = _candidate_model(content)
    for handle in handles:
        plan = _plan_for_permission(handle, content, user, permission)
        if getattr(plan, 'content_identity', None) is not None:
            content_identity = plan.content_identity
        plan_parts = []
        for record in plan.records:
            for lookup, target_attname in _scope_prefix_lookups(
                record, scope_model,
            ):
                plan_parts.append(_ordinary_prefix_predicate(
                    record, lookup, target_attname, user, permission,
                    content_identity,
                ))
        if getattr(plan, 'delegations', None):
            plan_parts.extend(_delegated_prefix_predicates(
                tuple(plan.delegations),
                _ordinary_records(
                    sponsor_handles, content, permission._meta.concrete_model,
                ),
                user, permission, scope_model,
                content_identity=content_identity,
                skipped=skipped,
            ))
        grant = None
        if plan_parts:
            grant = (
                plan_parts[0] if len(plan_parts) == 1
                else reduce(or_, plan_parts)
            )
        wrapped = _apply_checked_user(
            grant, plan, user, skipped, permission, content_identity,
            permission._meta.concrete_model
            if isinstance(permission, Model) else plan.permission_model,
            complete=True,
        )
        if wrapped is not None:
            parts.append(wrapped)
    if not parts:
        return queryset.none()
    granted_q = parts[0] if len(parts) == 1 else reduce(or_, parts)
    return bind_once(queryset.filter(granted_q).distinct())


def filter_by_permitted_content(queryset, user, permission, *, content, handles=None,
                                **skip_flags):
    """Filter scope-model rows that appear as a proper prefix of ``content``.

    Fail closed unless ``queryset.model`` is a proper prefix node of some
    applicable record's ``content_path`` whose content terminal is
    ``content``. Compile ``EXISTS`` of root rows correlated to
    ``OuterRef`` of that hop's resolved target field (the related
    ``attname`` from ``get_path_info()``, which need not be ``pk``) at
    that node, bind user + permission from the same record, and OR
    applicable records.

    An ``along=`` registration uses the same bounded ``WITH RECURSIVE``
    walk as the forward check. A prefix at the walk site is kept when
    its identity is in that walk. A later proper prefix is kept when it
    hangs off a walk-site row in the walk. A one-level delegation
    contributes a prefix only when the delegation and the sponsor's
    ordinary permission both reach it. A second delegation level does
    not. A delegated ``along=`` whose content suffix is longer than one
    reverse hop raises ``TrustsConfigurationError``.

    ``queryset.model`` equal to the content terminal is allowed when a
    proper prefix hop of that same model exists (self-referential
    trees). A terminal-only path has no proper prefix, so the same-model
    queryset still returns ``none()``. Unknown terminal, empty handles,
    or a scope model not on the path also return ``none()``.
    ``permission`` must be a model instance. Construction of a
    fail-closed result issues zero SQL; SQL runs only when a compiled
    predicate is evaluated. Default and explicit handle lists include
    relationship-family handles only.

    Noun-blind: this builder does not import or name Zero schema models
    and does not use a compiler's historical group
    OR. Explicit ``group=`` records participate through the same prefix
    correlation. Membership shape is not a group.
    """
    if not isinstance(queryset, QuerySet):
        raise TrustsConfigurationError(
            'filter_by_permitted_content requires a QuerySet, not %r.'
            % (queryset,)
        )
    if handles is None:
        from trusts.apps import _relationship_implementation_handles
        handles = _relationship_implementation_handles()
    else:
        handles = _relationship_handles(handles)
    user = _require_instance(user, 'user')
    permission = _require_instance(permission, 'permission')
    inquiry = bind_checked_user(user, skip_flags=skip_flags, handles=handles)
    if not handles or inquiry.denied:
        return queryset.none()
    skipped = inquiry.values
    return _compile_permitted_content_queryset(
        queryset, user, permission, content=content, handles=handles,
        sponsor_handles=handles,
        skipped=skipped,
    )


def filter_authorized_scopes(queryset, user, permission, *, content, handles=None,
                             **skip_flags):
    return filter_by_permitted_content(
        queryset, user, permission, content=content, handles=handles,
        **skip_flags,
    )


def _path_text(path):
    return '.'.join(path)


def _materialize_related_model(field):
    """Resolve a still-string ``remote_field.model`` through the app registry.

    Isolated ``ForeignKey(settings.AUTH_USER_MODEL)`` fields keep a string
    until Django's lazy related-class hook runs. Path information needs the
    model class. ``apps.get_model`` is metadata only (zero SQL).
    """
    remote = getattr(field, 'remote_field', None)
    if remote is None:
        return
    model = getattr(remote, 'model', None)
    if isinstance(model, ModelBase):
        return
    related = getattr(field, 'related_model', None)
    if isinstance(related, str) or related is None:
        label = related if isinstance(related, str) else model
        if isinstance(label, str):
            try:
                related = django_apps.get_model(label)
            except (LookupError, ValueError):
                return
    if isinstance(related, ModelBase):
        try:
            remote.model = related
        except (AttributeError, TypeError):
            return


def _resolved_hop(field, role, path):
    """Resolve one hop from Django path information.

    Requires exactly one ``PathInfo`` and exactly one target field.
    Terminal model and outer comparison field come from that metadata.
    """
    _materialize_related_model(field)
    getter = getattr(field, 'get_path_info', None)
    if not callable(getter):
        raise TrustsConfigurationError(
            '%s path %r has no resolvable path information.'
            % (role, _path_text(path))
        )
    infos = getter()
    if infos is None:
        infos = ()
    infos = tuple(infos)
    if len(infos) != 1:
        raise TrustsConfigurationError(
            '%s path %r does not resolve to exactly one relation hop; '
            'composite and multi-join relations are not supported.'
            % (role, _path_text(path))
        )
    info = infos[0]
    target_fields = getattr(info, 'target_fields', None) or ()
    if len(target_fields) != 1:
        raise TrustsConfigurationError(
            '%s path %r exposes %s target fields; composite and '
            'multi-column correlation are not supported.'
            % (role, _path_text(path), len(target_fields))
        )
    to_opts = getattr(info, 'to_opts', None)
    related = None
    if to_opts is not None:
        related = getattr(to_opts, 'concrete_model', None) or getattr(
            to_opts, 'model', None
        )
    if not isinstance(related, ModelBase):
        raise TrustsConfigurationError(
            '%s path %r does not terminate on a model.'
            % (role, _path_text(path))
        )
    target = target_fields[0]
    attname = getattr(target, 'attname', None)
    if not attname:
        raise TrustsConfigurationError(
            '%s path %r does not expose one supported target field.'
            % (role, _path_text(path))
        )
    return related._meta.concrete_model, attname


def _shift_outer_ref(value):
    """Add one correlation level to a symbolic outer reference."""
    if isinstance(value, OuterRef):
        return OuterRef(value)
    return value


def _ordinary_records(handles, content, permission_model=None):
    """Applicable ordinary records across relationship handles."""
    records = []
    for handle in handles:
        plan = handle.registry.plan_for(content)
        for record in plan.records:
            if (
                permission_model is not None
                and record.permission_model is not permission_model
            ):
                continue
            records.append(record)
    return tuple(records)


def _root_relative_column(model, path):
    """Concrete column lookup for a forward single-valued path.

    ``sponsor`` becomes ``sponsor_id``. ``sponsor_link__user`` becomes
    ``sponsor_link__user_id``. Every prefix stays on the path, so ``F()``
    cannot bind a bare ``user_id`` on the delegation root. The last
    component is that field's attname: the column that stores the
    comparison identity, including a non-PK ``to_field``. The path was
    already resolved at registration.
    """
    parts = str(path).split('__')
    current = model
    prefix = []
    field = None
    for index, name in enumerate(parts):
        field = current._meta.get_field(name)
        if index == len(parts) - 1:
            break
        prefix.append(name)
        current = field.related_model
    return '__'.join(prefix + [field.attname])


def _reject_unsupported_delegated_suffix(walk):
    """Longer than one reverse content hop is not one content column.

    One reverse hop rewrites onto ``rewrite_attname``. A longer suffix
    is fail-closed on both the forward and reverse checks. This does
    not implement that walk.
    """
    if walk is None or not walk.suffix_path or walk.rewrite_attname:
        return
    raise TrustsConfigurationError(
        'Delegated along= cannot compile suffix path %r; the walk '
        'identity is not one column of the content row.'
        % _path_text(walk.suffix_path)
    )


def _candidate_outer_ref(walk):
    """Outer content column that stores this walk's identity.

    No suffix: the content row is the walk-site, so the column is the
    walk identity. One reverse suffix hop rewrites that comparison onto
    the content row's foreign key (``rewrite_attname``). A longer suffix
    is not a single column on the content row.
    """
    if walk.rewrite_attname:
        return OuterRef(walk.rewrite_attname)
    _reject_unsupported_delegated_suffix(walk)
    return OuterRef(walk.walk_ident)


def _delegation_sponsor_q(record, sponsor_records, permission, content_identity,
                          *, forward=True, bound_content=None):
    """Sponsor ordinary-authority OR, correlated to one delegation row.

    An ordinary row without ``along`` keeps an exact content comparison.
    When the delegation row itself does not walk, that comparison is the
    delegation's content column, which equals the requested object. When
    the delegation walks, the sponsor must reach the requested object,
    not the delegation anchor. An ordinary ``along`` row instead requires
    the sponsor's walked grant to reach that same object.
    """
    parts = []
    if record.along is None:
        content_binding = OuterRef(record.content_field)
    elif forward:
        content_binding = _shift_outer_ref(OuterRef(record.content_target))
    else:
        content_binding = bound_content
    for ordinary in sponsor_records:
        if not _sponsor_record_matches(ordinary, record):
            continue
        if ordinary.along is None:
            inner = _bind_record_qs(
                ordinary,
                content_identity=content_identity,
                user=OuterRef(record.sponsor_field),
                content=content_binding,
                permission=_shift_outer_ref(permission),
            )
            parts.append(Exists(inner))
            continue
        if forward:
            parts.append(_KeyedReach(
                ordinary.along,
                _sponsor_walk_seed(
                    ordinary, _shift_outer_ref(permission), content_identity,
                ),
                F(_root_relative_column(record.root, record.sponsor_field)),
                _candidate_outer_ref(ordinary.along),
            ))
            continue
        parts.append(GrantReach(
            ordinary,
            OuterRef(record.sponsor_field),
            _shift_outer_ref(permission),
            content=bound_content,
            content_identity=content_identity,
        ))
    if not parts:
        return None
    return parts[0] if len(parts) == 1 else reduce(or_, parts)


def _delegation_reaches(record, *, forward, user=None, content=None):
    """Equality, or the delegation row's own bounded walk, to the object."""
    _reject_unsupported_delegated_suffix(record.along)
    if record.along is None:
        if forward:
            return Q(**{record.content_field: OuterRef(record.content_target)})
        return Q(**{record.content_field: content})
    if forward:
        return Q(_KeyedReach(
            record.along,
            _delegation_walk_seed(record, user),
            F(record.root._meta.pk.attname),
            _candidate_outer_ref(record.along),
        ))
    return Q(_AnchorInInverseReach(record, content))


def _delegated_content_exists(delegations, sponsor_records, user, permission,
                              *, content_identity=None, skipped=()):
    """Candidate-content predicate for one-level delegated authority."""
    parts = []
    for record in delegations:
        sponsor_q = _delegation_sponsor_q(
            record, sponsor_records, permission, content_identity,
        )

        def bound(record=record):
            combined = Q(**{
                record.delegate_field: _bind_terminal(user, 'delegate'),
            })
            combined &= _delegation_reaches(record, forward=True, user=user)
            return combined

        combined = _matched_delegation_q(
            record, sponsor_q, permission, skipped, bound,
        )
        if combined is None:
            continue
        parts.append(Exists(record.root._default_manager.filter(combined)))
    if not parts:
        return None
    return parts[0] if len(parts) == 1 else reduce(or_, parts)

