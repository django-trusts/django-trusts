"""Content grants and the permitted-content compiler.

``granted`` is defined here. The permitted-content queryset compiler
is private; the public filter lives in ``trusts.decorators``.
"""

__all__ = []

from functools import reduce
from operator import or_

from django.core.exceptions import FieldDoesNotExist
from django.db.models import Exists, F, Model, OuterRef, Q, Subquery

from trusts.plan.rewrites import bind_once
from trusts.plan.hops import lookup_text, path_text, resolved_hop
from trusts.plan.predicates import bind_record_qs, bind_terminal
from trusts.errors import TrustsConfigurationError
from trusts.plan.delegations import (
    _matched_delegation_q,
    _sponsor_record_matches,
)
from trusts.plan.walk import (
    _delegation_walk_seed,
    _sponsor_walk_seed,
)
from trusts.plan.recursions import (
    GrantReach,
    _AnchorInInverseReach,
    _KeyedReach,
    _PrefixInForwardWalk,
)
from trusts.plan.via import (
    bind_grant_qs,
    delegate_q,
    delegate_user_q,
    sponsor_constraint,
    via_scope,
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


def _and_predicate(left, right):
    """AND two grant predicates. ``None`` on the left stays inapplicable."""
    if left is None:
        return None
    return _as_q(left) & _as_q(right)


def _is_reverse_relation(field):
    return bool(
        getattr(field, 'auto_created', False)
        and not getattr(field, 'concrete', False)
    )


def _content_scope_lookup(record, prefix_lookup, target_attname):
    """Content-model lookup equal to the outer scope row's identity.

    The lookup walks back from the protected object to this prefix.
    A forward hop uses the reverse accessor. A reverse hop uses the
    foreign key that points at the scope row.
    """
    names = tuple(prefix_lookup.split('__'))
    path = tuple(record.content_path)
    suffix = path[len(names):]
    current = record.root
    for name in names:
        field = current._meta.get_field(name)
        current, _attname = resolved_hop(field, 'content', path)
    steps = []
    for name in suffix:
        field = current._meta.get_field(name)
        if getattr(field, 'many_to_many', False):
            raise TrustsConfigurationError(
                'filter_by_permitted_content cannot apply a content '
                'filter through many-to-many hop %r.' % name
            )
        steps.append(field)
        current, _attname = resolved_hop(field, 'content', path)
    parts = []
    for index, field in enumerate(reversed(steps)):
        last = index == len(steps) - 1
        if _is_reverse_relation(field):
            fk = field.field
            parts.append(fk.attname if last else fk.name)
            continue
        if not getattr(field, 'concrete', False) or not field.is_relation:
            raise TrustsConfigurationError(
                'filter_by_permitted_content cannot apply a content '
                'filter through %r.' % prefix_lookup
            )
        accessor = field.remote_field.get_accessor_name()
        if last:
            parts.append('%s__%s' % (accessor, target_attname))
        else:
            parts.append(accessor)
    return '__'.join(parts)


def _content_under_outer(record, lookup, target_attname, overlay):
    """Filtered content rows that sit on this outer prefix row."""
    correlation = _content_scope_lookup(record, lookup, target_attname)
    return Exists(record.content_model._default_manager.filter(overlay).filter(
        **{correlation: OuterRef(target_attname)},
    ))


def _this_grant_seed(record):
    """Walk seed for the grant row that contains this subquery."""
    walk = record.along
    rows = record.root._default_manager.filter(pk=OuterRef(OuterRef('pk')))
    if walk.walk_ident == 'ident':
        seed = rows.values(walk.walk_field).distinct()
    else:
        seed = rows.values(ident=F(walk.walk_field)).distinct()
    query = seed.query.clone()
    query.subquery = True
    return query


def _grant_reaches_filtered_content(record, overlay):
    """This grant row authorizes a content row that passes ``overlay``."""
    return Exists(record.content_model._default_manager.filter(overlay).filter(
        Q(GrantReach(record, seed_query=_this_grant_seed(record))),
    ))


def _outer_column(name, depth):
    """``name`` on a query ``depth`` levels outside the current one."""
    ref = name
    for _index in range(depth):
        ref = OuterRef(ref)
    return ref


def _walk_seed_from_rows(walk, rows):
    """Reach seed selecting this walk's identity from ``rows``."""
    if walk.walk_ident == 'ident':
        seed = rows.values(walk.walk_field).distinct()
    else:
        seed = rows.values(ident=F(walk.walk_field)).distinct()
    query = seed.query.clone()
    query.subquery = True
    return query


def _sponsor_rows_for_handoff(delegation, ordinary, permission,
                              content_identity, lookup, ordinary_lookup, *,
                              depth):
    """Sponsor grants on the same prefix as the delegation row.

    The comparison is the prefix value stored on that row, so a grant
    on another copy of the prefix does not authorize this sheet.
    ``depth`` is 2 when these rows are the seed of a walk expression
    on the sheet query, and 1 when they are a direct subquery of it.
    A single stored foreign key compares columns. A longer lookup reads
    the handoff's prefix through a subquery nested one level deeper.
    """
    handoff_column = _stored_prefix_column(delegation.root, lookup)
    grant_column = _stored_prefix_column(ordinary.root, ordinary_lookup)
    if handoff_column is not None and grant_column is not None:
        correlation = Q(**{
            grant_column: _outer_column(handoff_column, depth),
        })
    else:
        prefix_on_handoff = Subquery(
            delegation.root._default_manager.filter(
                pk=_outer_column('pk', depth + 1),
            ).values(lookup)[:1]
        )
        correlation = Q(**{_root_relative_column(
            ordinary.root, ordinary_lookup,
        ): prefix_on_handoff})
    return bind_record_qs(
        ordinary,
        permission=permission,
        content_identity=content_identity,
        user=_outer_column(delegation.sponsor_field, depth),
        correlation=correlation,
    )


def _stored_prefix_column(model, lookup):
    """Attname when ``lookup`` is one foreign key stored on ``model``."""
    if not lookup or '__' in lookup:
        return None
    try:
        field = model._meta.get_field(lookup)
    except FieldDoesNotExist:
        return None
    if (
        not getattr(field, 'concrete', False)
        or not getattr(field, 'is_relation', False)
        or getattr(field, 'many_to_many', False)
    ):
        return None
    return field.attname


def _same_sheet_in_both_walks(delegation, sponsor_records, permission,
                              content_identity, prefix_model, lookup, overlay):
    """One filtered sheet is in the delegation walk and the sponsor walk.

    Two separate ``EXISTS`` checks can match different sheets and list
    the prefix. The sheet query holds both walks, so one row has to
    satisfy the filter and both reaches. Each walk seed is correlated
    outside its recursive member.
    """
    sheet = delegation.content_model._default_manager.filter(overlay)
    sheet = sheet.filter(Q(GrantReach(
        delegation, seed_query=_this_grant_seed(delegation),
    )))
    sponsor_parts = []
    for ordinary in sponsor_records:
        if not _sponsor_record_matches(ordinary, delegation):
            continue
        ordinary_lookups = _scope_prefix_lookups(ordinary, prefix_model)
        if ordinary.along is not None:
            _reject_unsupported_delegated_suffix(ordinary.along)
        for ordinary_lookup, ordinary_attname in ordinary_lookups:
            if ordinary.along is not None:
                rows = _sponsor_rows_for_handoff(
                    delegation, ordinary, permission, content_identity,
                    lookup, ordinary_lookup, depth=2,
                )
                sponsor_parts.append(Q(GrantReach(
                    ordinary,
                    seed_query=_walk_seed_from_rows(ordinary.along, rows),
                )))
                continue
            rows = _sponsor_rows_for_handoff(
                delegation, ordinary, permission, content_identity,
                lookup, ordinary_lookup, depth=1,
            )
            correlation = _content_scope_lookup(
                ordinary, ordinary_lookup, ordinary_attname,
            )
            prefix_on_handoff = Subquery(
                delegation.root._default_manager.filter(
                    pk=OuterRef('pk'),
                ).values(lookup)[:1]
            )
            sponsor_parts.append(
                Q(**{correlation: prefix_on_handoff}) & Exists(rows)
            )
    if not sponsor_parts:
        return Exists(sheet.none())
    reached = (
        sponsor_parts[0] if len(sponsor_parts) == 1
        else reduce(or_, sponsor_parts)
    )
    return Exists(sheet.filter(reached))


def _plan_for_permission(catalog, candidates, user, permission):
    if isinstance(permission, Model):
        return catalog.plan_for(
            candidates, user=user, permission=permission,
        )
    return catalog.plan_for(candidates, user=user)


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


def _compile_granted(catalog, candidates, user, permission, *, kind='complete',
                     permission_model=None, skipped=()):
    """Ordinary predicate and one-level delegated predicate for ``catalog``.

    A delegation's sponsor rows are this catalog's ordinary records.
    """
    with via_scope(catalog, skipped):
        return _compile_granted_body(
            catalog, candidates, user, permission, kind=kind,
            permission_model=permission_model, skipped=skipped,
        )


def _compile_granted_body(catalog, candidates, user, permission, *, kind,
                          permission_model, skipped):
    if permission_model is None and isinstance(permission, Model):
        permission_model = permission._meta.concrete_model
    content_identity = _candidate_model(candidates)
    plan = _plan_for_permission(catalog, candidates, user, permission)
    compiler = plan.query_compiler
    if kind == 'complete':
        fn = compiler.complete_exists
    else:
        fn = compiler.group_exists
    part = _as_q(fn(plan, candidates, user, permission))
    delegated = None
    if kind == 'complete' and plan.delegations:
        delegated = _delegated_content_exists(
            tuple(plan.delegations),
            _ordinary_records(catalog, candidates, permission_model),
            user, permission,
            content_identity=content_identity,
            skipped=skipped,
        )
    return _apply_checked_user(
        _or_q(part, delegated), plan, user, skipped, permission,
        content_identity, permission_model, complete=(kind == 'complete'),
    )


def granted(catalog, candidates, user, permission, *, kind='complete',
            permission_model=None, skipped=()):
    """This relationship-family catalog's complete (or group) predicate.

    A valid compiler returning ``None`` is inapplicable. A user that is
    not a model instance returns ``None``. Compiler exceptions for a
    real inquiry propagate. An empty result is ``None``. A catalog whose
    family is not relationship returns ``None``.

    ``permission`` may be a permission instance or an unevaluated lookup
    (``Subquery`` / ``OuterRef``). Expressions are not passed to
    ``plan_for``; the plan is selected by content and user terminals.
    """
    if catalog.family != 'relationship' or not isinstance(user, Model):
        return None
    return _compile_granted(
        catalog, candidates, user, permission, kind=kind,
        permission_model=permission_model,
        skipped=skipped,
    )


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
                        content_identity, grant_q=None):
    """Grant row whose stored prefix is the outer row."""
    inner = bind_grant_qs(
        record,
        user=user,
        permission=permission,
        correlation=Q(**{lookup: OuterRef(target_attname)}),
        content_identity=content_identity,
    )
    if grant_q is not None:
        inner = inner.filter(grant_q)
    return Exists(inner)


def _apply_content_overlay(predicate, record, lookup, target_attname, position,
                           content_overlay):
    """Keep a prefix only when filtered content sits on that same proof.

    An ancestor of an ``along=`` walk is the grant's stored prefix. The
    walk, not the content row's own parent, decides which objects that
    grant authorizes, so that case filters inside the grant. Every other
    prefix is the content path of the outer row.
    """
    if content_overlay is None or predicate is None:
        return predicate
    if position == 'before' and getattr(record, 'along', None) is not None:
        return predicate
    return _and_predicate(
        predicate,
        _content_under_outer(
            record, lookup, target_attname, content_overlay,
        ),
    )


def _ordinary_prefix_predicate(record, lookup, target_attname, user, permission,
                              content_identity, content_overlay=None):
    """One ordinary permitted-content predicate, including an ``along=`` walk."""
    position = _prefix_walk_position(record, lookup)
    if position in ('exact', 'before'):
        grant_q = None
        if (
            content_overlay is not None
            and position == 'before'
            and record.along is not None
        ):
            grant_q = _grant_reaches_filtered_content(
                record, content_overlay,
            )
        predicate = _exact_prefix_exists(
            record, lookup, target_attname, user, permission,
            content_identity, grant_q=grant_q,
        )
        return _apply_content_overlay(
            predicate, record, lookup, target_attname, position,
            content_overlay,
        )
    suffix = None
    if position == 'after':
        suffix = _prefix_partial_suffix(record, lookup)
    predicate = _PrefixInForwardWalk(
        record, user, permission, target_attname,
        content_identity=content_identity,
        suffix_lookup=suffix,
    )
    return _apply_content_overlay(
        predicate, record, lookup, target_attname, position, content_overlay,
    )


def _sponsor_reached(delegation, ordinary, permission, content_identity, *,
                     content=None, correlation=None, forward=True,
                     candidate=None, bound_content=None, along_walk=False):
    """Sponsor-user walk in place of equality, or ``None`` to keep equality."""
    constraint = sponsor_constraint(delegation, ordinary)
    if constraint is None:
        return None
    permission = _shift_outer_ref(permission)
    if along_walk:
        _reject_unsupported_delegated_suffix(ordinary.along)
    if along_walk and forward:
        target = (
            candidate if candidate is not None
            else _candidate_outer_ref(ordinary.along)
        )
        return _KeyedReach(
            ordinary.along,
            _sponsor_walk_seed(
                ordinary, permission, content_identity,
                constraint=constraint,
                carrier=F(ordinary.root._meta.pk.attname),
            ),
            None,
            target,
        )
    if along_walk:
        return GrantReach(
            ordinary,
            None,
            permission,
            content=bound_content,
            content_identity=content_identity,
            user_q=constraint,
        )
    kwargs = {
        'content_identity': content_identity,
        'permission': permission,
    }
    if content is not None:
        kwargs['content'] = content
    if correlation is not None:
        kwargs['correlation'] = correlation
    return Exists(bind_record_qs(ordinary, **kwargs).filter(constraint))


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
            reached = _sponsor_reached(
                record, ordinary, permission, content_identity,
                correlation=Q(**{ordinary_lookup: (
                    OuterRef(lookup) if record.along is None
                    else _shift_outer_ref(candidate)
                )}),
                forward=True,
                candidate=candidate,
                along_walk=(
                    ordinary.along is not None and ordinary_pos == 'site'
                ),
            )
            if reached is not None:
                parts.append(reached)
                continue
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
            parts.append(Exists(bind_record_qs(
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
        _delegation_walk_seed(
            record, user, user_q=delegate_user_q(record, user),
        ),
        F(record.root._meta.pk.attname),
        candidate,
    ))


def _delegation_prefix_exists(record, sponsor_records, user, permission,
                             content_identity, prefix_model, lookup,
                             target_attname, candidate, position,
                             skipped=(), content_overlay=None):
    """``EXISTS`` delegation row correlated to ``candidate``."""
    sponsor_q = _prefix_sponsor_q(
        record, sponsor_records, permission, content_identity, prefix_model,
        candidate, lookup,
    )

    def bound():
        combined = delegate_q(record, user)
        combined &= _delegation_prefix_reach_q(
            record, user, lookup, target_attname, candidate, position,
        )
        return combined

    combined = _matched_delegation_q(
        record, sponsor_q, permission, skipped, bound,
    )
    if combined is None:
        return None
    if (
        content_overlay is not None
        and position == 'before'
        and record.along is not None
    ):
        combined &= _same_sheet_in_both_walks(
            record, sponsor_records, permission, content_identity,
            prefix_model, lookup, content_overlay,
        )
    return Exists(record.root._default_manager.filter(combined))


def _delegated_prefix_predicates(delegations, sponsor_records, user, permission,
                                prefix_model, *, content_identity,
                                skipped=(), content_overlay=None):
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
                skipped=skipped, content_overlay=content_overlay,
            )
            if found is not None:
                parts.append(_apply_content_overlay(
                    found, record, lookup, target_attname, position,
                    content_overlay,
                ))
    return parts


def permitted_content_q(scope_model, user, permission, *, content, catalog,
                        skipped=(), content_overlay=None, on_content=False):
    """Grant ``Q`` for scope rows that prefix ``content``, or ``None``.

    ``content_overlay`` is the selected named filters. ``on_content``
    means that overlay reads the protected object, so it constrains the
    content row under each prefix. Otherwise it is a user or permission
    check and combines with the scope predicate.
    """
    with via_scope(catalog, skipped):
        wrapped = _permitted_content_body(
            scope_model, user, permission, content=content, catalog=catalog,
            skipped=skipped,
            content_overlay=content_overlay if on_content else None,
        )
    if content_overlay is not None and not on_content and wrapped is not None:
        wrapped = _as_q(wrapped) & content_overlay
    return wrapped


def _permitted_content_body(scope_model, user, permission, *, content, catalog,
                            skipped, content_overlay=None):
    scope_model = scope_model._meta.concrete_model
    content_identity = _candidate_model(content)
    plan = _plan_for_permission(catalog, content, user, permission)
    if plan.content_identity is not None:
        content_identity = plan.content_identity
    plan_parts = []
    for record in plan.records:
        for lookup, target_attname in _scope_prefix_lookups(
            record, scope_model,
        ):
            plan_parts.append(_ordinary_prefix_predicate(
                record, lookup, target_attname, user, permission,
                content_identity, content_overlay=content_overlay,
            ))
    if plan.delegations:
        plan_parts.extend(_delegated_prefix_predicates(
            tuple(plan.delegations),
            _ordinary_records(
                catalog, content, permission._meta.concrete_model,
            ),
            user, permission, scope_model,
            content_identity=content_identity,
            skipped=skipped, content_overlay=content_overlay,
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
    return wrapped


def bind_filtered_queryset(queryset, predicate, *, user_model):
    if predicate is None:
        return queryset.none()
    return bind_once(
        queryset.filter(predicate).distinct(), user_model=user_model,
    )


def _compile_permitted_content_queryset(
    queryset, user, permission, *, content, catalog, skipped=(),
    content_overlay=None, on_content=False,
):
    wrapped = permitted_content_q(
        queryset.model, user, permission, content=content, catalog=catalog,
        skipped=skipped, content_overlay=content_overlay,
        on_content=on_content,
    )
    return bind_filtered_queryset(
        queryset, wrapped, user_model=catalog.user_model,
    )


def _shift_outer_ref(value):
    """Add one correlation level to a symbolic outer reference."""
    if isinstance(value, OuterRef):
        return OuterRef(value)
    return value


def _ordinary_records(catalog, content, permission_model=None):
    """Applicable ordinary records on this catalog's own plan."""
    records = []
    plan = catalog.plan_for(content)
    for record in plan.records:
        if (
            permission_model is not None
            and record.permission_model is not permission_model
        ):
            continue
        records.append(record)
    return tuple(records)


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
        % path_text(walk.suffix_path)
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
        reached = _sponsor_reached(
            record, ordinary, permission, content_identity,
            content=content_binding if ordinary.along is None else None,
            forward=forward,
            bound_content=bound_content,
            along_walk=ordinary.along is not None,
        )
        if reached is not None:
            parts.append(reached)
            continue
        if ordinary.along is None:
            inner = bind_record_qs(
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
            _delegation_walk_seed(
                record, user, user_q=delegate_user_q(record, user),
            ),
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
            combined = delegate_q(record, user)
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
        related, target_attname = resolved_hop(field, 'content', path)
        if related._meta.concrete_model is scope_model and index != last:
            lookups.append((lookup_text(path[:index + 1]), target_attname))
        current = related
    return tuple(lookups)

