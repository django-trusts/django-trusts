"""Isolated registration and common authorization-plan compiler.

``TrustsRegistry`` validates root-relative ``Ref`` paths through Django
model ``_meta`` and stores immutable records. More than one normalized
registration may share one permission-bearing root when they terminate
on different content models. The same registered records compile into
one correlated relation plan. Three projections change only the
terminal: permission enumeration, object authorization (SQL ``EXISTS``
membership over that enumeration), and authorized-content filtering.

Optional ``Along`` replaces equality at one walk-site with bounded
grant-anchored reachability. V1 compiles that walk only for Django's
SQLite backend.

Closed predicate nodes ``All``, ``Equal``, and ``permission_in`` are the
private stored overlay on one permission-bearing root. Public
``register(*, trust=..., condition=...)`` accepts only a one-argument
trust-rooted symbolic callable (path ``==``, collection-rooted
``.contains(member)``, conjunction with ``&``) and lowers to those
nodes. A requester path may end in exactly one terminal M2M membership
hop after zero or more forward single-valued hops. Validation is
registration-time ``_meta`` only (zero SQL).

The configured backend exposes two public registration methods.
``register(*, trust=...)`` is the AnyPath ``EXISTS`` fast path.
``add_named_filter`` binds a named restricting predicate and is not
an authorization source. Core is relationship-only. OrderedFold
construction, registration, and PostgreSQL remaining-bits rendering
live in ``django-trusts-ordered-fold``. Core does not import, depend
on, auto-discover, or fallback-import that package.

When the permission terminal's concrete model is Django's
``auth.Permission``, the shared grant requires that row's content type
to be the protected object's content identity. Proxy models keep their
own. A mismatch is an empty predicate, not an error. Any other
terminal, including a custom model that has a ``content_type`` foreign
key, stays primary-key identity. The codename is not parsed to guess
the model.

Import from ``trusts.core``. This slice does not re-export a process-global
registry from ``trusts``. Generic compiler protocol, the default plan
compiler, ``any_plan_records()``, ``granted()``, ``all_match()``,
``common_permissions()``, ``filter_by_permitted_content()``,
``ConditionLookup``, and configuration/compiler exceptions live here.
Permission-condition *records* live on each ``TrustsRegistry`` via
``trusts.plan.conditions.ConditionRegistry``. Construction self-binds
the private store adapter; ``set_condition_lookup`` remains for
tests and explicit unbind.
"""

from functools import reduce
from operator import or_
from typing import TypeVar

from django.db.models import Count, Exists, Model, OuterRef, Q

from trusts._bind_once import bind_once
from trusts.compile.factory import (
    assemble_frozen,
    TrustsRegistry,
    RegisteredDelegation,
    RegisteredRelation,
    _ALONG_BOUND_MAX,
    _ALONG_BOUND_MIN,
    _INTEGER_IDENTITY_TYPES,
    _SUFFIX_KINDS,
    _SUFFIX_MAX,
    _TEXT_IDENTITY_TYPES,
    _UUID_IDENTITY_TYPES,
    _append_group_permissions,
    _bind_public_along,
    _build_along_walk,
    _classify_field,
    _common_prefix,
    _concrete_fk,
    _concrete_model,
    _content_model,
    _delegated_condition_arity,
    _flatten_public_all,
    _generic_relation_types,
    _group_permissions_field,
    _ident_family,
    _lower_public_condition,
    _m2m_related_model,
    _m2m_related_target_attname,
    _normalize_delegated_condition,
    _normalize_public_condition,
    _normalize_public_role,
    _permission_m2m_result,
    _public_condition_path,
    _public_path_segments,
    _public_ref,
    _re_resolve_suffix,
    _reject_public_condition_value,
    _require_condition_arity,
    _require_one_permission_source,
    _resolve_along_edge,
    _resolve_forward_singles,
    _resolve_group_path,
    _resolve_m2m_terminal,
    _resolve_path,
    _resolve_permission_in_m2m,
    _resolve_permission_in_path,
    _resolve_permission_path,
    _same_terminal_bindings,
    _suffix_rewrite_attname,
    _target_field,
    _validate_condition,
    _validate_delegated_condition,
    _validate_equal,
    _validate_permission_in,
    probe_along_capabilities,
)
from trusts.compile.nodes import (
    All,
    Along,
    Equal,
    PermissionIn,
    Ref,
    _InquiryPermissionMatch,
    _is_condition_operand,
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
from trusts.commons import (
    _ALONG_ENGINES,
    _BINDING_FIELDS,
    _DJANGO_SQLITE3,
    _along_cycle_clause,
    _auth_group_and_permission,
    _bind_record_qs,
    _bind_terminal,
    _compile_predicate,
    _content_type_identity,
    _content_walk_seed,
    _grant_walk_attname,
    _inverse_neighbor_sql,
    _is_lookup_expression,
    _lookup_text,
    _neighbor_sql,
    _permission_content_type_filters,
    _permission_terminal_is_auth_permission,
    _record_predicate,
    _render_reach_sql,
    _require_along_renderer,
    _require_instance,
    along_connection_supported,
)
from trusts.errors import TrustsCompilerError, TrustsConfigurationError
from trusts.plan.handles import BackendHandle
from trusts.plan.registry import FrozenRegistry as _FrozenRegistry
from trusts.plan.contents import (
    _apply_checked_user,
    _as_q,
    _candidate_outer_ref,
    _compile_granted,
    _compile_permitted_content_queryset,
    _delegated_content_exists,
    _delegated_prefix_predicates,
    _delegation_prefix_exists,
    _delegation_prefix_reach_q,
    _delegation_reaches,
    _delegation_sponsor_q,
    _delegation_walk_seed,
    _exact_prefix_exists,
    _materialize_related_model,
    _ordinary_prefix_predicate,
    _ordinary_records,
    _path_text,
    _plan_for_permission,
    _prefix_lookup_hops,
    _prefix_partial_suffix,
    _prefix_sponsor_q,
    _prefix_walk_position,
    _principal_eligibility_q,
    _reject_unsupported_delegated_suffix,
    _relationship_handles,
    _resolved_hop,
    _root_relative_column,
    _scope_prefix_lookups,
    _shift_outer_ref,
    _sponsor_walk_seed,
    filter_authorized_scopes,
    filter_by_permitted_content,
    granted,
)
from trusts.plan.relations import (
    ConditionLookup,
    PlanQueryCompiler,
    QueryCompiler,
    RelationPlan,
    SkipParams,
    _TARGET_ATTRS,
    _bound_permission_identity,
    _candidate_model,
    _known_skip_names,
    _or_q,
    _outer_permission_identity,
    bind_checked_user,
    candidate_queryset,
    user_skip_params,
)
from trusts.plan.recursions import (
    GrantReach,
    _AnchorInInverseReach,
    _IdentInReach,
    _KeyedReach,
    _PrefixInForwardWalk,
    _render_keyed_reach_sql,
    _unwrap_seed_sql,
)
from trusts.plan.standards import (
    BUILTIN_USER_CONDITIONS,
    UserCondition,
    assert_concrete_booleans,
    bind_skip_flags,
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

T = TypeVar('T', bound=Model)


def compiler_for_class(cls):
    """Resolve the class-owned compiler. Does not construct a backend instance."""
    compiler = getattr(cls, 'query_compiler', None)
    if compiler is None:
        raise TrustsCompilerError('%r is not query-capable' % (cls,))
    complete = getattr(compiler, 'complete_exists', None)
    group = getattr(compiler, 'group_exists', None)
    if not callable(complete) or not callable(group):
        raise TrustsCompilerError('%r is not query-capable' % (cls,))
    return compiler


def any_plan_records(handles, content):
    """True when any handle registry declares an ordinary or delegated plan.

    Aggregate **support** gate across configured Trusts paths. A
    declaration on one path establishes that the content terminal is
    known; it does not compile a grant and does not authorize through
    another path's compiler. Empty ``handles`` is False. Does not
    consult ``historical_fallback`` or historical model names.
    Construction issues no SQL. Relationship records only; a
    non-relationship plan on another family is not a Core support
    declaration.
    """
    for handle in handles:
        plan = handle.registry.plan_for(content)
        if plan.records or plan.delegations:
            return True
    return False


def _compiler_applies(compiler, plan):
    """Route applicability through ``compiler.applies`` when present."""
    applies = getattr(compiler, 'applies', None)
    if callable(applies):
        return bool(applies(plan))
    return bool(getattr(plan, 'records', None))


def all_match(handles, candidates, user, permission, *, kind='complete',
              extra_q=None, sponsor_handles=None, permission_model=None,
              skipped=()):
    """True iff candidates are nonempty and no row lacks the aggregate proof.

    One SQL. ``None`` when no handle applies so the caller may use the
    undeclared fallback. ``extra_q`` is an optional overlay (AND); it
    never creates a grant. Every supplied handle participates.
    """
    handles = tuple(handles)
    granted_q = _compile_granted(
        handles, candidates, user, permission, kind=kind,
        sponsor_handles=sponsor_handles,
        permission_model=permission_model,
        skipped=skipped,
    )
    if granted_q is None:
        return None
    if extra_q is not None:
        granted_q = granted_q & extra_q
    qs, granted_q = bind_once(candidate_queryset(candidates), granted_q)
    stats = qs.aggregate(
        total=Count('pk', distinct=True),
        lacking=Count('pk', distinct=True, filter=~granted_q),
    )
    return stats['total'] > 0 and stats['lacking'] == 0


def instance_match(handle, obj, user, permission, *, kind='complete', extra_q=None,
                   sponsor_handles=None, permission_model=None,
                   skipped=()):
    """One grant EXISTS for ``obj`` through ``handle`` only.

    ``None`` when the handle is inapplicable. ``extra_q`` is an optional
    overlay (AND); it never creates a grant.
    """
    granted_q = _compile_granted(
        (handle,), obj, user, permission, kind=kind,
        sponsor_handles=sponsor_handles,
        permission_model=permission_model,
        skipped=skipped,
    )
    if granted_q is None:
        return None
    if extra_q is not None:
        granted_q = granted_q & extra_q
    return bind_once(obj._meta.concrete_model._default_manager.filter(
        pk=obj.pk,
    ).filter(granted_q)).exists()


def _compile_common_permissions(handles, candidates, user, *, kind='complete',
                                sponsor_handles=None,
                                skipped=()):
    """Permission queryset for the given handles. No family filter."""
    qs = candidate_queryset(candidates)
    perm_expr = OuterRef(OuterRef('pk'))
    handles = tuple(handles)
    sponsor_handles = handles if sponsor_handles is None else tuple(sponsor_handles)
    parts = []
    permission_model = None
    applicable = False
    for handle in handles:
        plan = handle.registry.plan_for(candidates, user=user)
        if not _compiler_applies(handle.compiler, plan):
            continue
        applicable = True
        if plan.permission_model is not None:
            if permission_model is None:
                permission_model = plan.permission_model
            elif permission_model is not plan.permission_model:
                raise TrustsConfigurationError(
                    'Applicable registrations must share one permission '
                    'model; got %s and %s.'
                    % (
                        permission_model._meta.label,
                        plan.permission_model._meta.label,
                    )
                )
        if kind == 'complete':
            fn = handle.compiler.complete_exists
        else:
            fn = handle.compiler.group_exists
        part = _as_q(fn(plan, qs, user, perm_expr))
        delegated = None
        if kind == 'complete' and getattr(plan, 'delegations', None):
            sponsor_records = _ordinary_records(sponsor_handles, candidates)
            compatible_records = _compatible_sponsor_records(
                plan.delegations, sponsor_records,
            )
            delegated = _delegated_content_exists(
                plan.delegations, compatible_records, user, perm_expr,
                content_identity=_candidate_model(candidates),
                skipped=skipped,
            )
            if delegated is not None:
                applicable = True
                terminals = {
                    (record.permission_model, record.permission_target)
                    for record in compatible_records
                }
                if len(terminals) != 1:
                    raise TrustsConfigurationError(
                        'Delegated sponsor registrations must share one '
                        'permission model and comparison target.'
                    )
                delegated_model, _delegated_target = terminals.pop()
                if permission_model is None:
                    permission_model = delegated_model
                elif permission_model is not delegated_model:
                    raise TrustsConfigurationError(
                        'Applicable registrations must share one '
                        'permission model.'
                    )
        wrapped = _apply_checked_user(
            _or_q(part, delegated), plan, user, skipped, perm_expr,
            _candidate_model(candidates), permission_model,
            complete=(kind == 'complete'),
        )
        if wrapped is not None:
            parts.append(wrapped)
    if not applicable or permission_model is None:
        return None
    if not parts:
        return permission_model._default_manager.none()
    granted_q = parts[0] if len(parts) == 1 else reduce(or_, parts)
    return bind_once(permission_model._default_manager.filter(
        Exists(qs),
    ).exclude(
        Exists(qs.filter(~granted_q)),
    ).distinct())


def common_permissions(handles, candidates, user, *, kind='complete',
                       **skip_flags):
    """Permission queryset held on every candidate via the aggregate proof.

    Core-owned aggregate: fold-family handles are omitted. One SQL when
    evaluated. ``None`` when no remaining handle applies so the caller
    may use the undeclared fallback. Uses nested ``OuterRef`` so the
    permission identity is the outer permission row, not the candidate.
    Applicability is ``compiler.applies(plan)``. Mixin enumeration uses
    ``_compile_common_permissions`` on ``self._own_handle()``.
    Only relationship-family handles participate.
    ``RelationPlan.common_permissions`` is not this function.
    ``skip_<name>`` is a bound parameter on the registered rules.
    Anonymous, unauthenticated, and ``None`` are an empty queryset when
    a handle applies, and ``None`` only when no handle applies.
    """
    participating = _relationship_handles(handles)
    inquiry = bind_checked_user(
        user, skip_flags=skip_flags, handles=participating)
    if inquiry.denied:
        return _anonymous_common_permissions(participating, candidates)
    return _compile_common_permissions(
        participating, candidates, user, kind=kind,
        sponsor_handles=participating,
        skipped=inquiry.values,
    )


def _anonymous_common_permissions(handles, candidates):
    """Empty permission queryset for an inquiry denied before SQL.

    ``None`` stays the undeclared-fallback signal when no handle applies.
    An applicable handle does not compile a grant for this user.
    """
    permission_model = None
    applicable = False
    for handle in handles:
        registry = getattr(handle, 'registry', None)
        if registry is None:
            continue
        plan = registry.plan_for(candidates)
        if not _compiler_applies(getattr(handle, 'compiler', None), plan):
            continue
        if not plan.records and not plan.delegations:
            continue
        applicable = True
        if plan.permission_model is not None:
            permission_model = plan.permission_model
            break
    if not applicable:
        return None
    if permission_model is None:
        from django.contrib.auth.models import Permission

        permission_model = Permission
    return permission_model._default_manager.none()


def _compatible_sponsor_records(delegations, sponsor_records):
    """Ordinary records that can satisfy at least one delegation row."""
    compatible = []
    for ordinary in sponsor_records:
        for delegation in delegations:
            if ordinary.content_model is not delegation.content_model:
                continue
            if ordinary.user_model is not delegation.sponsor_model:
                continue
            expected = delegation.condition_permission_model
            if expected is not None and ordinary.permission_model is not expected:
                continue
            if (
                expected is not None
                and ordinary.permission_target
                != delegation.condition_permission_target
            ):
                continue
            compatible.append(ordinary)
            break
    return tuple(compatible)


def _delegated_user_exists(delegations, sponsor_records, content, permission,
                           *, content_identity=None, skipped=()):
    """Candidate-user predicate for one-level delegated authority."""
    content = _require_instance(content, 'content')
    parts = []
    for record in delegations:
        sponsor_q = _delegation_sponsor_q(
            record, sponsor_records, permission, content_identity,
            forward=False, bound_content=content,
        )
        if sponsor_q is None:
            continue
        eligibility = _principal_eligibility_q(
            record.sponsor_model, record.sponsor_field,
            record.sponsor_rules, skipped,
        )
        if eligibility is None:
            continue
        combined = Q(**{
            record.delegate_field: OuterRef(record.delegate_target),
        })
        combined &= _delegation_reaches(
            record, forward=False, content=content,
        )
        condition = _compile_predicate(
            record.condition, record, permission=permission,
        )
        if condition is not None:
            combined &= condition
        combined &= eligibility
        combined &= sponsor_q
        parts.append(Exists(record.root._default_manager.filter(combined)))
    if not parts:
        return None
    return parts[0] if len(parts) == 1 else reduce(or_, parts)




# ``BackendHandle.register`` annotates these names. Bind the same objects
# ``trusts.core`` defines so ``get_type_hints`` resolves them. ``plan.handles``
# does not import this module.
BackendHandle.register.__globals__['RegisteredRelation'] = RegisteredRelation
BackendHandle.register.__globals__['RegisteredDelegation'] = RegisteredDelegation
