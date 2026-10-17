"""Multi-handle authorization aggregates.

These combine several handles. Single-handle grants stay in
``trusts.plan.contents``. This module may import other ``plan`` modules,
``commons``, and ``errors``. It does not import ``trusts.core``,
``trusts.compile``, ``trusts.backends``, or ``trusts.apps``.
"""

__all__ = []

from functools import reduce
from operator import or_

from django.db.models import Count, Exists, OuterRef, Q

from trusts._bind_once import bind_once
from trusts.commons import _require_instance
from trusts.errors import TrustsCompilerError, TrustsConfigurationError
from trusts.plan.contents import (
    _apply_checked_user,
    _as_q,
    _compile_granted,
    _delegated_content_exists,
    _delegation_reaches,
    _delegation_sponsor_q,
    _ordinary_records,
    _relationship_handles,
)
from trusts.plan.delegations import (
    _compatible_sponsor_records,
    _matched_delegation_q,
)
from trusts.plan.relations import (
    _candidate_model,
    _or_q,
    bind_checked_user,
    candidate_queryset,
)


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
    may use the undeclared fallback. Uses nested ``OuterRef`` so the permission
    identity is the outer permission row, not the candidate.
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

        def bound(record=record):
            combined = Q(**{
                record.delegate_field: OuterRef(record.delegate_target),
            })
            combined &= _delegation_reaches(
                record, forward=False, content=content,
            )
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
