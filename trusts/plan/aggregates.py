"""Authorization aggregates over one registry."""

__all__ = []

from functools import reduce
from operator import or_

from django.db.models import Count, Exists, OuterRef, Q

from trusts.plan.rewrites import bind_once
from trusts.plan.hops import require_instance
from trusts.errors import TrustsCompilerError, TrustsConfigurationError
from trusts.plan.contents import (
    _apply_checked_user,
    _as_q,
    _compile_granted,
    _delegated_content_exists,
    _delegation_reaches,
    _delegation_sponsor_q,
    _ordinary_records,
)
from trusts.plan.delegations import (
    _compatible_sponsor_records,
    _matched_delegation_q,
)
from trusts.plan.relations import (
    _candidate_model,
    _or_q,
    answering_compiler,
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


def _compiler_applies(compiler, plan):
    """Route applicability through ``compiler.applies`` when present."""
    applies = getattr(compiler, 'applies', None)
    if callable(applies):
        return bool(applies(plan))
    return bool(plan.records)


def all_match(catalog, candidates, user, permission, *, kind='complete',
              extra_q=None, permission_model=None, skipped=()):
    """True iff candidates are nonempty and no row lacks the aggregate proof.

    One SQL. ``None`` when the catalog does not apply so the caller may
    use the undeclared fallback. ``extra_q`` is an optional overlay (AND);
    it never creates a grant.
    """
    granted_q = _compile_granted(
        catalog, candidates, user, permission, kind=kind,
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


def instance_match(catalog, obj, user, permission, *, kind='complete', extra_q=None,
                   permission_model=None, skipped=()):
    """One grant EXISTS for ``obj`` through ``catalog`` only.

    ``None`` when the catalog is inapplicable. ``extra_q`` is an optional
    overlay (AND); it never creates a grant.
    """
    granted_q = _compile_granted(
        catalog, obj, user, permission, kind=kind,
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


def _compile_common_permissions(catalog, candidates, user, *, kind='complete',
                                skipped=()):
    """Permission queryset for ``catalog``. It sponsors itself."""
    qs = candidate_queryset(candidates)
    perm_expr = OuterRef(OuterRef('pk'))
    compiler = answering_compiler(catalog)
    plan = catalog.plan_for(candidates, user=user)
    if not _compiler_applies(compiler, plan):
        return None
    permission_model = plan.permission_model
    if kind == 'complete':
        fn = compiler.complete_exists
    else:
        fn = compiler.group_exists
    part = _as_q(fn(plan, qs, user, perm_expr))
    delegated = None
    if kind == 'complete' and plan.delegations:
        sponsor_records = _ordinary_records(catalog, candidates)
        compatible_records = _compatible_sponsor_records(
            plan.delegations, sponsor_records,
        )
        delegated = _delegated_content_exists(
            plan.delegations, compatible_records, user, perm_expr,
            content_identity=_candidate_model(candidates),
            skipped=skipped,
        )
        if delegated is not None:
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
    if permission_model is None:
        return None
    if wrapped is None:
        return permission_model._default_manager.none()
    return bind_once(permission_model._default_manager.filter(
        Exists(qs),
    ).exclude(
        Exists(qs.filter(~wrapped)),
    ).distinct())


def _delegated_user_exists(delegations, sponsor_records, content, permission,
                           *, content_identity=None, skipped=()):
    """Candidate-user predicate for one-level delegated authority."""
    content = require_instance(content, 'content')
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
