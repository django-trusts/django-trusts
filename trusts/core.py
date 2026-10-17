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

from dataclasses import replace
from functools import reduce
from operator import or_
from typing import TypeVar

from django.db.models import Count, Exists, F, Model, OuterRef, Q
from django.db.models.query import QuerySet

from trusts._bind_once import bind_once
from trusts.compile.factory import (
    assemble_frozen,
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
        # Stay lazy: importing trusts.core must not load the condition IR.
        # ConditionLookup lives in plan.relations, already imported above.
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


# ``BackendHandle.register`` annotates these names. Bind the same objects
# ``trusts.core`` defines so ``get_type_hints`` resolves them. ``plan.handles``
# does not import this module.
BackendHandle.register.__globals__['RegisteredRelation'] = RegisteredRelation
BackendHandle.register.__globals__['RegisteredDelegation'] = RegisteredDelegation
