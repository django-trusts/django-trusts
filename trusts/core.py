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
registry from ``trusts``. ``any_plan_records()``, ``common_permissions()``,
and ``compiler_for_class()`` stay importable here because
django-trusts-zero imports them; their bodies live in
``trusts.plan.aggregates``. Generic compiler protocol, the default plan
compiler, ``granted()``, ``filter_by_permitted_content()``,
``ConditionLookup``, and configuration/compiler exceptions are re-exported
from their homes.
Permission-condition *records* live on each ``TrustsRegistry`` via
``trusts.plan.conditions.ConditionRegistry``. Construction self-binds
the private store adapter; ``set_condition_lookup`` remains for
tests and explicit unbind.
"""

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
from trusts.plan.aggregates import (
    any_plan_records,
    common_permissions,
    compiler_for_class,
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

# ``BackendHandle.register`` annotates these names. Bind the same objects
# ``trusts.core`` defines so ``get_type_hints`` resolves them. ``plan.handles``
# does not import this module.
BackendHandle.register.__globals__['RegisteredRelation'] = RegisteredRelation
BackendHandle.register.__globals__['RegisteredDelegation'] = RegisteredDelegation
