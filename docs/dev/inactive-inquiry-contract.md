# #284 activity inquiries: implementation review driver

Date: 2026-10-11. Status: S1 documentation proposal, not implemented.
The contract is [in the built documentation](../source/inactive-permission-inquiries.rst).
Chat owns documentation/design coordination; Grok reviews the contract and
independently verifies implementation feasibility before coding.

## Sizing

Whole #284: 13–34. Completed: unscored source investigation, no accepted
implementation. Current S1: 3, compared with #129 / PR #140. This is a bounded
documentation contract with migration analysis, cross-inquiry discovery, and
review. S2 runtime propagation: provisional 8. S3 remaining agreement,
companion, cache, and lockfile proof: provisional 5. Lockfile representation
and external overrides can widen the envelope. Any unit reaching 13 must be
split and sized before implementation.

## Source inventory on `dev` at `eeab800`

| Surface | Current source | Required review |
| --- | --- | --- |
| Forward public `.permitted` | `trusts/query.py`, `trusts/_permitted.py` | Preserve preflight before denial; propagate one mode to every applicable handle and condition overlay |
| Lower-level `.authorized` and manager adapter | `trusts/query.py`, `trusts/core.py:granted` | Default activity denial is a behavior change; retain instance-only input and candidate queryset |
| Backend checks and enumeration | `trusts/backends.py` | Extend owned signatures without changing stock Django calls; cover instance/collection and complete/group queries |
| Reverse content and user-manager adapters | `trusts/query.py`, `trusts/reverse.py` | Share mode-aware compiler; default aggregate candidate eligibility; preserve candidate manager and backend completeness |
| Registry inquiries | `TrustsRegistry.permissions_for`, `has_permission`, `filter_authorized` | Current ordinary projections have no principal gate; require old/new migration and explicit mode |
| Plan/compiler projections | `RelationPlan.content_exists`, `user_exists`, `permissions`, `common_permissions`, `has_permission`, `filter_content`; `PlanQueryCompiler` | Propagate mode without treating correlated SQL bindings as runtime users; verify each supported query shape |
| Aggregate inquiries | `granted`, `all_match`, `instance_match`, `common_permissions`, `_compile_common_permissions` | Keep grants/conditions composed per handle and preserve validation and query budget |
| Scope listing | `filter_authorized_scopes` | Ordinary-prefix projection currently has no activity gate; review support boundaries rather than silently adding delegated scopes |
| Delegate and sponsor eligibility | `_delegated_content_exists`, `_delegated_user_exists`, `_principal_eligibility_q` | Skip only built-in activity in audit mode; ordinary sponsor ceiling stays intact; actor's ordinary branch remains OR |
| Named conditions | `trusts/conditions`, `_permitted`, backend/reverse overlays | An explicit activity condition is not bypassed; queryable names retain their current AND/OR ownership |
| Enforcement guards | `trusts/decorators.py` | No audit keyword; retain current guard, validation, and superuser behavior |
| Policy export/check | `trusts/policy_lock.py`, reverse locked queryset, `trusts.E009` | Agree mode representation and parameter roles before coding; schema stays 1 unless separately justified |
| Django user methods | `PermissionsMixin` and async counterparts | No keyword forwarding; no monkey patch or required user-model substitution |
| Other backends/compilers and Zero | Consumer overrides and reverse hooks | Inventory separately; audit mode must raise for unsupported participating contributions, not silently drop them |

The list is a source-based starting inventory. Grok must verify completeness,
especially companion overrides and sync/async entry points. Ordinary plan
primitives are not assumed to gain delegation behavior merely because this
ticket propagates an activity mode.

## Review gates

1. Confirm the public signatures and which compiler/adaptor signatures carry
   the mode. Define explicit capability/dispatch for custom audit backends.
2. Confirm anonymous/unauthenticated denial, strict boolean validation, and
   existing permission/configuration validation before inactive shortcuts.
   Inventory schema-neutral principal models lacking an `is_active` field
   or exposing Python-only eligibility properties; surface any change in
   compatibility or inability to express equivalent reverse SQL.
3. Decide how policy SQL exposes both modes without misdescribing the default
   or silently changing reviewed lockfile bytes. Do not assume an audit SQL
   format or schema bump in this docs-only PR.
4. Verify cache isolation between modes and relevant activity/revocation
   behavior. No hypothetical cache is required merely to carry the flag.
5. Confirm both positive and negative acceptance cases in the contract on
   supported databases, plus exact-version Zero/consumer proof where needed.
6. Add `migrates.md` in the behavior-changing implementation PR. Record current
   ordinary inactive positives versus new denial, audit replacements,
   companion effects, and searches for `.authorized(`, registry inquiries,
   `filter_authorized_scopes(`, reverse adapters, enumeration, and policy SQL.

Grok's agreement should name any unexpressible or unsupported surface before
S2. Existing superuser/codecs/backend-OR differences must be retained as
explicit agreement boundaries, not concealed by an inactivity flag. Thomas's
future superuser preference is no special treatment by default and explicit
opt-in; its design belongs to #273, not this implementation.
