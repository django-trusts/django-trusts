# #284 inactive-user inquiries: implementation review driver

Date: 2026-10-11. Status: documentation held for implementation review of #296.
The contract is [in the built documentation](../source/index.rst#user-is-active-checks).
Chat owns documentation/design coordination; Grok reviews the contract and
independently verifies implementation feasibility before coding.

## Sizing

Whole #284: 13–34. Completed: unscored source investigation, no accepted
implementation. Current S1: 5 (re-sized from 3 after review exposed directional and
export asymmetry plus coordinated migration wording), compared with
#129 / PR #140 at 3. This is a bounded
documentation contract with migration analysis, cross-inquiry discovery, and
review. S2 runtime propagation: provisional 8. S3 remaining result comparisons,
companion, cache, and lockfile proof: provisional 5. Lockfile representation
and external overrides can widen the envelope. Any unit reaching 13 must be
split and sized before implementation.

## Source inventory on `dev` at `eeab800`

| Surface | Current source | Required review |
| --- | --- | --- |
| Forward public `.permitted` | `trusts/query.py`, `trusts/_permitted.py` | Preserve preflight before denial; propagate the flag to every applicable handle and condition overlay |
| Lower-level `.authorized` and manager adapter | `trusts/query.py`, `trusts/core.py:granted` | Default inactive-user denial is a behavior change; retain instance-only input and candidate queryset |
| Backend checks and enumeration | `trusts/backends.py` | Extend owned signatures without changing stock Django calls; cover instance/collection and complete/group queries |
| Reverse content and user-manager adapters | `trusts/query.py`, `trusts/reverse.py` | Share compiler; `is_active` checks within Trusts-owned grants; preserve candidate manager and backend completeness |
| Registry inquiries | `TrustsRegistry.permissions_for`, `has_permission`, `filter_authorized` | Current ordinary projections have no user check; require old/new migration and explicit flag |
| Plan/compiler projections | `RelationPlan.content_exists`, `user_exists`, `permissions`, `common_permissions`, `has_permission`, `filter_content`; `PlanQueryCompiler` | Propagate the flag without treating correlated SQL bindings as runtime users; verify each supported query shape |
| Aggregate inquiries | `granted`, `all_match`, `instance_match`, `common_permissions`, `_compile_common_permissions` | Keep grants/conditions composed per handle and preserve validation and query budget |
| Scope listing | `filter_by_permitted_content` | Ordinary-prefix projection currently has no `is_active` check; review support boundaries rather than silently adding delegated scopes |
| Delegate and sponsor eligibility | `_delegated_content_exists`, `_delegated_user_exists`, `_principal_eligibility_q` | Skip only built-in `is_active` checks when the flag is true; ordinary sponsor ceiling stays intact; actor's ordinary branch remains OR |
| Named conditions | `trusts/conditions`, `_permitted`, backend/reverse overlays | An explicit `is_active` condition is not bypassed; queryable names retain their current AND/OR ownership |
| Enforcement guards | `trusts/decorators.py` | No audit keyword; retain current guard, validation, and superuser behavior |
| Policy export/check | `trusts/policy_lock.py`, reverse locked queryset, `trusts.E009` | Agree flag representation and parameter roles before coding; schema stays 1 unless separately justified |
| Django user methods | `PermissionsMixin` and async counterparts | No keyword forwarding; no monkey patch or required user-model substitution. Core currently has no Trusts-owned async inquiry APIs to extend |
| Other backends/compilers and Zero | Consumer overrides and reverse hooks | Preserve external backend contracts; verify the exact Zero companion revision |

The list is a source-based starting inventory. Grok must verify completeness,
especially companion overrides. Stock Django async methods remain outside
the flag-forwarding contract; no new Trusts async API is added. Ordinary plan
primitives are not assumed to gain delegation behavior merely because this
ticket propagates a flag value.

## Review gates

1. Confirm the public signatures and which compiler/adaptor signatures carry
   the flag. Custom backends retain their current signatures and rules.
2. Confirm anonymous/unauthenticated denial, strict boolean validation, and
   existing permission/configuration validation before inactive shortcuts.
   Inventory schema-neutral user models lacking an `is_active` field
   or exposing Python-only eligibility properties; surface any change in
   compatibility or inability to express equivalent reverse SQL.
3. Decide how policy SQL exposes both flag values without misdescribing the default
   or silently changing reviewed lockfile bytes. Do not assume an optional-flag SQL
   format or schema bump in this docs-only PR.
4. `_ensure_perm_cache` creates `_trust_perm_cache`, but no current inquiry
   reads it as a permission-result cache. Do not invent a new cache for S2.
   Any cache actually introduced or used must include the flag value and
   appropriate `is_active`/revocation invalidation.
5. Confirm both positive and negative acceptance cases in the contract on
   supported databases, plus exact-version Zero/consumer proof where needed.
6. Reconcile the #284 `migrates.md` entry with the behavior-changing
   implementation. The docs-first entry records current
   ordinary inactive positives versus new denial, optional-flag replacements,
   companion effects, and searches for `.authorized(`, registry inquiries,
   `filter_by_permitted_content(`, reverse adapters, enumeration, and policy SQL.

Grok's agreement should name any unexpressible or unsupported surface before
S2. Existing superuser/codecs/backend-OR differences must be retained as
documented differences, not concealed by the optional flag. Thomas's
future superuser preference is no special treatment by default and explicit
opt-in; its design belongs to #273, not this implementation.

## Review findings and integration gate

Grok checked both `dev` and `feature/along-complete-surfaces`; their `is_active`
checks are equivalent. Before S2, ordinary `.authorized()` can return rows for
an inactive user, but its delegated branch cannot. The original user-facing
current-behavior table omitted that partial gate; this baseline belongs here.

There are three directional change points, all controlled by the same flag:

- the concrete delegate check in `_delegated_content_exists` is Python;
- sponsor eligibility in both directions is `_principal_eligibility_q` SQL;
- reverse delegate eligibility comes from the Trusts-owned `_trusts_eligibility_q` branch.

Default exporter SQL was asymmetric at the time of this review: `policy_lock.py`
added no `is_active` predicate of its own; the reverse locked queryset included
`is_active` checks, while ordinary forward/registry exports consumed projections
without that check. Python actor checks were not automatically represented in SQL.

That forward gap is closed. Inquiries that used to reject an inactive user in
Python before SQL now also compare a concrete `is_active` column in the grant
SQL that runs. The lockfile records that SQL and the token `user.is_active=True`.
There is no separate rule key. `skip_<name>=True` omits that registered
condition. The built-in condition's keyword is `skip_is_active=True`. A
user model with no concrete `is_active` column does not gain a term. The schema
version stays 1.

User-facing pages describe finished behavior in present tense. Planned status,
review inventory, sizing, and unresolved representation decisions stay here.
Hold PR #294 until the matching S2 implementation has been reviewed and its
findings reconciled; merging it together with implementation is also acceptable.
Do not publish user documentation that outpaces the implementation on `dev`.
The `dev` to `master` release gate and Thomas's separate manual lockfile-review
gate for the existing train remain unchanged.

Runtime implementation is under review in #296. SQL representation remains
subject to review; the backend boundary is settled below.

## Thomas's wording review, 2026-10-11

Keep one shared default rule and a short audit section in the existing usage
guide. No separate user-facing inactive-user page. Use user, delegate, and sponsor;
write `user.is_active` and `sponsor.is_active` directly. Keep anonymous and
unauthenticated denial separate from the `is_active` check. These callers cannot supply
persisted grants, so no positive permission answer is meaningful.

Thomas clarified the public keyword by the returned answer (review
5486296327): content, permission enumeration, and boolean inquiries used
`allow_inactive_user`; user-list inquiries used `allow_inactive`. This
supersedes the narrower exception that initially named only
`filter_by_permitted_content`. Public adapters accept `skip_<name>` for each
registered user condition and for the current checked-user override. The
built-in `is_active` condition's keyword is `skip_is_active`. It is not a
separate parameter. An override that is unset or replaced does not keep
its old keyword. Every row below uses that form.

| Public inquiry | Keywords |
| --- | --- |
| Content `.permitted` and `.authorized`, and their manager adapters | `skip_<name>` |
| Backend `has_perm`, `get_all_permissions`, `get_group_permissions` | `skip_<name>` |
| Registry `permissions_for`, `has_permission`, `filter_authorized`; `filter_by_permitted_content` | `skip_<name>` |
| Content `get_permitted_users`; optional user-manager `.permitted` | `skip_<name>` |

Do not add an eligibility abstraction in anticipation of a superuser feature.
Existing Django behavior stays unchanged; the inventory here remains evidence
for a later, separate superuser design.

Thomas authorizes Grok to begin implementation after these wording corrections
(review 5486296327). Merge the documentation only after the feature. Resolve
SQL flag representation in the implementation design;
surface any genuine behavior conflict before expanding scope. No additional
human authorization is required for the already agreed bounded feature work.

## Backend boundary clarification, 2026-10-11

Thomas's decision, relayed in #296 comment 6118712403: Trusts guarantees only
its own backend. `is_active` predicates stay inside Trusts-owned grant branches;
custom backend predicates are not wrapped with a global `is_active` filter.
The keyword is not forwarded to custom backends, and no new hook capability
or flag support is required from them. This supersedes the earlier review
requirements for aggregate `is_active` filtering and explicit audit participation.

Reviewing a user before reactivation is one use of the optional flag, not a
separate feature. Anonymous and unauthenticated denial remains independent of
the `is_active` check on Trusts-owned inquiry paths.
