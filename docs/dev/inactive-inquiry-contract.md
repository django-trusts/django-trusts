# #284 activity inquiries: implementation review driver

Date: 2026-10-12. Status: S2 runtime propagation is in review on the
along= train. The public keywords and the three activity change points are
implemented. Thomas settled the aggregate `has_perm` question: Trusts
guarantees activity only for its own backend. Lockfile mode representation
and the remaining non-reverse custom-backend dispatch stay flagged.
The contract is [in the built documentation](../source/index.rst#user-is-active-checks).
Chat owns documentation/design coordination.

## Sizing

Whole #284: 13–34. Completed: unscored source investigation. S1 documentation
contract: 5 (re-sized from 3), compared with #129 / PR #140 at 3, held in
PR #294 and not merged. Current S2 runtime propagation: 8. S3 remaining
agreement, companion, cache, and lockfile proof: provisional 5. Lockfile
representation and external overrides can widen the envelope. This S2 unit
did not reach 13, so it was not split.

## Open questions

1. How the lockfile/policy SQL represents normal versus audit mode. Export
   still records the default mode only. Schema version stays 1. No audit
   document and no byte change for the default lock. This remains a flagged
   follow-up.
2. How custom backends receive the mode outside the reverse hook. Trusts-owned
   mixin methods take the flag. A reverse `permitted_users_predicate`
   participates in audit only by naming `allow_inactive`
   (`POSITIONAL_OR_KEYWORD` or `KEYWORD_ONLY`). `**kwargs` alone is not
   participation: audit mode raises `TrustsConfigurationError` before SQL
   and does not call the hook. Singular and enumeration dispatch for a
   custom backend that is not that reverse hook remains a flagged follow-up.
3. Settled by Thomas: Trusts cannot guarantee anything outside its own
   backend. The activity check applies only to Trusts-owned grants. Default
   `get_permitted_users` agrees with `has_perm` for a custom backend,
   including an inactive user that only that backend admits. There is no
   `is_active` AND around the combined OR. `#294`'s
   `docs/reverse-permission-inquiry.md` lines 158–160 and 179–180 still
   describe the stricter wrapper and need to change to this decision.
   Audit participation does not conflict with it: a reverse hook that does
   not name `allow_inactive` raises before SQL, and Trusts does not rewrite
   that hook's predicate. The active-superuser contributor is unchanged.

## Reported, not settled

Registry projections and `.authorized()` treat a principal with no
`is_active` attribute as not inactive (`stored_user_is_inactive`). Backend
and forward public helpers deny that shape through
`getattr(user, 'is_active', False)`. This patch does not unify those
readings. Explicit activity conditions, expiry and revocation, group
positives, and both the delegate and the sponsor being inactive together
remain unproven matrices. SQL-mode export representation stays the flagged
lockfile follow-up above.

## Sizing history

S2 was provisional 8 before coding and stayed 8. Thomas's decision keeps
the activity check on the Trusts-owned branch and keeps reverse-hook audit
participation on this same unit. It did not reach 13. Lockfile
representation and non-reverse custom-backend dispatch remain the flagged
remainder.

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
| Django user methods | `PermissionsMixin` and async counterparts | No keyword forwarding; no monkey patch or required user-model substitution. Core currently has no Trusts-owned async inquiry APIs to extend |
| Other backends/compilers and Zero | Consumer overrides and reverse hooks | Inventory separately; audit mode must raise for unsupported participating contributions, not silently drop them |

The list is a source-based starting inventory. Grok must verify completeness,
especially companion overrides. Stock Django async methods remain outside
the flag-forwarding contract; no new Trusts async API is added. Ordinary plan
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
4. `_ensure_perm_cache` creates `_trust_perm_cache`, but no current inquiry
   reads it as a permission-result cache. Do not invent a new cache for S2.
   Any cache actually introduced or used must include the activity mode and
   appropriate activity/revocation invalidation.
5. Confirm both positive and negative acceptance cases in the contract on
   supported databases, plus exact-version Zero/consumer proof where needed.
6. Reconcile the #284 `migrates.md` entry with the behavior-changing
   implementation. The docs-first entry records current
   ordinary inactive positives versus new denial, audit replacements,
   companion effects, and searches for `.authorized(`, registry inquiries,
   `filter_authorized_scopes(`, reverse adapters, enumeration, and policy SQL.

Grok's agreement should name any unexpressible or unsupported surface before
S2. Existing superuser/codecs/backend-OR differences must be retained as
explicit agreement boundaries, not concealed by an inactivity flag. Thomas's
future superuser preference is no special treatment by default and explicit
opt-in; its design belongs to #273, not this implementation.

## Review findings and integration gate

Grok checked both `dev` and `feature/along-complete-surfaces`; their activity
checks are equivalent. Before S2, ordinary `.authorized()` can return rows for
an inactive user, but its delegated branch cannot. The original user-facing
current-behavior table omitted that partial gate; this baseline belongs here.

There are three directional change points, all controlled by the same mode:

- the concrete delegate check in `_delegated_content_exists` is Python;
- sponsor eligibility in both directions is `_principal_eligibility_q` SQL;
- reverse delegate eligibility comes from the outer `_trusts_eligibility_q`.

Default exporter SQL is also asymmetric: `policy_lock.py` adds no activity
predicate of its own; the reverse locked queryset includes activity eligibility,
while ordinary forward/registry exports consume projections without that
activity gate. Python actor checks are not automatically represented in SQL.
S2 identifies the runtime checks separately from exported SQL and does not
claim lockfile agreement for an audit mode. The current schema version is 1;
there is no schema bump. Default lock bytes stay on the activity predicates
they already had.

User-facing pages describe finished behavior in present tense. Planned status,
review inventory, sizing, and unresolved representation decisions stay here.
Hold PR #294 until the matching S2 implementation has been reviewed and its
findings reconciled; merging it together with implementation is also acceptable.
Do not publish user documentation that outpaces the implementation on `dev`.
The `dev` to `master` release gate and Thomas's separate manual lockfile-review
gate for the existing train remain unchanged.

Chat agrees with the activity-mode direction. Thomas later authorized the
bounded runtime unit and asked that lockfile mode representation, custom
backend dispatch, and a global gate stricter than stock `has_perm` be flagged
rather than decided in that unit. Thomas then settled the gate: Trusts
guarantees activity only for its own backend, and default
`get_permitted_users` keeps agreeing with `has_perm` for a custom backend.
The lockfile representation and the remaining non-reverse dispatch details
stay flagged. Reverse-hook audit participation is the explicit
`allow_inactive` parameter described above. It does not add an activity
filter outside the Trusts branch.

## Thomas's wording review, 2026-10-11

Keep one shared default rule and a short audit section in the existing usage
guide. No separate user-facing activity page. Use user, delegate, and sponsor;
write `user.is_active` and `sponsor.is_active` directly. Keep anonymous and
unauthenticated denial separate from activity. These callers cannot supply
persisted grants, so no positive permission answer is meaningful.

Thomas clarified the public keyword by the returned answer (review
5486296327): content, permission enumeration, and boolean inquiries use
`allow_inactive_user`; user-list inquiries use `allow_inactive`. This
supersedes the narrower exception that initially named only
`filter_authorized_scopes`. Internal helpers can propagate one boolean mode;
public adapters map their documented keyword explicitly.

| Public inquiry | Keyword |
| --- | --- |
| Content `.permitted` and `.authorized`, and their manager adapters | `allow_inactive_user=False` |
| Backend `has_perm`, `get_all_permissions`, `get_group_permissions` | `allow_inactive_user=False` |
| Registry `permissions_for`, `has_permission`, `filter_authorized`; `filter_authorized_scopes` | `allow_inactive_user=False` |
| Content `get_permitted_users`; optional user-manager `.permitted` | `allow_inactive=False` |

Do not add an eligibility abstraction in anticipation of a superuser feature.
Existing Django behavior stays unchanged; the inventory here remains evidence
for a later, separate superuser design.

Thomas authorizes Grok to begin implementation after these wording corrections
(review 5486296327). Merge the documentation only after the feature. The
implementation request keeps the three open questions above flagged for
Thomas instead of settling them inside S2. No additional human authorization
is required for the already agreed bounded feature work.
