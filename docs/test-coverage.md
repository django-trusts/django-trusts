# Authorization test coverage

Recorded with the #14/#15 modernization. Existing tests were kept and
extended. This is not a claim that the declarative permission model is
complete.

## Tests that must keep passing

Denied access and organization isolation (a trust is the organization
boundary):

- `TrustContentTestMixin.test_user_not_in_group_has_no_perm`
- `TrustContentTestMixin.test_has_perm_disallow_no_perm_content`
- `TrustContentTestMixin.test_has_perm_disallow_no_perm_perm`
- `TrustContentTestMixin.test_mixed_trust_queryset`
- `TrustContentTestMixin.test_denied_access_without_grant` (added)
- `TrustContentTestMixin.test_organization_isolation_denies_cross_trust_access` (added)
- `TrustTest.test_own_condition_requires_settlor` (added; `:own` is settlor-only)
- Role tests that a stronger role on one trust does not leak to another

These run for `Content` subclasses, `Junction` content, and `Trust` as content
where the mixin applies.

## Known expected failure

`TrustJunctionTestCase.test_read_permissions_added` remains
`@unittest.expectedFailure`. Junctions do not add `read_*` permissions on the
joined model. That is historical, not a new denial-widening.

## Coverage gaps (not closed here)

| Area | Why it is a gap |
| --- | --- |
| Anonymous request users | Settlor-anonymous is rejected; object-level anonymous grants are not specified. |
| Superuser short-circuit | Django's `ModelBackend` still treats superusers as having all perms; no extra Trusts test. |
| Nested / inherited trusts | `Trust.trust` is a parent pointer with a readonly check; no recursive ACL evaluation (out of scope). |
| `has_perm` without `obj` | Falls through to Django model-level perms; only lightly covered via role tests. |
| `get_group_permissions` content path | Returns a permission queryset, not the string set `ModelBackend` uses; no dedicated assertion. |
| Decorator `raise_exception=True` | Most decorator tests use `raise_exception=False`. |
| `TRUSTS_ENTITY_MODEL` swap | Custom entity model is configurable but untested. |
| Captured production MySQL/Postgres dump | `scripts/verify-legacy-upgrade.py` upgrades a representative 0.10.3-shaped SQLite DB (`trusts.0001_initial` already recorded, historical table DDL). It is not a customer dump and does not replay Django 1.8 contrib tables. |
| Admin / i18n surfaces | Core models registered; `auto_modeladmin` opt-in is exercised in `AutoModelAdminTest`. |

## Issue #8 recovery tests (do not close #8)

These must keep passing in addition to the table above:

- `PermittedQuerySetTest` — trustee / TrustGroup local/global intersection / role-as-ceiling list-direct parity, SQL filter, inactive empty, `get_permission`, grant/revoke, arbitrary conditioned names raise `PermissionConditionNotQueryable`; unregistered `:own` on Category raises `AttributeError`
- `FilterByUserContentPermTest` — create-under-trust, no settlor shortcut, no parent-trust leak, inactive empty, `test_filter_by_user_perm` still discovered, conditioned names raise
- `AuthorizationTest` — reader/member denial with no mutation, scoped entity IDs, shared-group ceiling vs local grants, shared-group membership requires admin on every trust
- `TeamViewAuthorizationTest` — member GET/POST 403, admin add, unknown user PK does not mutate
- `AutoModelAdminTest` — Content and Junction proxies with `auto_modeladmin = True` register; opt-out does not
- `TrustGroupIntersectionTest` — issue #23 acceptance: no TrustGroup / empty local / local-without-ceiling deny; both layers allow; per-trust local subsets; removing either layer revokes; two groups combine without widening; trustee unchanged; role-derived ceiling; inactive/anonymous deny; `has_perm` / `.permitted` / `filter_by_user_content_perm` parity; legacy association grants nothing; grandfather dry-run/apply; later ceiling adds stay local-off; configured group/permission models
- `QueryableConditionTest` / `ConditionGrammarTest` — issue #4 V1: registered `Expr` nodes (`==`/`!=`/`&`/`|`/refs/constants), nested grouping, relationship traversal, `has_perm` / `.permitted` parity, inactive empty, no base grant, callables stay object-only and are never invoked with `Ref`s (`PermissionConditionNotQueryable` on queryset; exactly one real-value call on `has_perm` when `TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS` is True), V1-shaped lambdas are not auto-queryable, chained comparisons and Python `or` raise `PermissionConditionBooleanError` at construction, calls/indexing/arithmetic/setters/`TQ` lookups rejected, misspelled principal field vs nullable object field raises `PermissionConditionError`, non-empty `p.*` and terminal M2M/reverse O2M raise on both paths, `CharField`/int and relation/raw-PK `Eq`/`Ne` raise on both paths, Trust `:own` is a registered `Expr`
- `PermissionConditionCheckTest` — issue #29: import-time/`class_prepared` `Meta.permission_conditions` and `Trust:own` pass checks; invalid `Expr` does not raise at registration (including before `models_ready`); multiple errors aggregate as `trusts.E001`; `app_configs` subset still reports other apps; `manage.py check` is the entrypoint; silenced `trusts.E001` / `trusts.E002` still fail closed at runtime with no fallback grant; default callable rejection; explicit `TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS` opt-in emits `trusts.W001` and keeps object-only `has_perm`; checks never invoke callables and issue no database queries; `AppConfig.ready()` does not raise
- `TrustsRegistryTest` — issue #57: isolated `TrustsRegistry` / root-relative `Ref` registration only (ordinary Document / DocumentGrant; inferred terminals; mixed-root / missing / scalar / multi-valued / reverse / GFK / non-model / `root` and `path` field-name refs / duplicate / conflict; zero queries). Not an authorization test
- `TrustsRegistryProjectionTest` — issue #60: isolated common plan and three projections (ordinary Document / DocumentGrant / DocumentPermit; enumeration match/non-match; object auth agrees with membership via SQL `EXISTS`; authorized-content agrees with object checks as one queryset; shared-row correlation; two roots OR; duplicate rows distinct; unregistered fail-closed; lazy filter / no per-object loop; configured and custom user terminals; no historical Trust/Content/Junction). Not a historical authorization test
- `CategoryPermittedRegistryTest` / `TrustsRegistryOwnershipTest` / `ContributorIdempotenceTest` — issue #67 Child H: package-owned registry on `AppConfig` (created in `__init__`, not replaced by `ready()`); explicit test-app TUP→Trust←Category contribution with #62 r3 idempotence (re-enter no-op; different-root Category still registers TUP; conflict fails closed without sentinel; new AppConfig/registry receives the declaration again); Alice sibling Categories on Trust A; Bob / wrong-perm deny; Carol group-only not erased; `has_perm` (old) ↔ `.permitted` (new) parity; lazy / one-query / `[:n]`; no-TUP deny with registration still present; named `:condition` constrains trustee|group; Ticket / Junction stay on `trust_grant_q` (Trust-as-content is #70); reader uses `content_exists` not `filter_authorized`. No schema or migration.
- `TrustContributionIdempotenceTest` / `IsolatedAppsDoesNotDonateTrustContributionTest` / `TrustPermittedRegistryTest` — issue #70 S1: Trusts `AppConfig.ready()` contributes TUP→parent Trust←child Trust via `_meta` (no hard-coded reverse, no `_contents`); #62 r3 sentinel on this contribution (re-enter no-op; different-root Trust still registers TUP; conflict fails closed without sentinel; new AppConfig/registry and swapped live registry receive the declaration again; `ready()` does not replace the registry; `isolate_apps` without `trusts` does not touch the live Trust row); Alice sibling child Trusts on parent A not B; Bob / wrong-perm deny; Carol group-only not erased; `Trust:own` overlay including no underlying grant; mixed-parent isolation; `has_perm` (old) ↔ `.permitted` (new) parity; lazy / one-query / `[:n]`; create-under-trust stays on `trust_grant_q` (direct Trust terminal not registered); Ticket / Junction stay on the old path. No schema or migration.

Do not treat a gap as license to widen access. New grants need an explicit
test.
