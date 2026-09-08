# Authorization test coverage

Recorded with the #14/#15 modernization. Existing tests were kept and
extended. This is not a claim that the declarative permission model is
complete.

Executable tests live in the top-level `tests/` Django app, not the
installable `trusts/` package:

- `tests/support.py` — fixtures and helpers (not a `test*.py` module)
- `tests/core/test_core.py` — ordinary authorization tests
- `tests/regressions/test_issue_*.py` — historical issue regressions
- `python -m tests.runtests` — discovers the core and regression modules
  by explicit labels (`tests.core.test_core`, `tests.regressions.test_issue_*`)
- `python -m tests.runtests_custom` — isolated custom-user suite
  (`tests.custom_content`)

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
- `DependentContentTrustTest` — issue #25: `Receipt(Content) ← ReceiptImage ← ReceiptImageMeta`; `get_content_fieldlookup` is a composable string (not `None`); `compose_content_fieldlookup` for one- and two-hop registration; `has_perm` allow/deny/isolation at each hop; instance and QuerySet `filter_by_content`; missing registration denies; `None__…` lookups raise; scalar hop (`title`) whose value equals `str(dependent)` raises on compose/register/`filter_by_content`/`has_perm` and does not grant; shared Trust does not copy another model's permission; resolution stays in SQL
- `DefaultConfiguredModelContractTest` — issue #26 default-model regression: Role / TrustUserPermission / TrustGroup FKs use auth models; mismatched permission instances are not coerced by PK; `trusts.E003`–`E005` and `trusts.W002` / `W003` do not fire on the supported contract; lookup failures keep distinct IDs; silenced `trusts.E003` / `E004` / `E005` still fail closed at grant and `has_perm` / `.permitted()`; silenced `trusts.E003` also denies an existing Group membership + ceiling + local TrustGroup grant; getters stay on `auth.Group` / `auth.Permission` when those settings name another model
- `DeprecatedGroupPermissionSettingsTest` — issue #33: default config has no `E004` / `E005` / `W002` / `W003`; explicit `auth.Group` / `auth.Permission` settings are `trusts.W002` / `W003` and name the 1.1.0 removal; non-standard values are `E004` / `E005` (not the warning) and still fail closed; getters and field targets stay on `auth.*`; historical `0001_initial` / `0002_trustgroup` remain importable with pinned `auth.*` names
- Isolated `python -m tests.runtests_custom` — issue #26 / #33 fresh install with custom `AUTH_USER_MODEL` / `TRUSTS_ENTITY_MODEL` selected before migrate: settlor/trustee FKs target the custom user table; Group and Permission remain `auth.*`; no group/permission deprecation diagnostics when those settings are unset; trustee grants; group-permission ceiling; role-derived ceiling; `has_perm` / `.permitted()` parity; TrustGroup grant/set/revoke and authorization helpers; mismatched instances fail closed

Do not treat a gap as license to widen access. New grants need an explicit
test.
