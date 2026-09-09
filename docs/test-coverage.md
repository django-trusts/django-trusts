# Authorization test coverage

Recorded with the #14/#15 modernization. Existing tests were kept and
extended. This is not a claim that the declarative permission model is
complete.

Executable tests live in the top-level `tests/` Django app, not the
installable `trusts/` package:

- `tests/support.py` — fixtures and helpers (not a `test*.py` module)
- `tests/core/test_core.py` — ordinary authorization tests
- `tests/core/test_context.py` — issue #39 Context registry contract
  (test-only `ContextScope` / `ContextDocument` / `ContextAttachment` /
  `ContextAnnotation` / `ContextTrap` models; isolated malformed variants)
- `tests/core/test_trustee.py` — issue #40 Trustee registry contract
  (test-only requester / scope / operation / collective / bundle / grant
  models; isolated malformed variants)
- `tests/core/test_path.py` — issue #43 AuthorizationPath compose seam
  (isolated Context + Trustee join; reserved recursive/ordered slots)
- `tests/core/test_gh_vocab.py` — issue #43 GH-shaped private proof
  (`Account` / `Organization` / `Team` / `PermissionBundle` / `Policy` /
  `Repository`; `account.teams` membership vs organization containment)
- `tests/core/test_s1_kernel.py` — issue #47 S1 runtime / queryset /
  identity Context / `operation_lookup` / `alignment_paths` / `compose_scope`
  (isolated registries; object≡list; one-query; cross-org and NULL
  alignment deny; registration traps)
- `tests/core/test_s2_backend.py` — issue #47 S2 object-only
  `ObjectAuthorizationBackend` (`BaseBackend`; `obj is None` False;
  config error → denial; superuser does not grant objects; ModelBackend
  coexistence)
- `tests/core/test_s3_decorators.py` — issue #47 S3 native
  `require_authorized` / `P` / `K` / `G` / `O` (URL/GET/POST binding;
  404 vs 403; login redirect; config error → 403; superuser does not
  bypass; bounded query counts)
- `tests/core/test_s4_admin_views.py` — issue #47 S4
  `AuthorizedModelAdmin` / `AuthorizedQuerySetMixin` /
  `AuthorizedObjectMixin` / `trusts/` stub templates (pre-pagination
  SQL filter; object≡list; 404 vs 403; config error → 403; superuser
  does not bypass; template override; bounded query counts)
- `tests/core/test_zero_path.py` — issue #43 Step 2 Zero consumer of compose
  (`ContentQuerySet.permitted` / `TrustModelBackend`; same-PK fail-closed)
- `tests/core/test_kernel_split.py` — issue #43 Step 3 kernel/Zero AppConfig,
  migration identity, kernel `__init__` ownership
- `tests/regressions/test_issue_*.py` — historical issue regressions
- `python -m tests.runtests` — discovers the core and regression modules
  by explicit labels (`tests.core.test_core`, `tests.core.test_context`,
  `tests.core.test_trustee`, `tests.core.test_path`,
  `tests.core.test_gh_vocab`, `tests.core.test_s1_kernel`,
  `tests.core.test_s2_backend`,
  `tests.core.test_s3_decorators`,
  `tests.core.test_s4_admin_views`,
  `tests.core.test_zero_path`,
  `tests.core.test_kernel_split`, `tests.core.test_wheel_install`,
  `tests.regressions.test_issue_*`)
- `python -m tests.runtests_custom` — isolated custom-user suite
  (`tests.custom_content`)
- `scripts/verify-wheel-install.py` — uses `importlib.util.find_spec` so a
  leaked `trusts.tests` whose body raises `ImportError` (it imports
  `tests.models`) is still reported as present; kernel wheel must not
  ship `trusts.zero`
- `scripts/verify-migration-split.py` — fresh 0001+0002, sqlmigrate
  snapshots, empty plan, content-type keys, quiet makemigrations
- `scripts/verify-namespace-install.py` — builds this kernel and the
  **companion** django-trusts-zero checkout (not a synthetic in-tree
  Zero); wheel RECORD, uninstall/reinstall, editable+editable,
  AppConfig, migration identity. Pin: `scripts/zero-companion.pin`
  (stable django-trusts-zero `main` merge SHA, not a PR branch).

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
| Superuser short-circuit | Django `PermissionsMixin.has_perm` still treats active superusers as having all perms before backends run (`obj=None` and with `obj`). Object-level `TrustModelBackend.has_perm` and `.permitted()` follow relational grants; covered in `tests.core.test_zero_path`. |
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
- `ContextReusableLayerTest` / `ContextRegistryContractTest` / `ContextValidationTest` / `ContextSystemCheckTest` / `ContextNoCallbackTest` / `ContextQueryContractTest` / `ContextConvenienceCompatibilityTest` / `ContextAuthQueryParityTest` / `ContextFreshProcessFreezeTest` — issue #39 first slice: model-free `trusts.context` (no `Trust` / `Content` / `Junction` nouns); direct and multi-hop related resolution; registry completeness, duplicate, freeze, deterministic order; `Context.add_finalizer` runs once before every freeze so `filter_by_scope` cannot strand pending Junction/Content hops; public `Content.register_content` / `Junction` are idempotent-only or rejected after freeze; frozen `Junction.register_junction` verifies identity (contradictory `content_model` raises); `related_name='+'` / `'bad__path'` / `'bad_'` and partial `UniqueConstraint(condition=...)` fail closed at registration and as `trusts.E006`; scalar / many-valued / wrong-terminal / cyclic / missing paths fail closed; installed stale adapters and invalid deferred `Content._contents` leftovers emit `trusts.E006` (id/object/hint) without aborting `prepare_context_registry`; getters and properties are not executed; exact one-query exists/list equivalence; Content, dependent Content, Junction, and Trust-as-Content lookups match the registry; `has_perm` / `.permitted()` agree; `from trusts.zero.models import Junction` is the concrete import after Step 3. Does not close #39
- `TrusteeReusableLayerTest` / `TrusteeRegistryContractTest` / `TrusteeValidationTest` / `TrusteeSystemCheckTest` / `TrusteeNoCallbackTest` / `TrusteeQueryContractTest` / `TrusteeConvenienceCompatibilityTest` / `TrusteeAuthQueryParityTest` / `TrusteeFreshProcessFreezeTest` — issue #40 first slice: model-free `trusts.trustee` (no `User` / `Group` / `Role` / `Team` / `Trust` nouns); abstract `TrusteeMixin` with no concrete fields; explicit adapter registry (not `__subclasses__()`); external collective registration without inheritance; registry completeness, duplicate, freeze, deterministic order; `Trustee.add_finalizer` runs once before every freeze; scalar / callable / missing / wrong-requester / wrong-scope / wrong-operation / many-valued grant-identity / incomplete paths fail closed; same-PK scope/operation collisions fail closed before query construction; `trusts.E007` re-walks the installed map; getters and properties are not executed; exact one-query exists/list equivalence and shared compiled predicate; django-trusts `direct` / `group` adapters preserve User / Group / Role-ceiling `has_perm` / `.permitted()` results; settings gate only those built-ins; a test-only third adapter on the process-wide map participates in public `has_perm` / `.permitted()`; Role inherits the mixin with no Trusts schema migration. Does not close #40
- `AuthorizationPathReusableLayerTest` / `AuthorizationPathComposeTest` / `AuthorizationPathQueryTest` / `GhVocabNamingTest` / `GhVocabProofTest` / `GhVocabFailClosedTest` — issue #43 Step 1: model-free `trusts.path` compose seam (no `Trust` / `Content` / `Junction` / `Group` / `Role` / `Team` / `User` nouns); `compose` is the only public constructor; adapter-specific data is always `path.branches` (`AuthorizationBranch` records, same shape for one adapter or many); unregistered / empty / mismatched terminals fail closed; reserved `RecursiveEdge` / `OrderedContribution` / `condition=` reject compose and cannot evaluate if poked onto an instance; requester/operation must be instances of the composed terminals (raw PKs and same-PK collisions of the wrong model fail closed on path methods and module helpers); exact one-query exists/list equivalence; getters and properties are not executed; private GH vocabulary authorizes through `account.teams` / `team.permission_bundles` / `repository.policy`; organization containment without membership denies; wrong operation and missing bundle ceiling deny; process-wide Zero adapters stay on the current path; no Trusts schema migration; no `django-trusts-zero` relocation. Does not close #43

Do not treat a gap as license to widen access. New grants need an explicit
test.
