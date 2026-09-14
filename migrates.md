# django-trusts migration guide

## Current 1.x contract

`django-trusts` is a schema-neutral dependency. Do not add `'trusts'`
to `INSTALLED_APPS`. The consumer supplies a
`TrustsImplementationConfig`, a backend built on
`trusts.backends.TrustModelBackendMixin`, models, registrations, and a
grant-editing workflow.

Applications that still need the concrete 0.x Trust/Content continuation
should install `django-trusts-zero` and follow that package's
already-merged executable guide. That path uses
`trusts.zero.apps.ZeroConfig`. Those concrete steps are not documented
here.

The 1.x runtime requires Python 3.12–3.14 and Django 6.1.

## Audiences

- **Historical django-trusts 0.x** (concrete Trust / Content models):
  install `django-trusts-zero` and follow the already-merged Zero
  guide
  https://github.com/django-trusts/django-trusts-zero/blob/dev/migrates.md
  Immutable squash-merge of that guide:
  https://github.com/django-trusts/django-trusts-zero/blob/88a515e0956a820b2244bcc8982cf2d5ab9efd70/migrates.md
- **New schema-neutral django-trusts 1.x**: stay on this file plus the README
  and authorization guide. Register an implementation, a mixin backend,
  and builders. Do not add `'trusts'` to `INSTALLED_APPS`.

## Public django-trusts 1.x actions

1. Install the library. django-trusts ships no Django app.
2. Provide `TrustsImplementationConfig` and a backend that subclasses
   `TrustModelBackendMixin`. Call `super().ready()`.
3. Register protected models through
   `backend.register(trust=..., user=..., permission=..., content=...)`
   and named filters through
   `backend.add_named_filter(model, code, predicate)` in
   `AppConfig.ready()` before finalization. The application-facing
   object is the configured backend from `configured_backend()`.
   `register_permission_condition(...)` and
   `BackendHandle.register_ordered_fold(...)` are removed. Ordered
   allow/deny construction lives in `django-trusts-ordered-fold`
   (`from trusts_ordered_fold import OrderedFold, PermissionMaskDomain,
   MaskEntry, PolarityMap, FlatToken, register_ordered_fold,
   TrustsOrderedFoldModelBackend`). django-trusts does not import, depend on,
   auto-discover, or fallback-import that package.
4. Import only the six public `trusts.conditions` names:
   `PermissionConditionBooleanError`, `PermissionConditionError`,
   `PermissionConditionNotQueryable`, `PermissionConditionUnsupported`,
   `permission_condition_code`, `permission_has_condition`.
5. Do not import `from trusts.conditions import Expr` (`ImportError`).
   Do not import `kernel_config`, `trusts.core_backends`, or
   `from trusts.models import Trust`. Those names are gone.
6. `TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS = True` is `trusts.E007`
   and does not enable callbacks.
7. Object checks use `user.has_perm`. List filtering uses the
   consumer queryset's `.authorized` / registered plans.

## Trust registration vocabulary and path builders (final pre-RC API)

| | Old | New |
| --- | --- | --- |
| Relationship registration | `backend.register_relationship(DocumentPermission, user=..., permission=..., content=...)` | `backend.register(trust=DocumentPermission, user=..., permission=..., content=...)` |
| Path spelling | Django `__` strings only | A Django `__` string or a one-argument symbolic path builder for each of `user`, `permission`, and `content` |
| Domain vocabulary | permission-bearing relation / root | trust model; one persisted row is a trust record |
| Named filters | `backend.add_named_filter(...)` | unchanged |

`trust=` is required and keyword-only. `register_relationship` is removed;
there is no compatibility forwarder. This is a pre-1.0 API replacement.

Both accepted path spellings of the same registration (the usage guide pairs
them the same way under “Register the trust”):

```python
backend.register(
    trust=DocumentPermission,
    user=lambda t: t.user,
    permission=lambda t: t.permission,
    content=lambda t: t.document,
)

backend.register(
    trust=DocumentPermission,
    user="user",
    permission="permission",
    content="document",
)
```

A path builder is contextually typed as the `trust=` model. Trusts invokes it
once during registration with a symbolic proxy. Attribute access on that proxy
forms a rooted model path; other proxy operations are unsupported. Trusts
validates the returned path using Django model metadata, normalizes it to the
same internal `__` path as the string spelling, and discards the callable.

The builder body remains trusted application startup code. Trusts does not
inspect or sandbox unrelated Python in it, and therefore does not claim to stop
the SQL, I/O, or side effects that application code could also perform before
calling `register()`. Trusts’ own returned-path validation issues zero SQL. A
builder exception, missing or foreign returned path, empty path, or unsupported
relationship shape fails without partial registry mutation; effects already
performed by application code are outside that guarantee.

The lowercase term **trust model** describes the role of the registered
application model. It does not require or imply the concrete
`trusts.zero.models.Trust` class.

Migration-bot checklist across django-trusts and active consumers:

- `.register_relationship(`
- positional relationship root arguments
- path builders that rely on proxy operations beyond attribute access
- `user=`, `permission=`, and `content=` path strings
- prose using “permission-bearing relation”, “permission-bearing root”, or
  ambiguous bare “root” for the public trust model
- package typing metadata and built-wheel visibility of inline annotations

## Relation registration (#131)

| | Old | New |
| --- | --- | --- |
| Relation register | `from trusts.core import Ref` + `handle.registry.register(content=j.document, ...)` or `handle.register(...)` / `backend.register(...)` | `backend.register_relationship(DocumentGrant, user="user", permission="permission", content="document")` |
| Along | `along=Along(j.parent, 8)` | `along=("parent", 8)` |
| Closed condition | `Equal(t.team.organization, t.repository.organization)` | `Equal("team__organization", "repository__organization")` |
| Named filter | `handle.register_permission_condition(Document, "non_confidential", builder)` | `backend.add_named_filter(Document, "non_confidential", predicate=builder)` |
| OrderedFold | `.registry.register_strategy(OrderedFold(...Ref...))` or `handle.register_strategy(Ace, OrderedFold(...))` or `handle.register(Ace, strategy=OrderedFold(content="document", descriptor="", ...))` | `backend.register_ordered_fold(Ace, OrderedFold(content=Document, descriptor="", source_descriptor="document", order="ace_order", polarity=PolarityMap("ace_type", allow_value=ALLOW, deny_value=DENY), mask="access_mask", trustee="user", token=FlatToken(principal=User, principal_user="", principal_identity=""), domain=PermissionMaskDomain(Permission, masks)))` |

`handle.registry` remains temporarily so unconverted internal compiler tests
still compile. `backend.register_relationship` was the intermediate pre-RC
relationship method. It is replaced by the final
`backend.register(trust=...)` API above. `backend.add_named_filter` remains
public; OrderedFold registration now lives in `django-trusts-ordered-fold`.
The earlier untyped `BackendHandle.register(...)` positional/strategy forms and
`BackendHandle.register_permission_condition(...)` remain removed; the final
keyword-only `register(*, trust=...)` is not a compatibility restoration.
There is no public `register_strategy` alias. Public
OrderedFold `content` is the content model class, not a path on the
ACE. `descriptor` is content-relative and may be `""`.
`source_descriptor` is a required source-relative Django `__` path.
Do not derive it from a content path. Direct form:
`content=Document`, `descriptor=""`, `source_descriptor="document"`.
Convergent shared-descriptor form (Windows-shaped
`Ace.descriptor -> SecurityDescriptor <- Node.security_descriptor`):
`content=WinNode`, `descriptor="security_descriptor"`,
`source_descriptor="descriptor"`.

Migration-bot search list (django-trusts plus the four active consumers:
`django-trusts-zero`, `django-trusts-gh-permissions`,
`django-trusts-windows-acl`, `django-trusts-zero-example`):

- `from trusts.core import Ref`
- `Ref(`
- `.registry.register(`
- `.registry.register_strategy(`
- `Along(`
- `OrderedFold(`
- `OrderedFold(content="`
- `register_strategy(`
- `register_strategy(OrderedFold`
- `register(..., strategy=`
- `.register(`
- `register_permission_condition(`
- `handle.register(`
- `backend.register(`
- `handle.register_permission_condition(`
- `backend.register_permission_condition(`

Classify internal `TrustsRegistry.register` /
`TrustsRegistry.register_permission_condition`, Django
`admin.site.register`, and `BaseCommand.handle` separately. Merged
consumer heads with no remaining application calls:
Zero `2e3cccedb92b4cf85e9d6a3cd2d51821aad1d716`, example
`ac62897da26b493356cc149154d878018ee6a5fb`, Windows
`1a9dc9c2b299dd15ee3aa5dcf083168050606d13`. GH permissions remains
README-only.

## View guard (#138 / #191)

| | Old | New |
| --- | --- | --- |
| Legacy request family | `from trusts.decorators import P, R, K, G, O, permission_required` | `from trusts.zero.decorators import P, R, K, G, O, permission_required` |
| Trusts-only object view | `permission_required(...)` (Django backend OR / `user.has_perm`) or a hand-rolled check | `authorization_required(Document, "myapp.change_document")` |
| Named condition on a view | colon suffix on the permission string, or `P` / `K` / `G` / `O` lookups | `authorization_required(Document, "myapp.change_document", ("non_confidential",))` |
| Candidate identity | `K` / `G` / `O`, GET, POST, or a custom kwarg | URL `kwargs["pk"]` only, bound to `model._meta.pk` |

`permission_required`, `P`, `R`, `K`, `G`, and `O` are no longer imported
from `trusts.decorators`. They live in `django-trusts-zero` as
`trusts.zero.decorators`. django-trusts keeps only `authorization_required` and
does not forward, lazy-import, fall back, or optionally depend on Zero.

`authorization_required` does not call `user.has_perm` and does not OR
Django authentication backends.

Only configured backends whose applicable plan uses
`django.contrib.auth.models.Permission` participate. Each of those
backends composes its own grant with its own selected names before the
backends are OR'd. A backend that does not register every selected name
is omitted; its unconditioned grant does not participate. Backend order
does not change the result. Selected names that no participating auth.Permission backend
registers together still fail closed (`TrustsConfigurationError` /
`trusts.E008`). E008 uses that same per-backend completeness rule;
a global union of names across registries is not enough. A model
with no applicable auth.Permission plan also fails closed, including
when no names are selected. That structural preflight runs with zero
SQL before the active-superuser existence shortcut; superusers bypass
only valid grants and conditions.

Migration-bot checklist:

- `authorization_required(`
- `from trusts.decorators import authorization_required`
- `from trusts.decorators import permission_required`
- `from trusts.decorators import P`
- `from trusts.decorators import R`
- `from trusts.decorators import K`
- `from trusts.decorators import G`
- `from trusts.decorators import O`
- `from trusts.zero.decorators import P, R, K, G, O, permission_required`
- `permission_required(`
- `P(` / `K(` / `G(` / `O(`
- colon permission strings in views (`app_label.codename:name`)

## QuerySet authorization (#181)

| | Old | New |
| --- | --- | --- |
| QuerySet evaluator | First configured Trusts path on an owner was the collection coordinator and combined `configured_handles()` | Each exact `AUTHENTICATION_BACKENDS` dotted path evaluates only `self._own_handle()` |
| Sibling grants | Coordinator ORed applicable handle predicates, then applied all-candidates / common-permissions in one SQL | Django alone ORs backend **results**. A backend that grants only row 1 and a sibling that grants only row 2 both deny `qs` of both rows; the permission is absent from the union of backend-local common-permission sets |
| Named filter | Lookup used the coordinator's `handles[0].registry`. Host raised `AttributeError` for Document's `non_confidential` on a QuerySet or instance and blocked later backends | Lookup uses this path's registry only. An inapplicable backend returns false / empty **before** `:name` lookup (instance or QuerySet, 0 SQL). An applicable backend missing that local name is a fail-closed non-match (`False` / empty, 0 SQL), not a raise that stops Django siblings. Malformed or unbound policy this backend owns still raises. Declared `authorization_required` names stay covered by `trusts.E008`; ad-hoc `has_perm` strings are not scanned |
| Query bound | One SQL on the coordinator; other same-owner paths were 0 SQL | At most one authorization SQL per applicable Trusts backend invocation. Inapplicable / unknown-local-name: 0 SQL. The same path listed twice is two Django invocations / two queries (#180 stays closed) |

Instance and QuerySet `has_perm` / enumeration stay backend-local. A missing runtime `:name` is fail-closed, not a raise. Malformed or unbound policy owned by an applicable backend still raises.

`.authorized`, `filter_authorized_scopes`, `authorization_required`,
module-level `granted`, and module-level `common_permissions` are
relationship-family local (see Family-local django-trusts aggregates below).
Django's object-level `user.has_perm` OR across authentication backends
is a different layer.

Migration-bot checklist:

- `has_perm(` with a `QuerySet`
- `get_all_permissions(` with a `QuerySet`
- `get_group_permissions(` with a `QuerySet`
- colon named-filter permission strings (`app_label.codename:name`)
- `_is_collection_coordinator(`
- `configured_handles()` used to authorize a QuerySet
- `configured_implementation_handles()` used to authorize a QuerySet
  or view guard

This migration guide covers django-trusts 1.x only. It does not document concrete
Zero schema, UI, admin, or management-command steps.

## Family-local OR (#187)

| | Old | New |
| --- | --- | --- |
| Second family on one terminal | The second of `register_relationship` / `register_ordered_fold` (either order) raised `TrustsConfigurationError` (`AnyPath and OrderedFold cannot share one terminal`) | Both families may coexist on one content terminal of one exact backend path when user and permission terminals match |
| Authorization | One family per plan | Same-path family-local OR: `relationship_grant OR ordered_fold_grant`. This is the provisional same-path deferral while the engine still lives in django-trusts. 1.0 list/guard aggregation is relationship-family local (#194); object-level Django backend OR is a different layer |
| OrderedFold deny | N/A on a mixed plan (XOR blocked registration) | Settles only the OrderedFold branch. It does not veto an independent relationship grant |
| Named filter | Restricting overlay; never a grant | Unchanged |
| Malformed / unsupported renderer | Fail-closed; no silent drop | Unchanged. A configured OrderedFold branch is not omitted when the renderer is unsupported |
| Duplicate OrderedFold | `TrustsConfigurationError` | Unchanged |
| Group projection | Membership-hop relationship records only; OrderedFold-only plans have no group slice | Unchanged: OrderedFold does not become a group grant merely because it shares the plan |

Migration-bot checklist:

- `AnyPath and OrderedFold cannot share one terminal`
- `already has an OrderedFold strategy`
- `already has an AnyPath registration`
- separate backends or registries used only to XOR-workaround coexistence
- projection tests that assume a second family cannot register
- workaround code that copied relationship grants into ACE rows (or the reverse) solely to escape XOR

This migration guide covers django-trusts 1.x only. It does not document concrete
Zero schema, UI, admin, or management-command steps.

## Family-local django-trusts aggregates (#194 / #181)

| | Old | New |
| --- | --- | --- |
| Cross-handle list/guard aggregate | `.authorized`, `authorization_required`, and `filter_authorized_scopes` OR'd compiler predicates from every configured implementation handle in one SQL, including a co-installed fold-family plan | Those django-trusts-owned helpers include relationship-family handles only (`implementation_for_path(handle.path)._authorization_family == "relationship"`). Fold-family handles are omitted, not ORed |
| `granted` / module-level `common_permissions` | Noun-blind OR of every given handle | Same compilation, after dropping owned non-relationship-family handles. Unowned isolated test handles stay (default `"relationship"`) |
| Mixin `has_perm` / `get_*_permissions` | Exact-path `_own_handle()` | Unchanged. Mixin projection still evaluates the own handle even when that handle's family is not `"relationship"` |
| Django `user.has_perm` | Ordered authentication-backend OR of object results | Unchanged. Do not read this as django-trusts list/guard aggregation |
| Protected factories | `_ensure()` constructed `TrustsRegistry()`; `configured_backend()` constructed `BackendHandle` | `_create_registry(path)` and `_create_handle(path, registry, compiler)` on `TrustsImplementationConfig`. Freeze-on-first-live-read and exact-path ownership are unchanged |
| Family discriminator | None | Protected provisional `_authorization_family`, default `"relationship"`. Not a public family API |
| Applicability | Mixin and `common_permissions` hard-wired `plan.records or plan.strategy` | `QueryCompiler.applies(plan)`; relationship default is `bool(plan.records)`. Inapplicable backends stay 0 SQL before `:name` overlay. One authorization SQL per applicable backend invocation |
| `any_plan_records` | Consulted `plan.records or plan.strategy` | Same consult while the provisional engine still lives in django-trusts. This is a support gate, not a mixed-family one-SQL contract. C2 drops the `strategy` arm |

QuerySet / common-permission / guard consequences:

- `Document.objects.authorized(user, permission)` no longer includes rows
  granted only by a fold-family handle.
- `authorization_required` preflight and grant composition see only
  relationship-family `auth.Permission` plans. A fold-only plan on a
  fold-family handle does not open the django-trusts guard.
- Module-level `common_permissions` and `filter_authorized_scopes` omit
  fold-family handles. Mixin `get_all_permissions` / `get_group_permissions`
  stay path-local.
- Object-level `user.has_perm` can still be True when either a
  relationship backend or a fold backend grants that object.

Migration-bot checklist:

- `.authorized(`
- `authorization_required(`
- `filter_authorized_scopes(`
- `granted(`
- `common_permissions(`
- `configured_implementation_handles()` used to authorize a QuerySet
  or view guard
- `_authorization_family`
- `_create_registry(`
- `_create_handle(`
- `QueryCompiler.applies`
- `plan.records or plan.strategy`
- `family-local OR`
- `cross-handle aggregation`
- `separate design track`

This migration guide covers django-trusts 1.x only. It does not document concrete
Zero schema, UI, admin, or management-command steps.

## Remove OrderedFold from django-trusts (#195 / C2)

django-trusts deletion after standalone package P2
`c8c649aa5278db2b11fc380fa1646ae73df471ac` and Windows W
`333a8c7f6b8074d3a55f571846ee57892d8e97dd`. Work is on
`DEV_standalone_ordered_fold` against django-trusts C1
`6934894489d4fc0e46de88b55b9a27f5f2eb2b41`. django-trusts remains
relationship-only.

| Surface | Old (C1 / django-trusts shims) | New (C2) |
| --- | --- | --- |
| Engine module | `trusts.ordered_fold` (PostgreSQL renderer + validation) | **Deleted.** Import from `trusts_ordered_fold` / `trusts_ordered_fold.engine` |
| Declaration re-exports | `from trusts.core import OrderedFold, PermissionMaskDomain, MaskEntry, PolarityMap, FlatToken` | `from trusts_ordered_fold import OrderedFold, PermissionMaskDomain, MaskEntry, PolarityMap, FlatToken` |
| Registration | `backend.register_ordered_fold(source, fold)` or `registry.register_strategy(OrderedFold(...))` | `register_ordered_fold(backend, source, fold)` on an OrderedFold handle |
| Handle / registry | django-trusts `BackendHandle` + `TrustsRegistry` stored `plan.strategy` | `OrderedFoldBackendHandle` + `OrderedFoldRegistry` |
| Concrete backend | Relationship mixin path that also accepted a fold | **`trusts_ordered_fold.backends.TrustsOrderedFoldModelBackend`** (Windows: `WinfsBackend` subclass; one listed path) |
| Implementation owner | relationship `TrustsImplementationConfig` | subclass `OrderedFoldImplementationConfig` |
| Vendor check | django-trusts `trusts.E006` / `CHECK_ID_ORDERED_FOLD_RENDERER` | **`trusts_ordered_fold.E001`**. Silencing retired `trusts.E006` is a no-op |
| `RelationPlan.strategy` | Compiled fold on a django-trusts plan | **Removed.** django-trusts plans are relationship records only |
| `TrustsRegistry.strategies` / `register_strategy` | Internal fold store | **Removed** |
| `PlanQueryCompiler.complete_exists` | `records` or `strategy` | `records` only |
| `any_plan_records` | `plan.records or plan.strategy` | `plan.records` only |
| Applicability / `_compiler_applies` fallback | `records or strategy` | `bool(plan.records)` |
| Guard `_plan_is_auth_permission` | `records` or `strategy` | `records` only |
| E003 coverage | records + `registry.strategies` | records only |
| django-trusts PostgreSQL CI | `tests-orderedfold-pg` / `tests.fold_settings` | **Removed.** Extension CI owns PostgreSQL proof |
| Fold-only django-trusts tests | `test_issue100`, `test_issue187`, `test_ordered_fold_provisional`, fold halves of `test_issue131` | Moved to / owned by the extension. django-trusts keeps `test_issue195` |

QuerySet / common-permission / guard consequences:

- Relationship object, QuerySet, enumeration, group, and named-filter
  behavior is unchanged.
- django-trusts `.authorized`, `authorization_required`,
  `filter_authorized_scopes`, `granted`, and module-level
  `common_permissions` remain relationship-family local (#194).
- Mixin `has_perm` / `get_*_permissions` stay exact-path
  (`_own_handle()`). A fold-family handle still projects through the
  mixin when the extension owns that path; django-trusts no longer stores a
  fold on `RelationPlan`.
- Object-level `user.has_perm` is Django's ordered backend OR. Same-path
  family-local OR of relationship and OrderedFold on one django-trusts plan
  (#187) is removed and is not a 1.0 QuerySet contract.
- An applicable unsupported-vendor fold raises
  `TrustsConfigurationError` when the **extension** backend is reached.
  django-trusts relationship evaluation does not compile fold SQL.
- Windows keeps its fail-closed registration gate on
  `winfs.compat.require_ordered_fold()` / the OrderedFold package.
  Leftover django-trusts `register_ordered_fold` callers fail loud
  (`AttributeError`), not open.

```python
# Old (django-trusts provisional / C1 shim)
from trusts.core import (
    FlatToken,
    MaskEntry,
    OrderedFold,
    PermissionMaskDomain,
    PolarityMap,
)
backend.register_ordered_fold(Ace, OrderedFold(...))

# New (C2 / P2 / W)
from trusts_ordered_fold import (
    FlatToken,
    MaskEntry,
    OrderedFold,
    OrderedFoldImplementationConfig,
    PermissionMaskDomain,
    PolarityMap,
    TrustsOrderedFoldModelBackend,
    register_ordered_fold,
)
register_ordered_fold(backend, Ace, OrderedFold(...))
```

Migration-bot checklist:

```text
from trusts.core import OrderedFold
from trusts.core import PermissionMaskDomain
from trusts.core import MaskEntry
from trusts.core import PolarityMap
from trusts.core import FlatToken
from trusts.ordered_fold import
import trusts.ordered_fold
backend.register_ordered_fold(
handle.register_ordered_fold(
.registry.register_strategy(
register_strategy(
plan.strategy
registry.strategies
trusts.E006
CHECK_ID_ORDERED_FOLD_RENDERER
SILENCED_SYSTEM_CHECKS.*E006
AnyPath and OrderedFold cannot share one terminal
already has an OrderedFold strategy
family-local OR
tests.fold_settings
tests.core.test_issue100
from trusts_ordered_fold import
register_ordered_fold(
TrustsOrderedFoldModelBackend
OrderedFoldImplementationConfig
trusts_ordered_fold.E001
```

Then:

- [ ] Replace `from trusts.core import OrderedFold, …` with
      `from trusts_ordered_fold import …`.
- [ ] Replace `backend.register_ordered_fold(source, fold)` with
      `register_ordered_fold(backend, source, fold)`.
- [ ] List `TrustsOrderedFoldModelBackend` or a subclass. Do not list
      it beside a relationship backend for the same content terminal
      as a mixed-family QuerySet contract.
- [ ] Own that path with `OrderedFoldImplementationConfig`.
- [ ] Treat leftover `trusts.ordered_fold`, `plan.strategy`,
      `register_strategy(`, and django-trusts fold re-exports as unfinished
      conversion.
- [ ] Silenced `trusts.E006` becomes `trusts_ordered_fold.E001`;
      silencing still does not create a fallback grant.
- [ ] Drop XOR / `#187` workarounds that assumed one django-trusts plan.
- [ ] Confirm pair suites do not import deleted `trusts.ordered_fold`.
- [ ] Confirm django-trusts never `install_requires` the extension.
- [ ] Confirm Windows still fail-closes without a donated OrderedFold
      plan (`require_ordered_fold` / missing package).
- [ ] Confirm relationship object/QS/enumeration/group/named-filter
      proofs and family-local django-trusts aggregates stay green.

This migration guide covers django-trusts 1.x only. It does not document concrete
Zero schema, UI, admin, or management-command steps.

## Archaeology

Chronology of unpublished development stairs lives in the annotated
non-release archive, not this file.

- Tag file: https://github.com/django-trusts/django-trusts/blob/migration-archive-pre-1.0/migrates.md
- Immutable SHA file: https://github.com/django-trusts/django-trusts/blob/7414886263faafb6edfb44c0c5fcf9fc8fa14e79/migrates.md

Do not copy that archive back onto `dev`.
