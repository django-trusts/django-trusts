# Core migration record

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
- **New schema-neutral Core 1.x**: stay on this file plus the README
  and authorization guide. Register an implementation, a mixin backend,
  and builders. Do not add `'trusts'` to `INSTALLED_APPS`.

## Public Core 1.x actions

1. Install the library. Core ships no Django app.
2. Provide `TrustsImplementationConfig` and a backend that subclasses
   `TrustModelBackendMixin`. Call `super().ready()`.
3. Register protected models through
   `backend.register_relationship(root, user=..., permission=...,
   content=...)`, ordered plans through
   `backend.register_ordered_fold(source_model, OrderedFold(...))`, and
   named filters through `backend.add_named_filter(model, code, predicate)`
   in `AppConfig.ready()` before finalization. The application-facing
   object is the configured backend from `configured_backend()`.
   `BackendHandle.register(...)` and
   `register_permission_condition(...)` are removed. The OrderedFold
   construction surface—`backend.register_ordered_fold`, `OrderedFold`,
   `PermissionMaskDomain`, `MaskEntry`, `PolarityMap`, and `FlatToken`—is
   provisional and excluded from the normal 1.x compatibility guarantee.
   Its signatures or location may change, or it may be removed, in a future
   feature release. `OrderedFoldAllowed`, `RegisteredStrategy`, and
   `ordered_fold_connection_supported` are implementation details and are no
   longer re-exported from `trusts.core`; application code must not import
   them.
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

## Relation registration (#131)

| | Old | New |
| --- | --- | --- |
| Relation register | `from trusts.core import Ref` + `handle.registry.register(content=j.document, ...)` or `handle.register(...)` / `backend.register(...)` | `backend.register_relationship(DocumentGrant, user="user", permission="permission", content="document")` |
| Along | `along=Along(j.parent, 8)` | `along=("parent", 8)` |
| Closed condition | `Equal(t.team.organization, t.repository.organization)` | `Equal("team__organization", "repository__organization")` |
| Named filter | `handle.register_permission_condition(Document, "non_confidential", builder)` | `backend.add_named_filter(Document, "non_confidential", predicate=builder)` |
| OrderedFold | `.registry.register_strategy(OrderedFold(...Ref...))` or `handle.register_strategy(Ace, OrderedFold(...))` or `handle.register(Ace, strategy=OrderedFold(content="document", descriptor="", ...))` | `backend.register_ordered_fold(Ace, OrderedFold(content=Document, descriptor="", source_descriptor="document", order="ace_order", polarity=PolarityMap("ace_type", allow_value=ALLOW, deny_value=DENY), mask="access_mask", trustee="user", token=FlatToken(principal=User, principal_user="", principal_identity=""), domain=PermissionMaskDomain(Permission, masks)))` |

`handle.registry` remains temporarily so unconverted internal
compiler tests still compile. `backend.register_relationship`,
`backend.register_ordered_fold`, and `backend.add_named_filter` are
the public 1.0 methods. `BackendHandle.register(...)` and
`BackendHandle.register_permission_condition(...)` are removed.
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

Migration-bot search list (Core plus the four active consumers:
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
`trusts.zero.decorators`. Core keeps only `authorization_required` and
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
relationship-family local (see Family-local Core aggregates below).
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

This file is the Core 1.x router only. It does not document concrete
Zero schema, UI, admin, or management-command steps.

## Family-local OR (#187)

| | Old | New |
| --- | --- | --- |
| Second family on one terminal | The second of `register_relationship` / `register_ordered_fold` (either order) raised `TrustsConfigurationError` (`AnyPath and OrderedFold cannot share one terminal`) | Both families may coexist on one content terminal of one exact backend path when user and permission terminals match |
| Authorization | One family per plan | Same-path family-local OR: `relationship_grant OR ordered_fold_grant`. This is the provisional same-path deferral while the engine still lives in Core. 1.0 list/guard aggregation is relationship-family local (#194); object-level Django backend OR is a different layer |
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

This file is the Core 1.x router only. It does not document concrete
Zero schema, UI, admin, or management-command steps.

## Family-local Core aggregates (#194 / #181)

| | Old | New |
| --- | --- | --- |
| Cross-handle list/guard aggregate | `.authorized`, `authorization_required`, and `filter_authorized_scopes` OR'd compiler predicates from every configured implementation handle in one SQL, including a co-installed fold-family plan | Those Core-owned helpers include relationship-family handles only (`implementation_for_path(handle.path)._authorization_family == "relationship"`). Fold-family handles are omitted, not ORed |
| `granted` / module-level `common_permissions` | Noun-blind OR of every given handle | Same compilation, after dropping owned non-relationship-family handles. Unowned isolated test handles stay (default `"relationship"`) |
| Mixin `has_perm` / `get_*_permissions` | Exact-path `_own_handle()` | Unchanged. Mixin projection still evaluates the own handle even when that handle's family is not `"relationship"` |
| Django `user.has_perm` | Ordered authentication-backend OR of object results | Unchanged. Do not read this as Core list/guard aggregation |
| Protected factories | `_ensure()` constructed `TrustsRegistry()`; `configured_backend()` constructed `BackendHandle` | `_create_registry(path)` and `_create_handle(path, registry, compiler)` on `TrustsImplementationConfig`. Freeze-on-first-live-read and exact-path ownership are unchanged |
| Family discriminator | None | Protected provisional `_authorization_family`, default `"relationship"`. Not a public family API |
| Applicability | Mixin and `common_permissions` hard-wired `plan.records or plan.strategy` | `QueryCompiler.applies(plan)`; relationship default is `bool(plan.records)`. Inapplicable backends stay 0 SQL before `:name` overlay. One authorization SQL per applicable backend invocation |
| `any_plan_records` | Consulted `plan.records or plan.strategy` | Same consult while the provisional engine still lives in Core. This is a support gate, not a mixed-family one-SQL contract. C2 drops the `strategy` arm |

QuerySet / common-permission / guard consequences:

- `Document.objects.authorized(user, permission)` no longer includes rows
  granted only by a fold-family handle.
- `authorization_required` preflight and grant composition see only
  relationship-family `auth.Permission` plans. A fold-only plan on a
  fold-family handle does not open the Core guard.
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

This file is the Core 1.x router only. It does not document concrete
Zero schema, UI, admin, or management-command steps.

## Archaeology

Chronology of unpublished development stairs lives in the annotated
non-release archive, not this file.

- Tag file: https://github.com/django-trusts/django-trusts/blob/migration-archive-pre-1.0/migrates.md
- Immutable SHA file: https://github.com/django-trusts/django-trusts/blob/7414886263faafb6edfb44c0c5fcf9fc8fa14e79/migrates.md

Do not copy that archive back onto `dev`.
