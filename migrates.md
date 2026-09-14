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

## View guard (#138)

| | Old | New |
| --- | --- | --- |
| Trusts-only object view | `permission_required(...)` (Django backend OR / `user.has_perm`) or a hand-rolled check | `authorization_required(Document, "myapp.change_document")` |
| Named condition on a view | colon suffix on the permission string, or `P` / `K` / `G` / `O` lookups | `authorization_required(Document, "myapp.change_document", ("non_confidential",))` |
| Candidate identity | `K` / `G` / `O`, GET, POST, or a custom kwarg | URL `kwargs["pk"]` only, bound to `model._meta.pk` |

`permission_required`, `P`, `K`, `G`, and `O` stay imported and
behavior-compatible. They are not the 1.0 guard. `authorization_required`
does not call `user.has_perm` and does not OR Django authentication
backends.

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
- `permission_required(`
- `from trusts.decorators import permission_required`
- `P(` / `K(` / `G(` / `O(`
- colon permission strings in views (`app_label.codename:name`)

This file is the Core 1.x router only. It does not document concrete
Zero schema, UI, admin, or management-command steps.

## Archaeology

Chronology of unpublished development stairs lives in the annotated
non-release archive, not this file.

- Tag file: https://github.com/django-trusts/django-trusts/blob/migration-archive-pre-1.0/migrates.md
- Immutable SHA file: https://github.com/django-trusts/django-trusts/blob/7414886263faafb6edfb44c0c5fcf9fc8fa14e79/migrates.md

Do not copy that archive back onto `dev`.
