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
3. Register protected models through `handle.register(root, user=...,
   permission=..., content=...)` and named-condition **builders** through
   `handle.register_permission_condition` in `AppConfig.ready()` before
   finalization.
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
| Relation register | `from trusts.core import Ref` + `handle.registry.register(content=j.document, ...)` | `handle.register(DocumentGrant, user="user", permission="permission", content="document")` |
| Along | `along=Along(j.parent, 8)` | `along=("parent", 8)` |
| Closed condition | `Equal(t.team.organization, t.repository.organization)` | `Equal("team__organization", "repository__organization")` |

`handle.registry` remains temporarily so unconverted consumers still
compile. `handle.register_strategy` is not a public method yet.

Migration-bot search list:

- `from trusts.core import Ref`
- `Ref(`
- `.registry.register(`
- `.registry.register_strategy(`
- `Along(`

This file is the Core 1.x router only. It does not document concrete
Zero schema, UI, admin, or management-command steps.

## Archaeology

Chronology of unpublished development stairs lives in the annotated
non-release archive, not this file.

- Tag file: https://github.com/django-trusts/django-trusts/blob/migration-archive-pre-1.0/migrates.md
- Immutable SHA file: https://github.com/django-trusts/django-trusts/blob/7414886263faafb6edfb44c0c5fcf9fc8fa14e79/migrates.md

Do not copy that archive back onto `dev`.
