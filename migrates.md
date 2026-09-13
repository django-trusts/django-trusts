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
3. Register protected models and named-condition **builders** through
   `handle.register_permission_condition` in `AppConfig.ready()` before
   finalization. `register(...)` remains the public registration entry
   for implementation wiring.
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

This file is the Core 1.x router only. It does not document concrete
Zero schema, UI, admin, or management-command steps.

## Public relation registration

`BackendHandle.register` is the application registration entry for
AnyPath relations. Path strings use Django `__` grammar. `Ref` input
on the handle is `TypeError`. `handle.registry` remains only for
unconverted companion trees.

| | Previous | Current |
| --- | --- | --- |
| Relation register | `from trusts.core import Ref` plus `handle.registry.register(content=j.document, ...)` | `handle.register(DocumentGrant, user="user", permission="permission", content="document")` |
| Along | `along=Along(j.parent, 8)` | `along=("parent", 8)` |
| Closed condition | `Equal(t.team.organization, t.repository.organization)` | `Equal("team__organization", "repository__organization")` |

Named `:condition` builders stay `handle.register_permission_condition`.
The six-name `trusts.conditions` API is unchanged. Isolated
`TrustsRegistry.register` still accepts internal `Ref` objects.

Migration-bot checklist:

- [ ] Search for `from trusts.core import Ref` in application `ready()` / README / RST.
- [ ] Search for `Ref(`.
- [ ] Search for `.registry.register(`.
- [ ] Search for `.registry.register_strategy(`.
- [ ] Search for `Along(`.
- [ ] Retarget application relation registration to `handle.register` with `__` paths.
- [ ] Keep named-condition builders on `handle.register_permission_condition`.

## Archaeology

Chronology of unpublished development stairs lives in the annotated
non-release archive, not this file.

- Tag file: https://github.com/django-trusts/django-trusts/blob/migration-archive-pre-1.0/migrates.md
- Immutable SHA file: https://github.com/django-trusts/django-trusts/blob/7414886263faafb6edfb44c0c5fcf9fc8fa14e79/migrates.md

Do not copy that archive back onto `dev`.
