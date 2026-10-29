# Brief for building features

Historical development record. Last source update: 2026-10-24.

Standing guidance for anyone, human or agent, adding a feature in this
repository. Follow the brief. The history records the reversals that
produced it.

The brief describes the design in progress on the open train, pull
requests
[#338](https://github.com/django-trusts/django-trusts/pull/338)
through
[#344](https://github.com/django-trusts/django-trusts/pull/344),
and the docs pull request
[#337](https://github.com/django-trusts/django-trusts/pull/337).
`TrustsConfigMixin`, `Registry`, and `get_registry()` exist on those
branches. They are not on `dev` yet. `dev` still registers through
`TrustsImplementationConfig`, `trusts_backend_paths`, and
`configured_backend()`, as in the [user guide](../source/index.rst).

## Brief

1. The Django `AppConfig` is the only singleton. Each app's own config,
   with a `TrustsConfigMixin` that calls `super()`, owns that app's
   recorder and catalog. Registration state stays off module globals,
   off handles, and off backend-path keys.
2. The public API is what the user guide shows. On this train the
   registration calls are `get_registry()` returning a `Registry`,
   `register`, `add_named_filter`, `set_user_condition`, and
   `set_user_override`. Changing that surface needs Thomas's sign-off.
3. A documentation example shows only the code an application must
   write. It does not add a setting such as `trusts_backend_paths`.
4. Name a thing by its role. Config and backend plumbing do not use
   the words Implementation, Owner, or Handle.
5. A public type is abstract. Each signature is written once.
6. A backend answers from its own catalog. Django's authentication
   backend loop ORs the results. Delete a path that lets one backend
   read another backend's catalog.
7. During a request, a backend that does not own the model or the
   permission returns `False` or an empty result. It does not raise.
8. Build and run stay separate. Each `register()` call is checked
   when it is made. A configuration error is reported at that line,
   or by a startup system check. The registry then freezes.
9. `register`, named filters, and user rules share one condition
   grammar.
10. Layering is fixed. `apps.py` and `Registry` do not import models.
    The plan layer does not import the compile layer. Import at the
    top of the module. Each of these rules has a test when the code
    is written.
11. A test checks public behavior. It does not patch an internal
    object or assert a private name.
12. A companion repository calls only the public API. Breaking a
    companion that reached past that API is acceptable.

Rules 1–4 settle who owns the registry. Rule 10 places `Registry`
before the code is written.

## Reversals

Measured on 2026-10-24 from `dev` at `57a6e9d` (the merge of
[#320](https://github.com/django-trusts/django-trusts/pull/320))
to `a50f714`, the tip of
[#344](https://github.com/django-trusts/django-trusts/pull/344) on that date.
271 non-merge commits, 165 files, +19,775/−28,238. Sixteen stacked
code pull requests:
[#321](https://github.com/django-trusts/django-trusts/pull/321),
[#323](https://github.com/django-trusts/django-trusts/pull/323),
[#324](https://github.com/django-trusts/django-trusts/pull/324),
[#328](https://github.com/django-trusts/django-trusts/pull/328)–[#331](https://github.com/django-trusts/django-trusts/pull/331),
[#333](https://github.com/django-trusts/django-trusts/pull/333),
[#334](https://github.com/django-trusts/django-trusts/pull/334),
and
[#338](https://github.com/django-trusts/django-trusts/pull/338)–[#344](https://github.com/django-trusts/django-trusts/pull/344).

Permission-policy SQL, gaps in `along=`, and the split between the
catalog and the compiler were learned by building them.

### A. Who owns the registry

Since
[#76](https://github.com/django-trusts/django-trusts/pull/76)
(merged 2026-09-11) the owner kept changing.

- A kernel `AppConfig` held the registry.
- [#76](https://github.com/django-trusts/django-trusts/pull/76)
  stored a registry per backend path, and introduced the handle.
- `TrustsImplementationConfig` and `trusts_backend_paths` are still
  the example on `dev`. Test configs took names such as
  `KernelHostConfig` and `IsolatedOwnerConfig`.
- [#158](https://github.com/django-trusts/django-trusts/pull/158)
  made `BackendHandle.register` the public registration call. The
  `BackendHandle` class itself came in with
  [#76](https://github.com/django-trusts/django-trusts/pull/76).
- Three closed restarts:
  [#325](https://github.com/django-trusts/django-trusts/pull/325),
  [#326](https://github.com/django-trusts/django-trusts/pull/326),
  and
  [#327](https://github.com/django-trusts/django-trusts/pull/327).
- A module-level dict. Thomas's sketches on 2026-10-18 and
  2026-10-19 put `registries` and `recorders` in `trusts/backends.py`.
  Those commits are on the closed
  [#327](https://github.com/django-trusts/django-trusts/pull/327)
  line and remain in the ancestry of the open stack. The
  misunderstanding was shared.
- [#330](https://github.com/django-trusts/django-trusts/pull/330)
  gave each app config its own recorder and catalog, and removed
  `get_registry()`.
- [#338](https://github.com/django-trusts/django-trusts/pull/338)
  restored `get_registry()`. The tip of
  [#344](https://github.com/django-trusts/django-trusts/pull/344)
  types that return value as `Registry`.

Nothing had stated that the app config is the singleton.
`load_backend()` constructs a new backend instance on every call, so
later work kept inventing another object to hold the registry. Names
such as `TrustsImplementationConfig`, `KernelHostConfig`, and
`IsolatedOwnerConfig` describe that extra owner. The brief puts the
state on the app's own config, through the mixin.

### B. Backends crossing

[#183](https://github.com/django-trusts/django-trusts/pull/183)
(merged 2026-09-14) makes QuerySet authorization share-nothing: a
backend answers from its own data. Code that crossed backends stayed
in the tree until
[#342](https://github.com/django-trusts/django-trusts/pull/342)
deleted it.

### C. When a registration is checked

The moment of the check moved.
[#325](https://github.com/django-trusts/django-trusts/pull/325)
deferred lowering until build.
[#326](https://github.com/django-trusts/django-trusts/pull/326)
held the lowered object on the config.
[#330](https://github.com/django-trusts/django-trusts/pull/330)
froze recorders during `ready()`.
[#338](https://github.com/django-trusts/django-trusts/pull/338)
built the catalog on the first question.
[#341](https://github.com/django-trusts/django-trusts/pull/341)
checks each registration call when it is recorded. Request time does
not build the catalog.

### D. Condition grammar

Each registration path grew its own condition syntax.
[#333](https://github.com/django-trusts/django-trusts/pull/333)
stores one condition tree for `register`, named filters, and user
rules.

### E. Import cycles

[#321](https://github.com/django-trusts/django-trusts/pull/321)
and
[#323](https://github.com/django-trusts/django-trusts/pull/323)
are 39 commits of moving modules apart (13 on #321, 26 on #323).
Later commits pushed helpers down so `trusts.backends` would not
import the plan layer. `AppRegistryNotReady` was raised on
2026-10-18, when `trusts/apps.py` imported `trusts.backends` (that
module imports `auth.Permission`), and again on 2026-10-21 while
[#330](https://github.com/django-trusts/django-trusts/pull/330)
moved imports. There was no layering rule at the start.

### F. Tests pinned to internals

[#331](https://github.com/django-trusts/django-trusts/pull/331)
deletes tests that patched compilers and asserted private names,
along with other test-only surfaces.

### G. Fail closed

[#343](https://github.com/django-trusts/django-trusts/pull/343)
revisits a request whose model or permission the backend does not
own. The backend returns `False` or an empty queryset. Registration
and `ready()` still raise.
