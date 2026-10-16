# Registry planning internals

Historical development record. Last source update: 2026-10-14. Reorganized
2026-10-16; this revision has not been reviewed by a human for current accuracy.

`TrustsRegistry` is instantiable and isolated. `Ref(Model)` names a
permission-bearing relation root; attribute access builds a root-relative
path, including ordinary field names such as `root` and `path`. `register`
accepts those refs, validates them through Django `_meta` and each step's
`get_path_info()` (zero SQL), and stores an immutable `RegisteredRelation`.
Inspect the inferred root, full path, lookup, and target field on that
record, not on `Ref`.

```python
from trusts.core import Ref, TrustsRegistry

j = Ref(FolderGrant)
registry = TrustsRegistry()
registry.register(
    content=j.folder,
    user=j.user,
    permission=j.permission,
)
registry.register(
    content=j.folder.documents,
    user=j.user,
    permission=j.permission,
)
```

One root may store more than one record when the content terminals differ
(`Folder` and `Document` above). `registry.records` is global insertion
order. `records_for_root(root)` returns that root's ordered tuple and
raises `TrustsConfigurationError` when the root is absent. There is no
`get(root)`: a single record would be ambiguous.

The [audit](../../SECURITY_AUDIT.md#relationship-paths) defines duplicate and
conflict handling for registrations.

## Stored predicates

The [audit](../../SECURITY_AUDIT.md#relationship-conditions) owns the public
symbolic grammar; this section describes private planning nodes.

Internal `TrustsRegistry.register` may still accept a closed predicate tree
exported from `trusts.core`. `condition` may also be omitted or `None`. The
nodes below are that stored planning representation:

```python
from trusts.core import All, Equal, Ref, permission_in

t = Ref(TeamRepoGrant)
registry.register(
    content=t.repository,
    user=t.team.members,
    permission=t.operation,
    condition=All(
        permission_in(t.team.permission_bundles.operations),
        Equal(t.team.organization, t.repository.organization),
    ),
)
```

- `All(*predicates)` — AND of one or more `All` / `Equal` /
  `permission_in` nodes
- `Equal(left, right)` — two root-relative forward single-valued refs
  that terminate on the same model and the same resolved comparison
  field (`to_field` / PK). Distinct unique fields on that model are
  rejected at registration (zero SQL) so stored-column `F()` comparison
  cannot fail open on colliding values
- `permission_in(*refs)` — each ref is a bounded ceiling path:
  forward singles, then either at most one intermediate reverse O2M
  and a terminal M2M or reverse O2M on the registered permission
  model, or exactly one intermediate M2M and a terminal M2M on that
  permission model (`….clusters.tokens`). Extra multi-steps, M2M then
  single, wrong terminals, GFK, and non-PK `to_field` membership
  targets fail closed at zero SQL. The compiler emits the whole
  accepted path.

## Resolved metadata

Each step's terminal model, complete root-relative lookup
(`'__'.join(path)`, for example `folder__rows__content`), and outer comparison
field come from resolved path metadata. Correlation does not assume `pk`,
does not assume the terminal field lives on the root, and does not
hand-code forward versus reverse identity. A non-primary
`ForeignKey(..., to_field=...)` still uses that target field (`#64`).

`plan_for` assembles a `RelationPlan` from applicable records. Root selection,
field correlation, and `EXISTS` assembly live there. `OuterRef` uses the last
step's single target `attname`; it must not substitute an assumed primary key.

The [inquiry reference](permission-inquiries.md) owns projection signatures,
return shapes, and query budgets.

## Identity field classification

The compiler classifies walk identities by `get_internal_type()`:

| Family | Accepted reported field types |
| --- | --- |
| integer | `AutoField`, `BigAutoField`, `SmallAutoField`, `IntegerField`, `BigIntegerField`, `SmallIntegerField`, `PositiveIntegerField`, `PositiveSmallIntegerField`, `PositiveBigIntegerField` |
| text | `CharField`, `TextField`, `SlugField`, including subclasses reporting one of these types |
| UUID | `UUIDField` |

UUID and text remain distinct because string formatting can collide. Other
reported types are rejected. The compiler re-resolves suffixes from the walk
site using stored relationship names; a suffix it cannot re-resolve is invalid.

## Live ownership and freezing

The live store is `TrustsImplementationConfig.registries[path]`, one
`TrustsRegistry` per configured Trusts-derived `AUTHENTICATION_BACKENDS`
path owned by that implementation. `ready()` does not replace the store
or an existing registry object. With one Trusts path, `config.registry`
is a compatibility alias of that exact object.

Supported live access is the AppConfig handle API:
`configured_backend(path)`, `configured_handles()`, and the one-path
`registry` alias. Each surface returns the stored object and freezes it
on first read once **that AppConfig's `self.apps.ready`** is true (after
`Apps.populate`, not during contributor `ready()`). A newly observed
configured path is frozen before the handle is returned, so a settings
change cannot expose a writable late registry. After readiness, the
`registry` setter also freezes the replacement before storing it, so a
caller-held reference cannot mutate the live store. Assignment before
ready stays writable for contributor setup and freezes on the first
supported post-populate read. Frozen `register()` raises
`TrustsConfigurationError` before validation or mutation; existing
records, plans, compilers, and authorization reads stay usable.

Isolated `TrustsRegistry()` instances are a different surface. They do
not inspect Django's global readiness, never auto-freeze, and stay
writable after `apps.ready` unless the owner calls `freeze()`. Internal
tests may swap a standalone instance into the live store for isolation;
hosts must not treat `registries[path]` as a contributor route. External
applications contribute declarations in their own `AppConfig.ready()`
through `configured_backend()` (an exact path is required when several
Trusts backends are listed). Trusts does not import or discover
`tests.Category`.

For system-check and renderer boundaries, see the
[audit](../../SECURITY_AUDIT.md#bounded-inherited-relationships).

`trusts.E003` reports already-loaded concrete, non-proxy, non-abstract
`Content` and `Junction` subclasses whose `get_content_model()` has no
covering record on any valid configured handle. One covering handle is enough.
Manual dependents outside those bases are not scanned. The check performs no
SQL and does not register anything.
