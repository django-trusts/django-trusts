# TrustsRegistry (internal development primitive)

Historical development record. Last source update: 2026-10-14.
This reorganization has not been reviewed by a human for current accuracy.

Additive registration and projection surface for issues #57, #60, #65,
#83, #92, #98, and the first historical reader in #67. Import from `trusts.core`.
This slice does **not** re-export a process-global registry from `trusts`.

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

Exact duplicate normalized registration raises. The same root plus the
same content terminal with different content/user/permission/along
bindings is an explicit conflict. The same bindings with a different
closed condition is an allowed alternative; the plan ORs matching
records. Different roots remain supported.

A permission path ends on one forward to-one step, or on one forward
to-many step to `auth.Permission`. To-one means a foreign key or
one-to-one. To-many means a many-to-many. Those words name the relation
shape, not how many permission rows the terminal holds. Zero or more
forward to-one steps may precede the to-many terminal (`permissions`,
`team__permissions`). The direct to-one step is unchanged and may still
name whatever model that relation points at, including a custom
permission model. The to-many step's comparison field is the permission
primary key. A user path may be that same direct step, or zero or more
forward single-valued steps followed by exactly one terminal
many-to-many membership step (the accepted GH `t.team.members`
mapping). Reverse one-to-many requester paths stay rejected so existing
direct-user fail-closed tests remain. A content path may be a direct
step, or one or more forward single-valued steps, then a reverse
one-to-many gateway, then zero to two suffix steps. A suffix step is a
forward single-valued, reverse one-to-one, or reverse one-to-many
relation.

```text
permission := direct to-one terminal
            | (forward to-one step)*  forward to-many terminal
direct to-one terminal := exactly one forward to-one step
forward to-many terminal := one forward many-to-many step to auth.Permission
user := one forward single-valued
      | (forward single-valued)*  M2M
content := (forward single-valued)+  reverse O2M  suffix{0..2}
suffix step := forward single-valued | reverse O2O | reverse O2M
```

Prefix steps, when there are any, are to-one. Only the terminal may be
to-many, and a to-many terminal must be `auth.Permission`. A to-many
step before the terminal still fails closed. A reverse to-many
permission collection still fails closed. A direct to-one permission
target, including a custom permission model, is unchanged.

A `permission=` collection is not a `group=` registration. `via_group`
stays false, and the record does not contribute to
`get_group_permissions()`.

An intermediate many-to-many on `permission=` is still rejected at
registration. That keeps the current fail-closed rule. Supporting an
intermediate collection is deferred to a later change; this grammar
does not reject that shape as a design direction.

These shapes raise `TrustsConfigurationError` during `register`:

- reverse relations before the gateway, or a reverse as the only step
- reverse one-to-one as the gateway
- many-to-many except as the terminal user membership step or the
  terminal `permission=` collection (an intermediate permission
  collection is still rejected here, and that rejection is deferred
  rather than permanent)
- a permission collection that is a reverse many-to-many or that does
  not terminate on `auth.Permission`
- a permission collection whose through-table target is not the
  permission primary key
- multi-step all-forward permission without a terminal collection
- extra or intermediate multi-valued walks on user, content, or
  condition paths
- generic foreign keys/relations
- more than two steps after the gateway
- multi-step all-forward content (no gateway reverse)
- multi-step all-forward user without a terminal membership step
- arbitrary multi-valued chains
- composite / multi-column correlation (`get_path_info()` must yield
  exactly one `PathInfo` with exactly one target field)

Public `BackendHandle.register(..., condition=...)` accepts a one-argument
trust-rooted symbolic callable (`==`, `.contains(member)`, `&`) and rejects
prebuilt `All` / `Equal` / `permission_in` values. The callable is invoked
once after freeze and is not stored.

Internal `TrustsRegistry.register` may still accept a closed condition tree
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

Those conditions compile as an AND overlay on the same
permission-bearing root row. They do not create a grant. Callables,
`Q` objects, lookup strings, and tuples are not a condition dialect
and raise `TrustsConfigurationError` with zero SQL. Untyped values
still report that `condition` is not supported.

Optional `Along(ref, bound)` replaces equality at one walk-site with bounded
grant-anchored reachability. Pass `along=` to `register()`. Validation uses
`_meta` only (zero SQL) and runs after the frozen check. `bound` is an
integer in `1..64` (`bool` is rejected). The walk-site is the longest common
prefix of `along.ref.path` and the content path; remaining Along steps are
the directed edge; remaining content steps are the suffix.

Edge steps are one of:

```text
S := one forward single-valued self-step on the walk-site   (Along(j.node.parent))
C := one reverse O2M self-step on the walk-site             (Along(j.node.children))
E := reverse O2M onto an edge model, then one forward
     single-valued step back to the walk-site               (Along(j.node.parent_links.parent))
```

The same resolved identity field (`get_path_info()[0].target_fields[0]`,
including non-PK `to_field`) must appear on the grant walk step and both
Along edge ends. V1 then admits only one identity family per record:

| Family | `get_internal_type()` |
| --- | --- |
| integer | `AutoField`, `BigAutoField`, `SmallAutoField`, `IntegerField`, `BigIntegerField`, `SmallIntegerField`, `PositiveIntegerField`, `PositiveSmallIntegerField`, `PositiveBigIntegerField` |
| text | `CharField`, `TextField`, `SlugField` (and subclasses that report `CharField`, such as `EmailField`) |
| uuid | `UUIDField` |

`UUIDField` is a distinct family from
`CharField` / `SlugField` / `TextField` (hyphenation collision). Mixed
families, BLOB/date/decimal/float/boolean/JSON/IP identities, unsupported
S/C/E edges, empty walk-site/edge, and suffixes that cannot be re-resolved
from the walk-site via stored names all raise `TrustsConfigurationError`
before mutation.

V1 compiles `GrantReach` for Django's sqlite3, postgresql, and mysql
backends. The walk is uncorrelated with candidate rows: one plain
`IN (WITH RECURSIVE …)` per recursive record. The recursive member is
`UNION ALL` plus a join to the next hop. A depth column capped at
`bound` guarantees termination. It is not a seen-set. On SQLite and
MySQL, `UNION ALL` can revisit a cycle. PostgreSQL's
`CYCLE ident SET is_cycle USING path` clause prunes only a path that
revisits an ident already on that same path. A diamond is not such a
path, so fan-out to the same node by two routes multiplies on all three
engines, bounded by the cap. The final `DISTINCT` keeps the reachable
set correct. That growth is the accepted tradeoff for dropping the JSON
seen-set. There is no JSON frontier or seen-array.
Depth 0 is the seed. Nodes at `bound` are reachable and not expanded.
NULL and dangling steps deny. Direct and recursive registrations `OR`.
In this snapshot, the lockfile records that portable statement (SQLite identifier quotes).
SQLite and MySQL 8.4+ execute it unchanged, aside from MySQL's backtick
quotes. PostgreSQL keeps the depth cap and appends that one clause.
The outer query still selects only the walk identity, so `is_cycle`
and `path` are not projected. That is not a second lockfile.
MariaDB is not supported yet: `connection.mysql_is_mariadb` fails
closed with the same error as any other unsupported engine, at runtime
and in `trusts.E005`, before the probe. A closure table is a documented
fallback only and is not generated.

The inquiry for users from content uses the same statement in the inverse direction. The
seed is the content-derived walk-site identity or identities. A
non-empty suffix selects the walk-site rows related to the bound
content, such as Cabinet identities for a Sheet. The recursive member
does not reference the outer user. Shape S walks to parents, shape C
walks to children, and shape E walks from child to parent. Eligible
grants and candidate users join that walk outside the CTE, and the
grant query is correlated to the outer candidate user only after the
walk. PostgreSQL still appends the one `CYCLE` clause. SQLite and MySQL
8.4+ keep the plain statement. MariaDB still fails closed before that
SQL. The lockfile records the plain reverse statement with the forward
statements.

A non-empty content suffix compiles a walk-model-rooted `EXISTS` from the
stored path names (`items__image`, `rows__content`, …). Every S5 suffix
already accepted by ordinary `register()` is supported; there is no quieter
Along subset and no reverse-name guessing. When the suffix is exactly one
reverse O2M/O2O step whose FK lives on the candidate and targets
`walk_ident`, the compiler may rewrite to `candidate.<fk> IN W`.

Conditions remain an AND overlay on a proof and never run on
intermediate walk nodes. The same expression drives instance
authorization, lazy `filter_authorized` before pagination, `all_match`,
and `permissions` / `common_permissions` (including nested permission
`OuterRef`). The inquiry for users from content derives walk-site identities from the bound
content, traverses the inverse graph without the outer candidate user, and
joins eligible grants and users outside the CTE. It preserves the terminal
condition and user checks from the forward proof; conditions do not apply to
intermediate walk nodes. Unsupported vendors raise `TrustsConfigurationError`
before walk SQL. Residual database errors stay loud and are not remapped to
`TrustsCompilerError`. Runtime authorization does not repeat the recursive
CTE capability probe.

In this snapshot, policy SQL exports the same recursive condition for each inquiry,
including users from content. Each trust row records the public `along`
path, resolved shape, and bound. The bound is a registration constant, not a
runtime binding. Rendering fails before returning a partial document if any
applicable recursive statement or parameter cannot be represented.

Implementation agreement tests compare the returned user set with per-user
object checks for the same content and permission. They cover depth exactly
at the bound and one hop beyond it, cycles, a failing condition, an inactive
user, two `Along` registrations on one content model ORed together, and
policy-lock rendering for each registered walk. The implementation change
records combined statement-plus-branch coverage before and after and does not
lower it.

`trusts.E005` (`Tags.database`) reports each selected alias whose live
Along records cannot render. It honors Django's `databases` argument
exactly and never falls back to `default`. Absent or empty `databases`
opens no connections, executes no SQL, and is not an all-clear. Isolated
`TrustsRegistry()` instances are not scanned. Silencing `trusts.E005`
hides only the diagnostic.

Each step's terminal model, root-relative lookup
(`'__'.join(path)`, for example `folder__rows__content`), and outer comparison
field come from resolved path metadata. Correlation does not assume `pk`,
does not assume the terminal field lives on the root, and does not
hand-code forward versus reverse identity. A non-primary
`ForeignKey(..., to_field=...)` still uses that target field (`#64`).

Inquiry projections are documented in
[permission inquiries](permission-inquiries.md#one-plan-three-projections).

Every app that hosts Trusts registrations or a Trusts backend must extend `TrustsConfigMixin` on its Django `AppConfig`, so the app owns its catalog.
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

`trusts.E003` reports already-loaded concrete, non-proxy, non-abstract
`Content` subclasses and `Junction` subclasses whose
`get_content_model()` has no covering record on any valid configured
handle. Coverage on one handle is enough. Manual dependents that are
neither Content nor Junction are outside E003 and fail closed at
runtime. The check issues zero SQL and does not register.
`trusts.E005` is the Along renderer database check described above.

Public and historical inquiry adapters are documented in
[permission inquiries](permission-inquiries.md#generic-public-seams-54-c1).

`ConditionLookup` (`record_for`, `compile_q`) is self-bound at
`TrustsRegistry` construct. `set_condition_lookup` remains for tests
and explicit unbind. Missing methods raise
`TrustsConfigurationError` and do not bind.
Every app that hosts Trusts registrations or a Trusts backend must extend `TrustsConfigMixin` on its Django `AppConfig`, so the app owns its catalog.
Resolve a live registry with `implementation_for_path()`,
`implementation_for_class()`, or `configured_implementation_handles()`.
Core ships no AppConfig and no `kernel_config()`. After Zero is
installed, `apps.get_app_config('trusts')` is ZeroConfig (models and
that implementation's registry store). Do not list `'trusts'` in
`INSTALLED_APPS`.

This primitive does not change historical authorization results or add a
database schema. See [../migrates.md](../source/migrates.md).
