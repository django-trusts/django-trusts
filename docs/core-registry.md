# TrustsRegistry (internal development primitive)

Additive registration and projection surface for issues #57, #60, #65,
#83, #92, #98, and the first historical reader in #67. Import from `trusts.core`.
This slice does **not** re-export a process-global registry from `trusts`.

`TrustsRegistry` is instantiable and isolated. `Ref(Model)` names a
permission-bearing relation root; attribute access builds a root-relative
path, including ordinary field names such as `root` and `path`. `register`
accepts those refs, validates them through Django `_meta` and each hop's
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
closed condition is an allowed alternative; the plan ORs complete
records. Different roots remain supported.

Permission refs remain one direct single-valued hop. A user path may be
that same direct hop, or zero or more forward single-valued hops followed
by exactly one terminal many-to-many membership hop (the accepted GH
`t.team.members` mapping). Reverse one-to-many requester paths stay
rejected so existing direct-user fail-closed tests remain. A content
path may be a direct hop, or one or more forward single-valued hops,
then a reverse one-to-many gateway, then zero to two suffix hops. A
suffix hop is a forward single-valued, reverse one-to-one, or reverse
one-to-many relation.

```text
user := one forward single-valued
      | (forward single-valued)*  M2M
content := (forward single-valued)+  reverse O2M  suffix{0..2}
suffix hop := forward single-valued | reverse O2O | reverse O2M
```

These shapes raise `TrustsConfigurationError` during `register`:

- reverse relations before the gateway, or a reverse as the only hop
- reverse one-to-one as the gateway
- many-to-many except as the terminal user membership hop
- extra or intermediate multi-valued walks on user, content, or
  predicate paths
- generic foreign keys/relations
- more than two hops after the gateway
- multi-hop all-forward content (no gateway reverse)
- multi-hop all-forward user without a terminal membership hop
- arbitrary multi-valued chains
- composite / multi-column correlation (`get_path_info()` must yield
  exactly one `PathInfo` with exactly one target field)

`condition` may be omitted, `None`, or a closed predicate tree exported
from `trusts.core`:

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
  permission model (`….clusters.tokens`). Extra multi-hops, M2M then
  single, wrong terminals, GFK, and non-PK `to_field` membership
  targets fail closed at zero SQL. The compiler emits the whole
  accepted path.

Those predicates compile as an AND overlay on the same
permission-bearing root row. They do not create a grant. Callables,
`Q` objects, lookup strings, and tuples are not a condition dialect
and raise `TrustsConfigurationError` with zero SQL. Untyped values
still report that `condition` is not supported.

Optional `Along(ref, bound)` replaces equality at one walk-site with bounded
grant-anchored reachability. Pass `along=` to `register()`. Validation uses
`_meta` only (zero SQL) and runs after the frozen check. `bound` is an
integer in `1..64` (`bool` is rejected). The walk-site is the longest common
prefix of `along.ref.path` and the content path; remaining Along hops are
the directed edge; remaining content hops are the suffix.

Edge hops are one of:

```text
S := one forward single-valued self-hop on the walk-site   (Along(j.node.parent))
C := one reverse O2M self-hop on the walk-site             (Along(j.node.children))
E := reverse O2M onto an edge model, then one forward
     single-valued hop back to the walk-site               (Along(j.node.parent_links.parent))
```

The same resolved identity field (`get_path_info()[0].target_fields[0]`,
including non-PK `to_field`) must appear on the grant walk hop and both
Along edge ends. V1 then admits only one JSON identity family per record:

| Family | `get_internal_type()` |
| --- | --- |
| integer | `AutoField`, `BigAutoField`, `SmallAutoField`, `IntegerField`, `BigIntegerField`, `SmallIntegerField`, `PositiveIntegerField`, `PositiveSmallIntegerField`, `PositiveBigIntegerField` |
| text | `CharField`, `TextField`, `SlugField` (and subclasses that report `CharField`, such as `EmailField`) |
| uuid | `UUIDField` |

`UUIDField` is a JSON-string carrier but a distinct family from
`CharField` / `SlugField` / `TextField` (hyphenation collision). Mixed
families, BLOB/date/decimal/float/boolean/JSON/IP identities, unsupported
S/C/E edges, empty walk-site/edge, and suffixes that cannot be re-resolved
from the walk-site via stored names all raise `TrustsConfigurationError`
before mutation.

V1 compiles `GrantReach` only for Django's `django.db.backends.sqlite3`
backend with JSON functions and recursive CTEs. The walk is uncorrelated
with candidate rows: one `IN (WITH RECURSIVE …)` per recursive record,
generation-level `frontier`/`seen`, identity-level cycle suppression, and a
final join of JSON values back to the typed walk-model identity column.
Depth 0 is the seed. Nodes at `bound` are reachable and not expanded.
NULL and dangling hops deny. Direct and recursive registrations `OR`.

A non-empty content suffix compiles a walk-model-rooted `EXISTS` from the
stored path names (`items__image`, `rows__content`, …). Every S5 suffix
already accepted by ordinary `register()` is supported; there is no quieter
Along subset and no reverse-name guessing. When the suffix is exactly one
reverse O2M/O2O hop whose FK lives on the candidate and targets
`walk_ident`, the compiler may rewrite to `candidate.<fk> IN W`.

Conditions remain an AND overlay on a complete proof and never run on
intermediate walk nodes. The same expression drives instance
authorization, lazy `filter_authorized` before pagination, `all_match`,
and `permissions` / `common_permissions` (including nested permission
`OuterRef`). Unsupported vendors raise `TrustsConfigurationError` before
walk SQL. Residual database errors stay loud and are not remapped to
`TrustsCompilerError`. Runtime authorization does not repeat the JSON/CTE
capability probe.

`trusts.E005` (`Tags.database`) reports each selected alias whose live
Along records cannot render. It honors Django's `databases` argument
exactly and never falls back to `default`. Absent or empty `databases`
opens no connections, executes no SQL, and is not an all-clear. Isolated
`TrustsRegistry()` instances are not scanned. Silencing `trusts.E005`
hides only the diagnostic.

Each hop's terminal model, complete root-relative lookup
(`'__'.join(path)`, for example `folder__rows__content`), and outer comparison
field come from resolved path metadata. Correlation does not assume `pk`,
does not assume the terminal field lives on the root, and does not
hand-code forward versus reverse identity. A non-primary
`ForeignKey(..., to_field=...)` still uses that target field (`#64`).

## One plan, three projections

`plan_for` selects applicable records by content/user/permission terminal
and compiles them into one `RelationPlan`. Root selection, field
correlation, and `EXISTS` assembly live in that plan. Bindings and
`EXISTS` use the complete stored lookup. `OuterRef` uses the last hop's
single target `attname`. The three development projections only change
the terminal:

```python
registry.permissions_for(user, document)
registry.has_permission(user, document, permission)
registry.filter_authorized(Document.objects.all(), user, permission)
```

- Permission enumeration projects distinct permission rows for
  `(user, content)`.
- Object authorization is SQL `EXISTS` membership of the requested
  permission in that same relational result. It does not materialize a
  Python list from enumeration.
- Authorized-content filtering returns a lazy `QuerySet` and correlates
  the same predicate to each candidate content row. Filtering happens in
  SQL before pagination or aggregation.

`RelationPlan.content_exists(user, permission)` is the shared
content-`EXISTS` predicate. `filter_content` / `filter_authorized`
consume that same object. A later reader may OR it with another predicate
on the original candidate queryset; do not filter trustee rows first and
then try to restore another branch.

Multiple applicable relation roots combine by SQL `OR`. Duplicate grant
rows do not duplicate permission or content results. An unregistered
content model fails closed: empty enumeration, `False`, and
`queryset.none()`.

Callers pass model instances for `user`, `content`, and `permission`.
This slice does not accept codename strings or dotted permission syntax.

`RelationPlan` projection methods require model-instance bindings; a
supplied `None` or other non-instance value raises
`TrustsConfigurationError` and is never omitted from the predicate.

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

`ContentQuerySet.permitted` is a thin aggregate caller. It ORs each
applicable handle compiler's complete predicate (`trusts.core.granted`)
and then applies the unchanged condition overlay. Concrete
`TrustModelBackend` routes keep the transitional historical TrustGroup
compiler; mixin-only routes receive only their registered-plan proof.
Public signature and documented one-path results are unchanged.
Unknown or undeclared terminals fail closed (empty / false / none).
`historical_fallback` identifies the concrete
`HistoricalGroupQueryCompiler` for mixin isolation; it does not reopen
a static content map. Mixin-only routes receive only their registered
plan proof.

Declared Category, Ticket, Trust, Group, documented dependents, and
any other registered content model — including ordinary non-`Content`
models — use the same handle and compiler for backend `has_perm` /
`get_all_permissions` / `get_group_permissions`. An instance consults
that backend's handle first. A QuerySet is coordinated by the first
configured Trusts path: one aggregate all-match / common-permission
query; other Trusts backends return false/empty with no SQL.
`obj is None` is false/empty on a Trusts backend; hosts that want
global Django permissions list
`django.contrib.auth.backends.ModelBackend` separately. Declared
Junction-backed Group uses the registered J1 plan and the concrete
compiler's TrustGroup OR. Group-as-protected-content does not replace
Django Group membership as the historical trustee path for Category /
Ticket / Trust. QuerySet plus a legacy callable condition raises
`PermissionConditionNotQueryable` before candidate SQL or callback
invocation. The Trusts app contributes Trust-as-content to every
configured `TrustModelBackend` (or subclass) path; the test app
contributes Category, Ticket, and Junction-backed Group onto the
unique handle. Hosts contribute documented dependents from their own
`AppConfig`.

`TrustManager.filter_by_user_content_perm` is a create-under-Trust
picker, not a content-row filter. Its support gate is
`any_plan_records`: any configured path with `plan_for(content).records`
establishes that the terminal is known. The grant remains
`trust_grant_q` on Trust rows. A declaration on one path does not
authorize through another path's compiler or `historical_fallback`, and
the method is not redirected through `filter_authorized(Trust)` or the
Trust-as-content parent relation. Unregistered models return `none()`.
Declared Group is a known terminal; create-under-Trust still uses
`trust_grant_q` on Trust rows.

## Generic public seams (#54 C1)

These additive APIs are the instance-only / metadata-driven surfaces that
later Zero and GH hosts call. They do not change `ContentQuerySet.permitted`,
`filter_by_user_content_perm`, the app label, or the historical compiler.

`AuthorizedQuerySet.authorized(user, permission, extra_q=None)` and
`AuthorizedManager = Manager.from_queryset(AuthorizedQuerySet)` live in
`trusts.query`. `permission` is a model instance. Strings raise
`TrustsConfigurationError` with zero SQL. The method does not parse
`:condition`, does not call `is_active_principal`, and does not call
`get_permission`. `extra_q` is the same AND overlay as `all_match` /
`instance_match`. There is no `.permitted` and no `.get_permission` on
this class.

`filter_authorized_scopes(queryset, user, permission, *, content, handles=None)`
in `trusts.core` filters rows of an intermediate scope model that is a
**proper prefix** of some applicable `RegisteredRelation.content_path`
whose content terminal is `content`. It compiles `EXISTS` of root rows
correlated to `OuterRef` of that hop's resolved target field (the
related `attname` from `get_path_info()`, including non-PK
`ForeignKey(..., to_field=...)`) at that node, binds user +
permission, and ORs applicable records. `queryset.model` equal to the
content terminal is allowed when a proper prefix hop of that same model
exists (self-referential trees). A terminal-only path, an unknown
terminal, empty handles, or a scope model not on the path return
`none()`. Core does not import Zero schema models
(`Trust`, `TrustUserPermission`, `TrustGroup`, …).

`PlanQueryCompiler.group_exists` compiles the membership-hop subset of
the same plan (user path ending in M2M) via `RelationPlan.content_exists`.
Direct FK / O2O / reverse user hops stay out of the group slice.
An OrderedFold `strategy` makes `group_exists` inapplicable (`None`).

`ConditionLookup` (`record_for`, `compile_q`) is self-bound at
`TrustsRegistry` construct. `set_condition_lookup` remains for tests
and explicit unbind. Missing methods raise
`TrustsConfigurationError` and do not bind.
Live registries are owned by installed `TrustsImplementationConfig`
subclasses. Resolve them with `implementation_for_path()`,
`implementation_for_class()`, or `configured_implementation_handles()`.
Core ships no AppConfig and no `kernel_config()`. After Zero is
installed, `apps.get_app_config('trusts')` is ZeroConfig (models and
that implementation's registry store). Do not list `'trusts'` in
`INSTALLED_APPS`.

This primitive does not change historical authorization results or add a
database schema. See [../migrates.md](../migrates.md).
