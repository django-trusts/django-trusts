# TrustsRegistry (internal development primitive)

Additive registration and projection surface for issues #57, #60, #65,
and the first historical reader in #67. Import from `trusts.core`. This
slice does **not** re-export a process-global registry from `trusts`.

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
same content terminal with a different path or different user/permission
paths is an explicit conflict. Same-root multiple paths to one content
model are unsupported; this slice does not invent precedence. Different
roots remain supported.

User and permission refs remain one direct single-valued hop. A content
path may be that same direct hop, or one or more forward single-valued
hops followed by exactly one final reverse one-to-many hop.

These shapes raise `TrustsConfigurationError` during `register`:

- reverse relations before the final hop, or a reverse as the only hop
- reverse one-to-one
- many-to-many
- generic foreign keys/relations
- anything after the final reverse hop
- multi-hop all-forward content (no trailing reverse)
- arbitrary multi-valued chains
- composite / multi-column correlation (`get_path_info()` must yield
  exactly one `PathInfo` with exactly one target field)

`condition` may be omitted or `None`; any other value is not supported yet.

Each hop's terminal model, complete root-relative lookup
(`'__'.join(path)`, for example `folder__documents`), and outer comparison
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

The live store is `trusts.apps.AppConfig.registries[path]`, one
`TrustsRegistry` per configured Trusts-derived `AUTHENTICATION_BACKENDS`
path. `ready()` does not replace the store or an existing registry
object. With one Trusts path, `config.registry` is a compatibility alias
of that exact object. Isolated tests still construct their own
`TrustsRegistry()`. External applications contribute declarations in
their own `AppConfig.ready()` through `configured_backend()` (an exact
path is required when several Trusts backends are listed). Trusts does
not import or discover `tests.Category`.

`ContentQuerySet.permitted` is a thin aggregate caller. It ORs each
applicable handle compiler's complete predicate (`trusts.core.granted`)
and then applies the unchanged condition overlay. Concrete
`TrustModelBackend` routes keep the transitional historical TrustGroup
compiler; mixin-only routes receive only their registered-plan proof.
Public signature and documented one-path results are unchanged.
Unregistered-on-every-path models keep `trust_grant_q`. Backend
`has_perm` is not migrated. The Trusts app contributes Trust-as-content
to every configured `TrustModelBackend` (or subclass) path; the test app
contributes Category and Ticket onto the unique handle.

This primitive does not change historical authorization results or add a
database schema. See [../migrates.md](../migrates.md).
