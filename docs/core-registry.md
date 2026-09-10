# TrustsRegistry (internal development primitive)

Additive registration and projection surface for issues #57 and #60.
Import from `trusts.core`. This slice does **not** re-export a
process-global registry from `trusts`.

`TrustsRegistry` is instantiable and isolated. `Ref(Model)` names a
permission-bearing relation root; attribute access builds a root-relative
path, including ordinary field names such as `root` and `path`. `register`
accepts those refs, validates them through Django `_meta` (zero SQL), and
stores one immutable `RegisteredRelation` per root. Inspect the inferred
root and paths on that record, not on `Ref`.

```python
from trusts.core import Ref, TrustsRegistry

j = Ref(DocumentGrant)
registry = TrustsRegistry()
record = registry.register(
    content=j.document,
    user=j.user,
    permission=j.permission,
)
```

This slice supports only direct single-valued forward relations (the
accepted DocumentGrant mock). Multi-valued, reverse, and generic foreign
key paths raise `TrustsConfigurationError`. `condition` may be omitted or
`None`; any other value is not supported yet.

## One plan, three projections

`plan_for` compiles every applicable `RegisteredRelation` into one
`RelationPlan`. Root selection, field correlation, and `EXISTS` assembly
live in that plan. The three development projections only change the
terminal:

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

Multiple applicable relation roots combine by SQL `OR`. Duplicate grant
rows do not duplicate permission or content results. An unregistered
content model fails closed: empty enumeration, `False`, and
`queryset.none()`.

Callers pass model instances for `user`, `content`, and `permission`.
This slice does not accept codename strings or dotted permission syntax.

This primitive does not change historical authorization results or add a
database schema. See [../migrates.md](../migrates.md).
