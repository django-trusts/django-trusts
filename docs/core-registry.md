# TrustsRegistry (internal development primitive)

Additive registration surface for issue #57. Import from `trusts.core`.
This slice does **not** re-export a process-global registry from `trusts`.

`TrustsRegistry` is instantiable and isolated. `Ref(Model)` names a
permission-bearing relation root; attribute access builds a root-relative
path. `register` accepts those refs, validates them through Django `_meta`
(zero SQL), and stores one immutable `RegisteredRelation` per root.

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

This primitive does not compile queries, change authorization results, or
add a database schema. See [../migrates.md](../migrates.md).
