# Migrating to django-trusts 1.0

django-trusts 1.0 is a step change from django-trusts 0.x. It is not API,
model, or schema compatible with the 0.x package. Version 1.0 is a
schema-neutral authorization library and does not provide a direct migration
path for applications using the historical Trust and Content implementation.

The compatibility layer for django-trusts 0.x is
[django-trusts-zero](https://github.com/django-trusts/django-trusts-zero).
Existing 0.x applications should install that package and follow its
[migration guide](https://github.com/django-trusts/django-trusts-zero/blob/dev/migrates.md).
That is the supported 0.x migration path.

Applications adopting schema-neutral django-trusts 1.0 as a new integration
should follow the
[usage guide](https://django-trusts.readthedocs.io/en/dev/).

## Explicit `auth.Group` registration (#246)

| | Old | New |
| --- | --- | --- |
| `get_group_permissions(obj)` | Core treated a `permission=` trust as group-derived when its user path ended in a many-to-many membership hop | Only an explicit `register(..., group=...)` contributes. Membership shape is not a Django group |
| `register(..., permission=...)` | Direct permission path; ordinary authorization | Unchanged. Still authorizes through `has_perm`, `get_all_permissions`, `.authorized`, and fixed queries. Does not feed `get_group_permissions` |
| `register(..., group=...)` | Not available | Forward single-valued path that must end at `auth.Group`. The compiler appends `Group.permissions`. Participates in ordinary authorization and in `get_group_permissions(obj)` |
| Both keywords | n/a | `TrustsConfigurationError`: `permission=` and `group=` are mutually exclusive |
| Neither keyword | `permission=` was required | `TrustsConfigurationError`: one of `permission=` or `group=` is required |

```python
# Old: a membership-shaped permission= path was inferred into
# get_group_permissions. That inference is gone.
backend.register(
    trust=DeskPaperGrant,
    user="desk__holders",
    permission="permission",
    content="paper",
)

# New: Django auth.Group must be declared. Stop at the group.
# The reverse membership hop is the related query name ``user``,
# not the Python accessor ``user_set`` (``_meta.get_field`` does not
# see ``user_set``).
backend.register(
    trust=GroupPaperGrant,
    user=lambda t: t.group.user,
    group=lambda t: t.group,
    content=lambda t: t.paper,
)
```

Application impact: trusts that only used `permission=` keep ordinary
authorization and disappear from `get_group_permissions(obj)`, even when
the user path is many-to-many. To put real Django group permissions in
that inquiry, register `group=` on a path that ends at `auth.Group` and
do not append `.permissions`. `group=` grants also show up in `has_perm`,
`get_all_permissions`, `.authorized`, and the fixed policy queries.

django-trusts-zero is out of scope. Zero stays on its current
`permission=` registration (`trustgroup__group__user` plus a permissions
ceiling) until a later baton. This change does not migrate Zero.

Migration-bot checklist:

- `group=`
- `permission=` and `group=` on the same `register(`
- `get_group_permissions`
- `user_set` used as a group membership hop (the registration hop is `user`)
- a `group=` path that appends `permissions`
- many-to-many user paths previously treated as Django groups

## Unused `get_short_model_name` helper (#217)

| | Old | New |
| --- | --- | --- |
| `trusts.utils.get_short_model_name` | Existed on the historical/pre-1.0 surface | schema-neutral django-trusts does not provide it |

0.x applications must follow [django-trusts-zero's migration guide](https://github.com/django-trusts/django-trusts-zero/blob/dev/migrates.md); django-trusts offers no replacement recipe. Detailed Old-behavior, replacement, and casing guidance are on [django-trusts-zero#39](https://github.com/django-trusts/django-trusts-zero/pull/39).

Migration-bot checklist:

- detect `get_short_model_name` imports/calls and send them to the Zero checklist

## Relationship condition language (#210)

| | Old | New |
| --- | --- | --- |
| Public condition | `All(permission_in("team__allowed_operations"), Equal("team__organization", "repository__organization"))` | `lambda t: t.team.allowed_operations.contains(t.operation) & (t.team.organization == t.repository.organization)` |
| Membership | `permission_in("team__allowed_operations")` | collection-rooted `.contains(member)` whose member is this registration's `permission=` path |
| Equality | `Equal("team__organization", "repository__organization")` | `t.team.organization == t.repository.organization` |
| Conjunction | `All(...)` | `p & q` (parenthesize `==`; `&` binds tighter) |
| `predicate=` | n/a | reserved; unsupported in 1.0 (`TypeError` unexpected keyword) |

```python
# Old public handle (prebuilt nodes)
backend.register(
    trust=TeamDocumentPermission,
    user="team__members",
    permission="permission",
    content="document",
    condition=All(
        permission_in("team__allowed_operations"),
        Equal("team__organization", "document__organization"),
    ),
)

# New public handle (one symbolic callable)
backend.register(
    trust=TeamDocumentPermission,
    user=lambda t: t.team.members,
    permission=lambda t: t.permission,
    content=lambda t: t.document,
    condition=lambda t: (
        t.team.allowed_operations.contains(t.permission)
        & (t.team.organization == t.document.organization)
    ),
)
```

The predicate runs once after the freeze check, in the same `AppConfig.ready()`
world as path lambdas. The stored overlay is private `Equal` /
`PermissionIn` / `All` and contains no callable. Literal Python `in` is
unsupported and is not recovered through AST, bytecode, `dis`, or a
`__contains__` side channel. Public `register(condition=...)` rejects
prebuilt `All` / `Equal` / `permission_in` values (`TypeError`). Internal
`TrustsRegistry.register` may still accept those private records.

`.contains` is a reserved method on the condition proxy. A model field
actually named `contains` cannot be walked in `condition=`. Path lambdas
(`user=` / `permission=` / `content=`) do not grow `.contains`.

Consumer Zero group-ceiling registrations and the GH conjunction stay on the
post-#208 / #210 consumer train. Do not migrate them in the django-trusts
slice.

Migration-bot checklist:

- `condition=All(`
- `condition=Equal(`
- `condition=permission_in(`
- `permission_in(`
- `Equal(`
- `.contains(`
- ` in `
- `predicate=`
- `condition=lambda`
- `Python 'in' is unsupported`
- reserved field name `contains` on a condition proxy walk

## Application-owned AuthorizedManagerMixin (#209)

| | Old | New |
| --- | --- | --- |
| Authorized manager | Use the concrete `AuthorizedManager`, or duplicate `.authorized()` in an application manager | Optionally mix `AuthorizedManagerMixin` into the application-owned manager while retaining its behavior |

No mandatory consumer change. `AuthorizedManager` remains supported.

Migration-bot checklist:

- `AuthorizedManager(`
- custom manager definitions
- application-owned `authorized(` methods

## Archaeology

The pre-1.0 development migration record is preserved for historical reference
at the
[archive tag](https://github.com/django-trusts/django-trusts/blob/migration-archive-pre-1.0/migrates.md)
and an
[immutable commit](https://github.com/django-trusts/django-trusts/blob/7414886263faafb6edfb44c0c5fcf9fc8fa14e79/migrates.md).
Those records describe unpublished development transitions; they are not an alternative 0.x migration path.
