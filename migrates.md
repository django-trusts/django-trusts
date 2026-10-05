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

## Permission content type must match the object (#267)

| | Old | New |
| --- | --- | --- |
| Permission row used on a different model than `Permission.content_type`, including a group that contains both | Grant on `has_perm`, enumeration, `.authorized()`, reverse users, and lockfile SQL that matched `permission_id` only | Denial: `False` / empty. The shared grant joins `content_type` and requires the protected object's `app_label` and `model` |
| `authorization_required` for that pair | Already `PermissionDenied` for an ordinary principal | Same denial |
| Same-model grant, including a custom codename that does not end with the model name | Grant on instance projections | Unchanged grant |
| Permission terminal that is not `auth.Permission`, including a custom model with a `content_type` foreign key | Primary-key identity | Unchanged |
| Active superuser `user.has_perm` | Django returns `True` before backends | Unchanged. Queryset and enumeration projections do not copy that shortcut |

For an ordinary owner of one organization, the shared owner group used to
grant both content types on both objects. Enumeration, `.authorized()`,
reverse users, and lockfile SQL follow the same split: the crossed
permission drops out, and the same-model permission stays.

```python
# Old (crossed group permissions matched by permission_id only)
owner.has_perm("gh_permissions.read_repository", organization)  # True
owner.has_perm("gh_permissions.manage_organization", repository)  # True

# New (Permission.content_type must match the object)
owner.has_perm("gh_permissions.read_repository", organization)  # False
owner.has_perm("gh_permissions.manage_organization", repository)  # False

# Same-model cases unchanged
owner.has_perm("gh_permissions.manage_organization", organization)  # True
owner.has_perm("gh_permissions.read_repository", repository)  # True
```

No schema migration. Existing crossed positives become denials. Regenerate
`trusts-policy.lock.yaml`; `auth.Permission` grants gain `const` parameters
for the protected model's content identity.

Migration-bot checklist:

- `has_perm(`
- `get_all_permissions(`
- `.authorized(`
- `get_permitted_users(`
- `.permitted(`
- `authorization_required(`
- `trusts_policy_sql`
- `content_type`

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

## Reverse permission inquiry (#255)

| | Old | New |
| --- | --- | --- |
| Users who hold one permission on one saved content object | No public reverse inquiry | `content.get_permitted_users(perm)` from `PermittedUsersMixin`. Optionally `User.objects.permitted(content, perm)` from `PermittedUsersManagerMixin` on the application's existing user manager |

No mandatory consumer change. Stock `auth.User` does not grow the manager method, and a content manager still returns content rows. The registered permission row is the identity used in SQL. A permission string is resolved inside that statement, not by a construction-time query. Core does not add its own `is_active` exclusion. An `Along` registration cannot be reversed exactly and raises `TrustsConfigurationError` before SQL, including when rendering the policy lock.

Migration-bot checklist:

- `PermittedUsersMixin`
- `PermittedUsersManagerMixin`
- `get_permitted_users(`
- `User.objects.permitted(`

## Archaeology

The pre-1.0 development migration record is preserved for historical reference
at the
[archive tag](https://github.com/django-trusts/django-trusts/blob/migration-archive-pre-1.0/migrates.md)
and an
[immutable commit](https://github.com/django-trusts/django-trusts/blob/7414886263faafb6edfb44c0c5fcf9fc8fa14e79/migrates.md).
Those records describe unpublished development transitions; they are not an alternative 0.x migration path.
