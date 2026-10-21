# Migrating from django-trusts 1.0 to 1.1

This guide records only changes from a released version that require
applications to change their code, settings, or data when they upgrade. A
surface that was previously refused and is now supported does not need an
entry, because no application could have depended on it. It is not a
development log. New features and changes that require no application action
belong in [What's new](whats-new.md); development history belongs in
[development history](../dev/development.md).

## Two fields do not match NULL

A condition that compares two fields no longer treats NULL as a value.
A field compared with a constant still follows Python: `== None` is
`IS NULL`, `!= None` is `IS NOT NULL`, and `!= 5` is true when the
field is NULL (`None != 5`).

| Comparison | When | Old | New |
| --- | --- | --- | --- |
| `o.left == o.right` | both NULL | matches | does not match |
| `o.left != o.right` | exactly one NULL | matches | does not match |
| `u.manager == o.reviewer` | both NULL | matches | does not match |
| `u != o.owner` | `owner` is NULL | matches | does not match |
| `o.left == None` | `left` is NULL | matches | unchanged |
| `o.left != 5` | `left` is NULL | matches | unchanged |

`has_perm`, a permitted queryset, and `get_permitted_users` use this
rule. Relation `condition=` equality was already plain `a = b` (NULL
never matches) and is unchanged. `o.left != o.right` when both are
NULL already did not match.

## One condition error (#333)

`PermissionConditionError` is now the only condition error, and it is a
`TrustsConfigurationError`. `register(condition=...)`, named filters, and
user rules raise it for every unsupported operator, unsupported node, and
missing field. The messages name the surface, for example
"'|' is not supported in a relation condition."
Named filters accept `.contains()`, `~`, and a bare boolean field.
The predicates compiler and the relation-condition guards raise `PermissionConditionError` directly and do not wrap it.

| | Old | New |
| --- | --- | --- |
| Python `and` / `or` / `not`, chained comparison | `PermissionConditionBooleanError` | `PermissionConditionError` |
| Unsupported operator or constant | `PermissionConditionUnsupported` | `PermissionConditionError` |
| `PermissionConditionNotQueryable` (a `ValueError`, never raised) | importable | removed |
| Base class of `PermissionConditionError` | `Exception` | `TrustsConfigurationError` |
| Ordered comparison (`<`, `<=`, `>`, `>=`) | rejected when the builder returned | rejected at the operator, same class |
| `condition=` or user-rule grammar, missing field, or non-boolean user-rule field | `TrustsConfigurationError` | `PermissionConditionError` (still caught by `except TrustsConfigurationError`) |
| Missing field in a `user=`, `permission=`, `delegate=`, or `sponsor=` path | `TrustsConfigurationError` | `PermissionConditionError` (still caught by `except TrustsConfigurationError`) |
| Second `add_named_filter` with the same model and code | replaced the first filter | `PermissionConditionError` at `ready()`; the second builder is not called |

An `except TrustsConfigurationError` block now also catches condition
errors. Catch `PermissionConditionError` first to tell them apart.

Migration-bot checklist:

- `PermissionConditionBooleanError`
- `PermissionConditionUnsupported`
- `PermissionConditionNotQueryable`
- `except PermissionConditionError`

## Test-only names removed

These names were importable and unused by the authorization runtime.
Call the catalog or the condition compiler instead.

| | Old | New |
| --- | --- | --- |
| Permission rows | `RelationPlan.common_permissions(user, content)` | `catalog.permissions_for(user, content)` |
| Condition object check | `ConditionRegistry.evaluate_permission_condition(...)` | `compile_registered_condition_q` and filter the queryset |
| Stored-condition object check | `evaluate_stored_condition(...)` | the same compiled `Q` |
| Compiler failure type | `TrustsCompilerError` | `TrustsConfigurationError` |
| Exists marker | `LiteralExists(queryset)` | ordinary `Exists`; the renderer writes `SELECT 1` |

Migration-bot checklist:

- `common_permissions`
- `evaluate_permission_condition`
- `evaluate_stored_condition`
- `TrustsCompilerError`
- `LiteralExists`

## `Meta.permission_conditions` removed (#330)

Named filters are not a model `Meta` option. Register the predicate on
the app config's recorder.

| | Old | New |
| --- | --- | --- |
| Named filter | `class Meta: permission_conditions = (('name', predicate),)` | `recorder.add_named_filter(Model, 'name', predicate)` in `AppConfig.ready()` |

django-trusts does not append `permission_conditions` to
`django.db.models.options.DEFAULT_NAMES`.

Migration-bot checklist:

- `permission_conditions`

## `filter_authorized_scopes` renamed (#302)

`filter_authorized_scopes` is deprecated. Call `filter_by_permitted_content`.
The signature and behavior are the same. The old function remains and calls
the new one.

| | Old | New |
| --- | --- | --- |
| Rows with permitted content under them | `filter_authorized_scopes(...)` | `filter_by_permitted_content(...)` |

Migration-bot checklist:

- search `filter_authorized_scopes(` and replace with `filter_by_permitted_content(`

## Superuser bypass (#273)

Trusts superuser bypass now requires an explicit `set_user_override()`.
See [User conditions and overrides](index.rst#user-conditions-and-overrides).

## Permission content type must match the object (#267)

`1.0.0 → 1.1.0`. Crossed `auth.Permission.content_type` positives are
1.0.0 behavior. Denial is 1.1.0 behavior.

| | 1.0.0 | 1.1.0 |
| --- | --- | --- |
| Permission row used on a different model than `Permission.content_type`, including a group that contains both | Grant on `has_perm`, enumeration, `.authorized()`, users from content, and lockfile SQL that matched `permission_id` only | Denial: `False` / empty. The shared grant joins `content_type` and requires the protected object's `app_label` and `model` |
| `authorization_required` for that pair | Already `PermissionDenied` for an ordinary user | Same denial |
| Same-model grant, including a custom codename that does not end with the model name | Grant on instance projections | Unchanged grant |
| Permission terminal that is not `auth.Permission`, including a custom model with a `content_type` foreign key | Primary-key identity | Unchanged |

For an ordinary owner of one organization, the shared owner group used to
grant both content types on both objects. Enumeration, `.authorized()`,
users from content, and lockfile SQL follow the same split: the crossed
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
`trusts-policy.lock.yaml` and review the diff; `auth.Permission` grants now
also match the protected object's content type.

Migration-bot checklist:

- `has_perm(`
- `get_all_permissions(`
- `.authorized(`
- `get_permitted_users(`
- `.permitted(`
- `authorization_required(`
- `trusts_policy_sql`
- `content_type`

## Permitted content queryset (#270)

`1.0.0 → 1.1.0`. No public content-list `.permitted()` is 1.0.0 behavior.
`queryset.permitted(permission, user, conditions=())` is 1.1.0 behavior.

| | 1.0.0 | 1.1.0 |
| --- | --- | --- |
| Content rows one user may access for one permission | Resolve an `auth.Permission` row, then `.authorized(user, permission)` | `queryset.permitted(permission, user, conditions=())` |
| Chained queryset | The list method is not on `QuerySet` | `Repository.objects.filter(...).permitted(...)` when the queryset mixes in `PermittedQuerySetMixin` and is supplied with `as_manager()` or `from_queryset` |
| Attachment names | `AuthorizedQuerySet`, `AuthorizedManagerMixin`, `AuthorizedManager` | Those names stay. Add `PermittedQuerySetMixin`, `PermittedQuerySet`, and `PermittedManager` |
| `.authorized(user, permission, extra_q=None)` | Instance projection, any registered terminal | Retained. User conditions and overrides apply; not routed through `.permitted` validation |
| Malformed permission, bad `conditions`, missing `auth.Permission` plan, or conditions no backend owns together | n/a | `TypeError` or `TrustsConfigurationError` before SQL, including for an anonymous user |
| Well-formed permission for another content type | Denial on the instance projection when the row's content type does not match | Empty `.permitted()` queryset |

New code should use `.permitted()`. For user checks and audit options, see
[User conditions and overrides](index.rst#user-conditions-and-overrides).
Zero's `ContentQuerySet.permitted(perm, user)` retains its permission codec.

```python
# Old
change = Permission.objects.get(
    content_type__app_label="documents",
    content_type__model="document",
    codename="change_document",
)
Document.objects.authorized(user, change)

# New
Document.objects.permitted("documents.change_document", user)
```

Migration-bot checklist:

- `PermittedQuerySetMixin`
- `PermittedQuerySet`
- `PermittedManager`
- `.permitted(`
- `conditions=`
- `.authorized(`
- `from_queryset`
- `as_manager()`

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

The condition runs once after the freeze check, in the same `AppConfig.ready()`
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

## Permission inquiry from content to users (#255)

| | Old | New |
| --- | --- | --- |
| Users who hold one permission on one saved content object | No public inquiry for users from content | `content.get_permitted_users(perm)` from `PermittedUsersMixin`. Optionally `User.objects.permitted(content, perm)` from `PermittedUsersManagerMixin` on the application's existing user manager |

No mandatory consumer change to adopt this adapter. Stock `auth.User` does not
grow the manager method, and a content manager still returns content rows.
The registered permission row is the identity used in SQL. A permission string
is resolved inside that statement, not by a construction-time query. User
conditions and overrides apply as described above.

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

## Migrating to django-trusts 1.0

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
