# Permitted content queryset inquiry

Status: docs-first API contract for issue #270. Runtime implementation follows
after design review.

## Question

Given one user and one permission, which rows in this content queryset may the
user access?

This is the forward queryset inquiry in the user × permission × content map:

```python
Repository.objects.permitted(
    "gh_permissions.read_repository",
    request.user,
)
```

It is the queryset counterpart of `user.has_perm(permission, object)`. It is
not the reverse inquiry answered by
`content.get_permitted_users(permission)`.

## Public API

```python
queryset.permitted(permission, user, conditions=())
```

The same method is available through a model's manager. It returns a lazy,
chainable queryset of the same model:

```python
Repository.objects.filter(organization=organization).permitted(
    "gh_permissions.read_repository",
    request.user,
)
```

`permission` accepts either:

- one full Django permission string, `"app_label.codename"`; or
- the corresponding `django.contrib.auth.models.Permission` instance.

Bare codenames and `:condition` suffixes are not accepted. Named conditions
are selected separately with one exact tuple:

```python
Repository.objects.permitted(
    "gh_permissions.read_repository",
    request.user,
    conditions=("not_archived",),
)
```

Condition names refer to queryable named conditions already stored by
`register()`. Multiple selected conditions are ANDed. The call fails closed if
no applicable relationship-family plan owns every selected condition. It does
not invoke callback conditions.

## Manager attachment

An application that owns a custom manager mixes in `PermittedManagerMixin`:

```python
from django.db import models
from trusts.query import PermittedManagerMixin


class RepositoryManager(PermittedManagerMixin, models.Manager):
    pass


class Repository(models.Model):
    objects = RepositoryManager()
```

`PermittedManagerMixin` adds `permitted()` without replacing the application's
manager or queryset behavior. A concrete `PermittedManager` is available when
the application does not need a custom manager.

The implementation may retain the existing `AuthorizedQuerySet`,
`AuthorizedManagerMixin`, `AuthorizedManager`, and `.authorized()` names for
compatibility. New user documentation teaches only `.permitted()` for this
inquiry. Compatibility names must not change the semantics below or become a
second preferred spelling.

## Compilation

The queryset supplies the protected content model. The method uses the same
normalized `register()` plans and named-condition registry as singular object
checks and `authorization_required()`.

For a permission string, the SQL binds all three parts of the identity:

- permission application label;
- permission codename; and
- the queryset model's content type.

Application code does not need a preliminary `Permission.objects.get()`.
A permission belonging to a different content model is a denial, even when a
relationship contains that permission row.

For every participating relationship-family backend, the method compiles:

```text
registered grant path AND every explicitly selected named condition
```

Participating backends are ORed, matching the existing relationship-family
queryset projection. The final queryset remains distinct and composable before
pagination.

## Principal and backend boundary

Anonymous and inactive principals receive an empty queryset. The method does
not copy Django's active-superuser shortcut.

The result is Trusts' registered relationship-family projection. It does not
call `user.has_perm()` per row and does not OR results from arbitrary Django
authorization backends. Django has no general protocol through which a backend
can contribute a queryset predicate.

Authentication method does not change these semantics. A session, bearer
token, or another authenticator establishes the principal; it does not select
a broader authorization path.

## Failure behavior

The method fails closed when:

- the permission input is malformed or unsupported;
- a string permission does not belong to the queryset model;
- there is no applicable registered `auth.Permission` plan;
- a selected condition is missing, callable-only, or not owned together with
  the applicable plan; or
- the principal is anonymous or inactive.

Configuration errors that can be established without querying should remain
zero-SQL. Anonymous and inactive principals return an empty queryset.

## Relationship to existing APIs

| Inquiry | Public spelling |
| --- | --- |
| May this user do this on one object? | `user.has_perm(permission, object)` |
| Which permissions does this user hold on one object? | `user.get_all_permissions(object)` |
| Which objects may this user access with one permission? | `queryset.permitted(permission, user)` |
| Which users may access one object with one permission? | `content.get_permitted_users(permission)` |

Zero already exposes `ContentQuerySet.permitted(perm, user)`. Core adopts the
same argument order and must keep that source shape compatible. Core adds full
Django permission strings, `auth.Permission` instances, and explicit
`conditions=()` according to the contract above; Zero may delegate to the Core
compiler while retaining its documented compatibility behavior.

## Non-goals

This API does not infer:

- an HTTP action-to-permission mapping;
- whether a denied object is HTTP 403 or 404;
- which parent object a create request targets;
- which domain service performs a mutation;
- ANY or ALL quantification across multiple permissions;
- arbitrary-backend queryset aggregation; or
- a superuser compatibility escape.

Those decisions remain with the application or an optional framework adapter.
