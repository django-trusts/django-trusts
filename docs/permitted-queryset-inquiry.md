# Permitted content queryset inquiry

Public contract for issue #270. `queryset.permitted(permission, user, conditions=())`
is implemented on `PermittedQuerySet`.

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

It asks the same question as `user.has_perm(permission, object)` for a whole
queryset. It is not exact codec parity with the current `has_perm` string
parser, and it is not the reverse inquiry answered by
`content.get_permitted_users(permission)`.

## Public API

```python
queryset.permitted(permission, user, conditions=())
```

The method lives on the queryset, so it stays available after `filter()`:

```python
Repository.objects.filter(organization=organization).permitted(
    "gh_permissions.read_repository",
    request.user,
)
```

`permission` accepts either:

- one full Django permission string, `"app_label.codename"`; or
- one saved `django.contrib.auth.models.Permission` instance.

The instance must be that exact model class. A proxy or another permission
model is rejected. Bare codenames and `:condition` suffixes are not accepted.
Named conditions are selected separately with one exact tuple:

```python
Repository.objects.permitted(
    "gh_permissions.read_repository",
    request.user,
    conditions=("not_archived",),
)
```

Condition names refer to queryable named conditions already stored by
`register()`. Multiple selected conditions are ANDed. The call does not
invoke callback conditions.

## Permission codec

For a string, the SQL binds the exact codename to the queryset model's
content type. The codename suffix is not parsed into an action and a model
name. `read_pull_request` on `PullRequest` stays that codename; it is not
looked up as model `request`.

`authorization_required` uses this same rule. `user.has_perm` still uses
`parse_perm_code`, which infers the model from the codename suffix. The two
agree on codenames shaped like `action_modelname` and diverge otherwise.
That gap is [issue #268](https://github.com/django-trusts/django-trusts/issues/268).
`.permitted()` is the queryset form of the `authorization_required` inquiry,
not a second implementation of the current `has_perm` codec.

A saved `auth.Permission` instance is bound by its primary key. Building
that queryset does not read `permission.content_type`. The shared grant
predicate requires the row's content type to be the queryset model's
content type. A same codename on another model does not become this model's
permission.

## Manager attachment

The method has to live on the queryset. `Repository.objects.filter(...).permitted(...)`
uses whatever queryset class `filter()` returned.

```python
from django.db import models
from trusts.query import PermittedQuerySetMixin


class RepositoryQuerySet(PermittedQuerySetMixin, models.QuerySet):
    def for_organization(self, organization):
        return self.filter(organization=organization)


class Repository(models.Model):
    objects = RepositoryQuerySet.as_manager()
```

An application that already owns a manager class supplies that queryset
with `from_queryset`:

```python
class RepositoryManager(models.Manager.from_queryset(RepositoryQuerySet)):
    def application_method(self):
        return "owned"


class Repository(models.Model):
    objects = RepositoryManager()
```

`PermittedQuerySet` and `PermittedManager = Manager.from_queryset(PermittedQuerySet)`
are the concrete forms when the application does not need its own queryset
methods. There is no `PermittedManagerMixin`: a manager-only method is absent
from the queryset returned by `filter()`.

`AuthorizedQuerySet`, `AuthorizedManagerMixin`, `AuthorizedManager`, and
`.authorized(user, permission, extra_q=None)` stay exported. New user
documentation teaches `.permitted()` for this inquiry. `.authorized()` is
the lower-level instance projection, not a second spelling of the same call.

## Participating backends

Core passes relationship-family implementation handles into the private
compiler. The compiler takes that handle list as an explicit input so
another package can pass its own later. Zero's `ContentQuerySet.permitted`
is unchanged in this slice.

A backend participates only when both of these are true:

- it has an applicable plan whose permission terminal is exactly
  `auth.Permission`; and
- it owns every selected name as a queryable condition.

String and `auth.Permission` inputs skip any other permission terminal.
An auth permission primary key is never compared with a custom terminal
that happens to use the same integer.

Non-owners contribute nothing. Their unconditioned grants are not OR'd in.
If no participating backend owns the complete name set, the call raises
`TrustsConfigurationError`. Backend order does not change the predicate.

`trusts.E008` reports this ownership rule for `authorization_required`
declarations only. A runtime `.permitted()` call is not registered with
that check. The same failure still raises when the queryset is built.
Silencing `trusts.E008` does not disable `.permitted()`.

## Compilation

The queryset supplies the protected content model. The method uses the same
normalized `register()` plans and named-condition registry as
`authorization_required()`. Application code does not need a preliminary
`Permission.objects.get()`.

For every participating backend, the method compiles:

```text
registered grant path AND every explicitly selected named condition
```

Participating backends are ORed. The final queryset is distinct and stays
lazy, so pagination applies in SQL.

## Principal and backend boundary

Anonymous and inactive principals receive an empty queryset. The method does
not copy Django's active-superuser shortcut. An active superuser without a
registered grant receives an empty queryset.

The result is Trusts' registered relationship-family projection. It does not
call `user.has_perm()` per row and does not OR results from arbitrary Django
authorization backends. Django has no general protocol through which a backend
can contribute a queryset predicate.

Authentication method does not change these semantics. A session, bearer
token, or another authenticator establishes the principal; it does not select
a broader authorization path.

Input and configuration are validated before the principal shortcut. A
misconfigured call raises for an anonymous principal instead of returning an
empty queryset.

## Failure behavior

Raise `TypeError` or `TrustsConfigurationError` before SQL when:

- the permission is not a full `app_label.codename` string or a saved exact
  `auth.Permission` instance;
- the string is a bare codename, has a `:` suffix, or does not contain one
  dot;
- `conditions` is not an exact tuple, or a name is blank, padded, contains
  `:`, or is duplicated;
- the queryset model has no applicable `auth.Permission` plan; or
- no participating backend owns every selected queryable condition.

Return an empty queryset when:

- the principal is anonymous or inactive; or
- the permission is well formed and the model has an applicable plan, but
  the permission belongs to another content type, including another
  application label.

A string whose application label does not match the model is that second
case. `authorization_required` still rejects a mismatched application label
when the view is declared. That static check stays on the decorator.

## Relationship to existing APIs

| Inquiry | Public spelling |
| --- | --- |
| May this user do this on one object? | `user.has_perm(permission, object)` |
| Which permissions does this user hold on one object? | `user.get_all_permissions(object)` |
| Which objects may this user access with one permission? | `queryset.permitted(permission, user)` |
| Which users may access one object with one permission? | `content.get_permitted_users(permission)` |

`.authorized(user, permission, extra_q=None)` remains available. It accepts
any saved permission-terminal instance, including a custom model, does not
check that the principal is active, and ANDs `extra_q`. It is not routed
through `.permitted()` validation. Its docstring points here.

Zero already exposes `ContentQuerySet.permitted(perm, user)`. This slice
does not change that method. It keeps Zero's wider codec, its own handles,
and its own contract checks.

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
