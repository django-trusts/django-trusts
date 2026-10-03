# Reverse permission inquiry: content to users

Status: Phase A design contract for
[django-trusts#255](https://github.com/django-trusts/django-trusts/issues/255).
This document does not claim that the API is implemented.

## Decision

The public API lives on the protected content instance:

```python
users = document.get_permitted_users(perm)
```

An application opts in by mixing a future `PermittedUsersMixin` into each
protected model that should expose the inquiry:

```python
from django.db import models
from trusts.query import PermittedUsersMixin


class Document(PermittedUsersMixin, models.Model):
    ...
```

The result is a lazy queryset of `settings.AUTH_USER_MODEL`.

The rejected public spelling is:

```python
User.objects.get_permitted_users(content, perm)
```

It is not shipped as a second public API. A private implementation helper may
accept a user queryset, but applications must not acquire a new public user
manager method.

The content-side method is the smaller integration boundary. Applications
already own the protected models that carry Trusts registrations. Many
applications use Django's stock `User` model and cannot replace its manager
without replacing the user model. The content method can begin with the
configured user model's existing default manager, preserve its queryset class
and filters, and still return the rows the caller wants.

## The inquiry

The method answers one question:

> Which users may perform this permission on this content object?

It is the reverse of the existing user-to-content projection:

```python
Document.objects.authorized(user, permission)
```

It is also different from Zero's `.permitted(perm, user)`, which is a
string-friendly user-to-content projection. Neither existing method is renamed
or wrapped by this API.

The method accepts exactly one persisted content instance. It does not accept a
content queryset. An unsaved content instance returns an empty user queryset.

## Permission input

`perm` accepts:

- a model instance that is the permission terminal of the applicable
  registration; for the standard Django path this is
  `django.contrib.auth.models.Permission`; or
- a supported Django permission string such as
  `"documents.change_document"`, including the existing
  `:named_filter` suffix where the selected backend supports it.

A permission instance follows the same instance binding used by
`.authorized()`. A string follows the same parsing, permission identity, and
named-filter behavior as `user.has_perm(perm, content)`.

Malformed strings raise the same public configuration/permission-code error
selected for the singular object check. A well-formed but unknown permission
does not authorize an ordinary user. Active superusers remain governed by
Django's outer superuser rule.

Companion implementations with a non-Django permission model can use the
instance form. A string codec for an application-specific permission model is
not invented by Core.

## Agreement invariant

For every user row in the configured user model's candidate queryset and every
accepted `perm` / persisted `content` pair:

```python
user in content.get_permitted_users(perm)
```

must equal:

```python
user.has_perm(perm, content)
```

The comparison uses the same configured Django authentication backends.

This is stronger than the Trusts-only contract of
`Model.objects.authorized(user, permission)`. The reverse inquiry must not
silently omit a grant supplied by another backend and still call the result
complete.

### Django outer rules

The queryset applies Django's outer principal rules before backend
contributions:

- an active superuser is included for every accepted permission/content pair;
- an inactive user, including an inactive superuser, is excluded;
- an anonymous principal is not a persisted user row and cannot appear.

The implementation must prove that the configured user model exposes
SQL-queryable superuser and active state compatible with its singular
`has_perm` behavior. If a custom user model implements either state only as
arbitrary Python behavior, exact SQL reversal is unsupported and fails loudly.

The invariant is over candidate rows supplied by the application's existing
default user manager. A custom default manager may intentionally exclude rows.
The mixin preserves that manager's queryset type and filters; it does not
replace them with an unfiltered Core manager.

## Backend completeness

Django grants an object permission when any configured authentication backend
grants. Exact reverse lookup therefore needs a closed backend set.

At construction time, every configured backend must fall into one of three
classes:

1. **Reverse-query contributor.** It can compile a predicate over candidate
   user rows for the supplied permission and content.
2. **Known object-permission non-contributor.** It declares, or is a precisely
   recognized built-in backend whose contract establishes, that it cannot
   grant when an object is supplied.
3. **Unsupported.** It might grant an object permission but cannot express the
   reverse predicate.

Core ORs every contributor in one user query. A known non-contributor adds
nothing. The presence of an unsupported backend raises
`TrustsConfigurationError` before SQL instead of returning an incomplete
queryset.

The implementation may use a protected backend hook or capability marker.
Its exact internal name is not part of the application-facing API selected in
this document. The semantics are mandatory:

- a `TrustModelBackendMixin` backend contributes the same complete
  relationship plan and named-filter overlay used by its singular
  `has_perm`;
- separate Trusts backend paths OR together, just as Django's outer backend
  loop does;
- the stock `ModelBackend` contributes no object grant;
- a third-party authentication-only backend must be explicitly known as a
  non-contributor rather than inferred from a class name;
- a third-party object-permission backend must supply a reverse-query
  contribution or make the inquiry unsupported.

A rejection by one backend never cancels a grant from another backend.

## SQL and query budget

Construction performs no SQL for either permission form.

Evaluation performs one user query. Its conceptual shape is:

```sql
SELECT DISTINCT user.*
FROM user
WHERE
    (user.is_active AND user.is_superuser)
    OR EXISTS (complete direct grant correlated to user and content)
    OR EXISTS (complete membership grant correlated to user and content)
    OR ...
```

Permission strings use a SQL binding/subquery rather than a preliminary
permission lookup. Registered relationship conditions and named filters remain
inside the applicable branch. Multiple paths and multiple backends OR together;
duplicate users collapse with `DISTINCT`.

The new query is a policy-lock operation. Phase B adds a
`get_permitted_users` statement for each applicable backend/content pair,
with candidate-user, permission, content, and named-filter parameter roles
represented in the generated authorization-policy SQL. It is not the existing
`permitted` operation, which means user-to-content.

## Database routing

The returned queryset begins with
`get_user_model()._default_manager.get_queryset()`.

A saved content instance supplies its database alias when available. Otherwise
Django's router selects the read database. All correlated Trusts and permission
tables must be queryable on that alias. Cross-database authorization cannot be
represented by one SQL statement and is unsupported; Core raises instead of
performing a Python merge or silently querying a second database.

The returned queryset keeps its manager/queryset subclass and database alias,
so later application filtering and ordering compose normally.

## Fail-closed behavior

For ordinary users, the result is empty when:

- no complete registered path applies to the content model;
- the permission is well formed but unknown;
- a required membership, attachment, ceiling, alignment, or other registered
  condition is absent;
- the content instance is unsaved;
- the grant has been revoked.

Malformed declarations, incompatible user/permission/content models,
unsupported databases, and incomplete backend coverage raise the corresponding
configuration error. They do not fall back to a broader query.

## Required Phase B proof

Implementation must cover:

- direct-user and membership-shaped grants;
- explicit `group=` registrations contributing their member users;
- multiple complete roots and multiple backends;
- duplicate elimination;
- missing membership or attachment;
- permission ceilings, equality conditions, and named filters;
- immediate revocation;
- unrelated and unknown permissions;
- active, inactive, and superuser behavior;
- a custom user model with a custom default manager/queryset;
- non-integer user and content primary keys;
- permission-instance and permission-string forms;
- an authentication-only backend declaration;
- an unsupported object-permission backend failing before SQL;
- database routing and cross-database rejection;
- zero-SQL construction and one-query evaluation;
- authorization-policy SQL and lockfile output;
- absence of the rejected user-manager public spelling;
- Python 3.12--3.14, package, and exact-Zero pairing CI.

The result set must be compared row-for-row with singular
`user.has_perm(perm, content)` across the candidate users in every behavioral
fixture.

## Non-goals

This issue does not add:

- users having any permission on the content;
- grant inventory without a resolved user;
- a public API returning groups;
- ORM enforcement on `save()`, `delete()`, or queryset evaluation;
- permission-bearing relationship mutation;
- another spelling of `.authorized()` or Zero's `.permitted()`;
- a replacement for application admin checks.

Group-derived grants still contribute their member users to this inquiry. The
excluded “group twin” is a separate result that would return groups rather than
users.

## Implementation slices and size

The documentation pass exposed a larger surface than the original 8--13
estimate.

- Whole Core ticket: **13--21**
- Phase A, this design contract: **3**
- Phase B1, private reverse relationship compiler and agreement fixtures:
  **8**
- Phase B2, public content mixin, permission-string/named-filter codec,
  backend-completeness preflight, principal rules, routing, lockfile, and
  migration record: **8**
- GH adoption: separate consumer issue, not included

Phase B1 ships no public application method. Phase B2 exposes
`get_permitted_users()` only after the full agreement contract is proven.
Each implementation slice must be re-sized from the accepted previous head.

## Related work

Issue #185 keeps the broader inquiry map and earlier user-to-content history.
This document owns only the reverse content-and-permission-to-users inquiry.

Async dispatch #247 and the GH organization-admin work are independent.
Most `OrgScopedAdmin` code protects Django admin services such as form
choices, hostile POSTs, actions, and deletion. This API does not replace or
materially shrink that boundary.

After Core lands, the GH example may adopt
`repository.get_permitted_users(operation)` in a separate exact-pairing PR.
That consumer work must not be folded into the Core implementation or the
active GH admin PR.
