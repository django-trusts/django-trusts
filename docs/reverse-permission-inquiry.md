# Reverse permission inquiry: content to users

Status: implemented for
[django-trusts#255](https://github.com/django-trusts/django-trusts/issues/255).
The scalar contract in this document is unchanged. Phase B records the
protected backend hooks and the `Along` failure boundary below.

The registered-path-only superuser rule below is the accepted contract for
[issue #273](https://github.com/django-trusts/django-trusts/issues/273).
The `dev` implementation still adds an outer active-superuser predicate until
that runtime work lands.

## Decision

Core exposes two public adapters for the same reverse inquiry:

```python
users = document.get_permitted_users(perm)
users = User.objects.permitted(document, perm)
```

Both accept exactly one saved content object and one permission, call one
internal reverse-query compiler, and return a lazy queryset of
`settings.AUTH_USER_MODEL`. For the same candidate queryset, content, and
permission, they must return identical rows.

The universally available adapter is `PermittedUsersMixin` on a protected
content model:

```python
from django.db import models
from trusts.query import PermittedUsersMixin


class Document(PermittedUsersMixin, models.Model):
    ...
```

The optional ergonomic adapter is `PermittedUsersManagerMixin` composed
with the application's existing user manager:

```python
from trusts.query import PermittedUsersManagerMixin


class UserManager(PermittedUsersManagerMixin, ExistingUserManager):
    ...
```

The mixin does not replace the application's manager, user model, or queryset
class. Applications using stock `auth.User` or a concrete third-party user
model may be unable to install it without changing `AUTH_USER_MODEL`; they use
the content adapter instead. Zero's migration-identity technique does not make
such a user-model substitution migration-free.

The user-manager method is `permitted(content, perm)`. The manager already
identifies the returned user model, and Django's `get` convention implies
one row, while this method returns a lazy queryset. The mixin name stays
`PermittedUsersManagerMixin`. The content spelling
`get_permitted_users(perm)` is the compatibility path because protected
content models are already application-owned Trusts participants. Neither
spelling is semantically stronger.

There is no `ContentManagerMixin.get_permitted_users()`. A content manager
normally returns content rows; making it return users would switch result
models and require passing a content instance already in hand. The content
instance method still returns a normal user queryset, so downstream
`.filter()`, `.exclude()`, `.annotate()`, and ordering remain available.

## The inquiry

Both adapters answer one question:

> Which users may perform this permission on this content object?

It is the reverse of the existing user-to-content projection:

```python
Document.objects.authorized(user, permission)
```

It is also different from Zero's content-queryset `.permitted(perm, user)`,
which is a string-friendly user-to-content projection. The optional
user-manager method `User.objects.permitted(content, perm)` is not that
method and does not wrap it. Neither existing method is renamed by this API.

Each adapter accepts exactly one saved content instance and exactly one
permission. Neither argument accepts a queryset. Passing an unsaved content
instance is invalid and fails before SQL rather than silently returning an
empty or partial result.

Queryset-valued content or permission inputs are deliberately deferred. They
would require explicit ANY/ALL quantifiers, including separate quantifiers when
both axes are querysets, defined empty-set behavior, and additional
authorization-policy lockfile rules.

## Permission input

`perm` accepts:

- a `django.contrib.auth.models.Permission` instance;
- a supported Django permission string such as
  `"documents.change_document"`, including the existing
  `:named_filter` suffix where the selected backend supports it; or
- an instance of another registered permission-terminal model only when the
  selected Trusts backend explicitly declares that its singular object
  `has_perm` path accepts that instance type as the same permission identity.

The registered permission row is the canonical reverse-query identity. A
Django `auth.Permission` instance is validated and used directly. A string is
a Django-facing alias: Core parses it with the same rules as
`user.has_perm(perm, content)` and binds it to the permission row applicable
to the supplied content and registration. The row lookup remains inside the
eventual SQL query; accepting a string does not add a construction-time query.
When that row's concrete model is `auth.Permission`, the grant also
requires the protected object's content identity. A proxy keeps its own.
A mismatch returns no ordinary users. Any other permission terminal stays
primary-key identity, including a custom model with a `content_type`
foreign key.

For the singular agreement check, a Django `auth.Permission` instance is
represented by its Django 6.1 `instance.user_perm_str` property,
`"app_label.codename"`. A supported application-specific permission instance
remains that instance for both paths. Core does not invent a string codec for
an application-specific permission model.

An instance type without an explicit matching singular-backend capability is
unsupported and raises before SQL. Malformed strings raise the same public
configuration/permission-code error selected for the singular object check. A
well-formed string that identifies no permission row applicable to the supplied
content does not authorize a user. Core does not add authority merely because
the candidate is an active superuser.

## Agreement invariant

For every user row in the configured user model's candidate queryset and every
accepted `perm` / saved `content` pair:

```python
user in content.get_permitted_users(perm)
user in User.objects.permitted(content, perm)
```

must both equal the OR of singular object checks contributed by the supported
configured backends for the normalized permission identity:

```python
normalized_perm = normalize_permission_for_singular_check(perm)
any(
    contributor_grants(backend, user, normalized_perm, content)
    for backend in supported_configured_backends
)
```

`normalize_permission_for_singular_check()` is explanatory notation, not a
second public API. It leaves supported strings and explicitly supported custom
permission instances unchanged, and reads
`django_permission_instance.user_perm_str` for a Django
`auth.Permission` instance. Reverse compilation still uses the canonical
permission row. `contributor_grants()` is also explanatory notation: it means
the backend's singular object-permission branch without
`PermissionsMixin.has_perm()`'s outer active-superuser return.

The reverse inquiry must not silently omit a grant supplied by a supported
contributing backend and still call the result complete. An unsupported
object-permission backend makes the inquiry unsupported rather than silently
narrowing it.

### Principal rules

The reverse query reproduces each supported backend's own eligibility rules,
but not Django's outer `PermissionsMixin.has_perm()` shortcut:

- an active superuser is included only through a contributing registered path;
- `is_superuser` by itself contributes no predicate and is not required on a
  custom user model;
- an inactive ordinary user is included only if a configured supported backend
  would grant that same singular object permission;
- an anonymous principal is not a persisted user row and cannot appear.

Core must not impose a blanket `is_active` exclusion that disagrees with a
custom backend. Each reverse-query contributor reproduces the active-state
behavior of its singular `has_perm` path. The implementation must prove that
the configured user model exposes every required principal condition as SQL.
Arbitrary Python-only state is unsupported and fails loudly.

The invariant is over candidate rows supplied by the application's existing
default user manager. A custom default manager may intentionally exclude rows.
The content adapter preserves that manager's queryset type and filters. The
optional user-manager adapter uses the application manager on which the mixin
is installed; installing it on the default manager gives both adapters the
same candidate universe.

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
    (
        backend_1_eligibility_predicate(user)
        AND backend_1_complete_grant_predicate(user, permission, content)
    )
    OR (
        backend_2_eligibility_predicate(user)
        AND backend_2_complete_grant_predicate(user, permission, content)
    )
    OR ...
```

The named predicates are conceptual SQL placeholders, not Python callbacks.
There is no Core-generated outer superuser contributor. Each backend branch
includes that backend's own eligibility behavior, including any active-state
rule it applies in the singular check. Core adds no global `is_active`
exclusion across all branches.

Permission strings use a SQL binding/subquery rather than a preliminary
permission lookup. Registered relationship conditions and named filters remain
inside the applicable branch. Multiple paths and multiple backends OR together;
duplicate users collapse with `DISTINCT`.

The new query is a policy-lock operation. Phase B adds a
`get_permitted_users` statement for each applicable backend/content pair,
with candidate-user, permission, content, and named-filter parameter roles
represented in the generated authorization-policy SQL. That lockfile key is
not the optional manager method `User.objects.permitted(content, perm)`, and
it is not the existing `permitted` operation, which means user-to-content.

## Database routing

The content adapter begins with
`get_user_model()._default_manager.get_queryset()`. The optional user-manager
adapter begins with that manager instance's existing queryset and adds the same
reverse predicate.

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
- the grant has been revoked.

Unsaved content, malformed declarations, incompatible
user/permission/content models, unsupported databases, and incomplete backend
coverage raise the corresponding input or configuration error before SQL. They
do not fall back to an empty, partial, or broader query.

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
- permission-string form, normalized Django `auth.Permission` instances, and
  explicitly supported custom permission-instance identities;
- an authentication-only backend declaration;
- an unsupported object-permission backend failing before SQL;
- database routing and cross-database rejection;
- zero-SQL construction and one-query evaluation;
- authorization-policy SQL and lockfile output;
- identical content-adapter and default-user-manager-adapter results;
- preservation of an application's existing user manager and queryset class;
- Python 3.12--3.14, package, and exact-Zero pairing CI.

The result set must be compared row-for-row with singular
`user.has_perm(normalized_perm, content)` across the candidate users in every
behavioral fixture, using the normalization rule above.

## Non-goals

This issue does not add:

- content-queryset or permission-queryset arguments;
- implicit ANY/ALL quantification across contents or permissions;
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
- Phase B2, public content and optional user-manager adapters,
  permission-string/named-filter codec, backend-completeness preflight,
  principal rules, routing, lockfile, and migration record: **8**
- GH adoption: separate consumer issue, not included

Phase B1 ships no public application method. Phase B2 exposes
`content.get_permitted_users(perm)` and optional
`User.objects.permitted(content, perm)` only after the full agreement
contract and their result equivalence are proven. Each implementation slice
must be re-sized from the accepted previous head.

## Phase B compiler boundary

`TrustModelBackendMixin.permitted_users_predicate(content, perm)` returns
the backend branch as a `Q`, or `None` when that path does not apply.
`singular_permission_accepted(perm)` is how a backend declares that
singular object `has_perm` accepts a non-string permission instance. The
mixin default accepts `django.contrib.auth.models.Permission` only.

`trusts_object_permissions = False` marks an authentication-only backend
as a known non-contributor. The exact classes `ModelBackend`,
`AllowAllUsersModelBackend`, `RemoteUserBackend`, and
`AllowAllUsersRemoteUserBackend` are object-blind. A subclass is not
inferred from that ancestry. Any other object-capable `has_perm` without
`permitted_users_predicate` raises `TrustsConfigurationError` before SQL.

An `Along` registration grants through a user-seeded walk. That walk has
no exact reverse predicate. `get_permitted_users` and the policy-lock
render raise `TrustsConfigurationError` before SQL. The path is not
dropped and is not widened to every user.

The content adapter's candidate model is `settings.AUTH_USER_MODEL`. A
registration whose user terminal is a different model fails that adapter
before SQL. The optional manager adapter uses the queryset of the manager
it was mixed into, so a custom user model can be queried from the manager
that owns it.

## Related work

Issue #185 keeps the broader inquiry map and earlier user-to-content history.
This document owns only the reverse content-and-permission-to-users inquiry.

Async dispatch #247 and the GH organization-admin work are independent.
Most `OrgScopedAdmin` code protects Django admin services such as form
choices, hostile POSTs, actions, and deletion. This API does not replace or
materially shrink that boundary.

After Core lands, the GH example may adopt
`User.objects.permitted(content, operation)` where it lists users allowed
one operation on one content object, in a separate exact-pairing PR only
after its backend explicitly declares the same `Operation` instance
identity for the singular and reverse paths. The content method remains
`content.get_permitted_users(perm)`. That consumer work must not be
folded into the Core implementation or the active GH admin PR.
