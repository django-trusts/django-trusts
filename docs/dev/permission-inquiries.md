# Permission inquiries

Historical development record. Last source update: 2026-10-15.
This reorganization has not been reviewed by a human for current accuracy.

Development reference consolidated from the #270 content-queryset contract,
the #255 users-from-content contract, and the registry projection record.

## Permitted content querysets

Public contract for issue #270. `queryset.permitted(permission, user, conditions=(), **skip_options)`
is implemented on `PermittedQuerySet`.

The [user conditions, overrides, and named skip options](../source/index.rst#user-conditions-and-overrides)
apply to this inquiry.

### Question

Given one user and one permission, which rows in this content queryset may the
user access?

This is the content queryset inquiry in the user × permission × content map:

```python
Repository.objects.permitted(
    "gh_permissions.read_repository",
    request.user,
)
```

It asks the same question as `user.has_perm(permission, object)` for a whole
queryset. It is not exact codec parity with the current `has_perm` string
parser, and it is not the inquiry for users from content answered by
`content.get_permitted_users(permission)`.

### Public API

```python
queryset.permitted(permission, user, conditions=(), **skip_options)
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

### Permission codec

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
condition requires the row's content type to be the queryset model's
content type. A same codename on another model does not become this model's
permission.

### Manager attachment

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

### Participating backends

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
If no participating backend owns the name set, the call raises
`TrustsConfigurationError`. Backend order does not change the condition.

`trusts.E008` reports this ownership rule for `authorization_required`
declarations only. A runtime `.permitted()` call is not registered with
that check. The same failure still raises when the queryset is built.
Silencing `trusts.E008` does not disable `.permitted()`.

### Compilation

The queryset supplies the protected content model. The method uses the same
normalized `register()` plans and named-condition registry as
`authorization_required()`. Application code does not need a preliminary
`Permission.objects.get()`.

For every participating backend, the method compiles:

```text
registered user conditions and overrides composed with the grant path and selected named conditions
```

Participating backends are ORed. The final queryset is distinct and stays
lazy, so pagination applies in SQL.

### User and backend boundary

The registry's user conditions and optional override apply to this inquiry.
Named skip options select which registered user conditions and overrides to omit for that call.

The result is Trusts' registered relationship-family projection. It does not
call `user.has_perm()` per row and does not OR results from arbitrary Django
authorization backends. Django has no general protocol through which a backend
can contribute a queryset condition.

Authentication method does not change these semantics. A session, bearer
token, or another authenticator establishes the user; it does not select
a broader authorization path.

Input and configuration are validated before the user shortcut. A
misconfigured call raises for an anonymous user instead of returning an
empty queryset.

### Failure behavior

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

- the user is anonymous or unauthenticated;
- a required user condition fails; or
- the permission is well formed and the model has an applicable plan, but
  the permission belongs to another content type, including another
  application label.

A string whose application label does not match the model is that second
case. `authorization_required` still rejects a mismatched application label
when the view is declared. That static check stays on the decorator.

### Relationship to existing APIs

| Inquiry | Public spelling |
| --- | --- |
| May this user do this on one object? | `user.has_perm(permission, object)` |
| Which permissions does this user hold on one object? | `user.get_all_permissions(object)` |
| Which objects may this user access with one permission? | `queryset.permitted(permission, user)` |
| Which users may access one object with one permission? | `content.get_permitted_users(permission)` |

`.authorized(user, permission, extra_q=None)` remains available. It accepts
any saved permission-terminal instance, including a custom model, applies the
shared user checks, and ANDs `extra_q`. It is not routed
through `.permitted()` validation. Its docstring points here.

Zero already exposes `ContentQuerySet.permitted(perm, user)`. This slice
does not change that method. It keeps Zero's wider codec, its own handles,
and its own contract checks.

### Non-goals

This API does not infer:

- an HTTP action-to-permission mapping;
- whether a denied object is HTTP 403 or 404;
- which parent object a create request targets;
- which domain service performs a mutation;
- ANY or ALL quantification across multiple permissions;
- arbitrary-backend queryset aggregation.

Those decisions remain with the application or an optional framework adapter.

## Users from content

Status: implemented for
[django-trusts#255](https://github.com/django-trusts/django-trusts/issues/255).
The scalar contract in this document is unchanged. Phase B records the
protected backend hooks and the recursive agreement boundary below.

Both adapters use the [user conditions, overrides, and named skip options](../source/index.rst#user-conditions-and-overrides).

### Decision

Core exposes two public adapters for the same inquiry for users from content:

```python
users = document.get_permitted_users(perm)
users = User.objects.permitted(document, perm)
```

Both accept exactly one saved content object, one permission, and the
named `skip_<name>` keyword arguments, call one
internal compiler for users from content, and return a lazy queryset of
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

### The inquiry

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

### Permission input

`perm` accepts:

- a `django.contrib.auth.models.Permission` instance;
- a supported Django permission string such as
  `"documents.change_document"`, including the existing
  `:named_filter` suffix where the selected backend supports it; or
- an instance of another registered permission-terminal model only when the
  selected Trusts backend explicitly declares that its singular object
  `has_perm` path accepts that instance type as the same permission identity.

The registered permission row is the canonical permission identity for users from content. A
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
content does not produce an ordinary grant.

### How forward and reverse checks agree

For every user row in the configured user model's candidate queryset and every
accepted `perm` / saved `content` pair:

```python
user in content.get_permitted_users(perm)
user in User.objects.permitted(content, perm)
```

must agree when called with the same skip options. Each supported backend
contribution retains its own user conditions and overrides and the same candidate queryset.

A Trusts contribution matches that Trusts backend's object check under the
same permission identity, registered conditions, override, and skip options.
Custom backend contributions retain their own rules. Core ORs those supported
contributions rather than silently omitting a backend that might grant.

This contract does not promise row-for-row parity with native
`user.has_perm()`. Django's user method can apply outer checks before calling
backends and cannot forward Trusts skip options. The locked
`get_permitted_users` statement is one Trusts backend contribution, not the
aggregate result across authentication backends.

#### User conditions and overrides and Django's backend boundary

Trusts user conditions and overrides are described once in the guide linked above. A registered
override participates in inquiries for users from content; no superuser grant is implicit.
Django's native `PermissionsMixin.has_perm()` can return before consulting
backends. See the [security audit's Django boundary](../../SECURITY_AUDIT.md#django-auths-checks-before-calling-backends).

A supported backend must express its contribution in SQL. Arbitrary
Python-only state is unsupported and fails loudly.

The comparison uses the candidate users from the application's existing
default user manager. A custom default manager may intentionally exclude rows.
The content adapter preserves that manager's queryset type and filters. The
optional user-manager adapter uses the application manager on which the mixin
is installed; installing it on the default manager gives both adapters the
same candidate universe.

### Backend coverage

Django grants an object permission when any configured authentication backend
grants. Exact reverse lookup therefore needs a closed backend set.

At construction time, every configured backend must fall into one of three
classes:

1. **Backend that can add users to the query.** It can compile a condition over candidate
   user rows for the supplied permission and content.
2. **Backend known to grant no object permissions.** It declares, or is a precisely
   recognized built-in backend whose contract establishes, that it cannot
   grant when an object is supplied.
3. **Unsupported.** It might grant an object permission but cannot express the
   reverse condition.

Core ORs the backend conditions in one user query. A backend that grants no
object permissions adds nothing. The presence of an unsupported backend raises
`TrustsConfigurationError` before SQL instead of returning an incomplete
queryset.

The implementation may use a protected backend hook or capability marker.
Its exact internal name is not part of the application-facing API selected in
this document. The semantics are mandatory:

- a `TrustModelBackendMixin` backend contributes the same
  relationship plan and named-filter overlay used by its singular
  `has_perm`;
- separate Trusts backend paths OR together, just as Django's authentication backend
  loop does;
- the stock `ModelBackend` contributes no object grant;
- a third-party authentication-only backend must be explicitly known as a
  unable to grant object permissions rather than inferred from a class name;
- a third-party object-permission backend must supply a users-from-content
  contribution or make the inquiry unsupported.

A rejection by one backend never cancels a grant from another backend.

### SQL and query budget

Construction performs no SQL for either permission form.

Evaluation performs one user query. Its conceptual shape is:

```sql
SELECT DISTINCT user.*
FROM user
WHERE
    (
        trusts_user_conditions(user, skip_options)
        AND (
            trusts_user_override(user, skip_options)
            OR trusts_grant(user, permission, content)
        )
    )
    OR custom_backend_grant(user, permission, content)
    OR ...
```

The named conditions are conceptual SQL placeholders, not Python callbacks.
Each Trusts backend composes its own user conditions and overrides with its grant.
Other backend branches retain their own conditions.

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

### Database routing

The content adapter begins with
`get_user_model()._default_manager.get_queryset()`. The optional user-manager
adapter begins with that manager instance's existing queryset and adds the same
reverse condition.

A saved content instance supplies its database alias when available. Otherwise
Django's router selects the read database. All correlated Trusts and permission
tables must be queryable on that alias. Cross-database authorization cannot be
represented by one SQL statement and is unsupported; Core raises instead of
performing a Python merge or silently querying a second database.

The returned queryset keeps its manager/queryset subclass and database alias,
so later application filtering and ordering compose normally.

### Fail-closed behavior

For ordinary users, the result is empty when:

- no registered path applies to the content model;
- the permission is well formed but unknown;
- a required membership, attachment, ceiling, alignment, or other registered
  condition is absent;
- the grant has been revoked.

Unsaved content, malformed declarations, incompatible
user/permission/content models, unsupported databases, and incomplete backend
coverage raise the corresponding input or configuration error before SQL. They
do not fall back to an empty, partial, or broader query.

### Required Phase B proof

Implementation must cover:

- direct-user and membership-shaped grants;
- explicit `group=` registrations contributing their member users;
- multiple roots and multiple backends;
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

Compare results with each contributing backend's object check for the same
candidate users and normalized permission. Verify default rules, each named
skip option, removed conditions, and an explicitly registered override.

### Non-goals

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

### Implementation slices and size

The documentation pass exposed a larger surface than the original 8--13
estimate.

- Whole Core ticket: **13--21**
- Phase A, this design contract: **3**
- Phase B1, private reverse relationship compiler and agreement fixtures:
  **8**
- Phase B2, public content and optional user-manager adapters,
  permission-string/named-filter codec, backend-coverage preflight,
  user conditions and overrides, routing, lockfile, and migration record: **8**
- GH adoption: separate consumer issue, not included

Phase B1 ships no public application method. Phase B2 exposes
`content.get_permitted_users(perm)` and optional
`User.objects.permitted(content, perm)` only after the full agreement
contract and their result equivalence are proven. Each implementation slice
must be re-sized from the accepted previous head.

### Phase B compiler boundary

`TrustModelBackendMixin.permitted_users_predicate(content, perm)` returns
the backend branch as a `Q`, or `None` when that path does not apply.
`singular_permission_accepted(perm)` is how a backend declares that
singular object `has_perm` accepts a non-string permission instance. The
mixin default accepts `django.contrib.auth.models.Permission` only.

`trusts_object_permissions = False` marks an authentication-only backend
as a backend that grants no object permissions. The exact classes `ModelBackend`,
`AllowAllUsersModelBackend`, `RemoteUserBackend`, and
`AllowAllUsersRemoteUserBackend` are object-blind. A subclass is not
inferred from that ancestry. Any other object-capable `has_perm` without
`permitted_users_predicate` raises `TrustsConfigurationError` before SQL.

An `Along` registration grants through a user-seeded walk. The inquiry for users from content
derives walk-site identities from the bound content, traverses the inverse
graph without the outer candidate user, and joins eligible grants and users
outside the CTE. It uses the same bound, terminal `condition=` overlay, and
user checks as the forward proof. The condition is
not evaluated on intermediate walk nodes. For a fixed content and permission,
the result must agree with the object check for every candidate user.
The policy-lock statement uses this same compiler for users from content. An unsupported
renderer or unrenderable recursive condition raises before SQL or partial
policy output; the path is never dropped or widened to every user.

The content adapter's candidate model is `settings.AUTH_USER_MODEL`. A
registration whose user terminal is a different model fails that adapter
before SQL. The optional manager adapter uses the queryset of the manager
it was mixed into, so a custom user model can be queried from the manager
that owns it.

### Related work

Issue #185 keeps the broader inquiry map and earlier user-to-content history.
This document owns only the inquiry from content and permission to users.

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

## One plan, three projections

`plan_for` selects applicable records by content/user/permission terminal
and compiles them into one `RelationPlan`. Root selection, field
correlation, and `EXISTS` assembly live in that plan. Bindings and
`EXISTS` use the stored lookup. `OuterRef` uses the last step's
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
  the same condition to each candidate content row. Filtering happens in
  SQL before pagination or aggregation.

`RelationPlan.content_exists(user, permission)` is the shared
content-`EXISTS` condition. `filter_content` / `filter_authorized`
consume that same object. A later reader may OR it with another condition
on the original candidate queryset; do not filter trustee rows first and
then try to restore another branch.

Multiple applicable relation roots combine by SQL `OR`. Duplicate grant
rows do not duplicate permission or content results. An unregistered
content model fails closed: empty enumeration, `False`, and
`queryset.none()`.

When the permission terminal's concrete model is `auth.Permission`, the
same `EXISTS` requires that row's content type to be the protected
object's content identity (`app_label` and `model_name`, proxy models
included). A mismatch is an empty condition on every projection. The
codename is not consulted. Any other terminal keeps primary-key identity,
including a custom permission model that has a `content_type` foreign key.

Callers pass model instances for `user`, `content`, and `permission`.
This slice does not accept codename strings or dotted permission syntax.

`RelationPlan` projection methods require model-instance bindings; a
supplied `None` or other non-instance value raises
`TrustsConfigurationError` and is never omitted from the condition.


## Historical adapters and public projections

`ContentQuerySet.permitted` is a thin aggregate caller. It ORs each
applicable handle compiler's condition (`trusts.core.granted`)
and then applies the unchanged condition overlay. Concrete
`TrustModelBackend` routes keep the transitional historical TrustGroup
compiler; mixin-only routes receive only their registered-plan proof.
Public signature and documented one-path results are unchanged.
Unknown or undeclared terminals fail closed (empty / false / none).
`historical_fallback` identifies the concrete
`HistoricalGroupQueryCompiler` for mixin isolation; it does not reopen
a static content map. Mixin-only routes receive only their registered
plan proof.

Declared Category, Ticket, Trust, Group, documented dependents, and
any other registered content model — including ordinary non-`Content`
models — use the same handle and compiler for backend `has_perm` /
`get_all_permissions` / `get_group_permissions`. An instance consults
that backend's handle first. A QuerySet is coordinated by the first
configured Trusts path: one aggregate all-match / common-permission
query; other Trusts backends return false/empty with no SQL.
`obj is None` is false/empty on a Trusts backend; hosts that want
global Django permissions list
`django.contrib.auth.backends.ModelBackend` separately. Declared
Junction-backed Group uses the registered J1 plan and the concrete
compiler's TrustGroup OR. Group-as-protected-content does not replace
Django Group membership as the historical trustee path for Category /
Ticket / Trust. QuerySet plus a legacy callable condition raises
`PermissionConditionNotQueryable` before candidate SQL or callback
invocation. The Trusts app contributes Trust-as-content to every
configured `TrustModelBackend` (or subclass) path; the test app
contributes Category, Ticket, and Junction-backed Group onto the
unique handle. Hosts contribute documented dependents from their own
`AppConfig`.

`TrustManager.filter_by_user_content_perm` is a create-under-Trust
picker, not a content-row filter. Its support gate is
`any_plan_records`: any configured path with `plan_for(content).records`
establishes that the terminal is known. The grant remains
`trust_grant_q` on Trust rows. A declaration on one path does not
authorize through another path's compiler or `historical_fallback`, and
the method is not redirected through `filter_authorized(Trust)` or the
Trust-as-content parent relation. Unregistered models return `none()`.
Declared Group is a known terminal; create-under-Trust still uses
`trust_grant_q` on Trust rows.

## Generic public seams (#54 C1)

These additive APIs are the instance-only / metadata-driven surfaces that
later Zero and GH hosts call. They do not change `ContentQuerySet.permitted`,
`filter_by_user_content_perm`, the app label, or the historical compiler.

`AuthorizedQuerySet.authorized(user, permission, extra_q=None, **skip_options)` and
`AuthorizedManager = Manager.from_queryset(AuthorizedQuerySet)` live in
`trusts.query`. `permission` is a model instance. Strings raise
`TrustsConfigurationError` with zero SQL. The method does not parse
`:condition` or call `get_permission`. It uses the
[user conditions and overrides](../source/index.rst#user-conditions-and-overrides).
`extra_q` is the same AND overlay as `all_match` /
`instance_match`. There is no `.permitted` and no `.get_permission` on
this class. The public content-list inquiry is
`PermittedQuerySet.permitted(permission, user, conditions=())`.
`.authorized` does not call it; the inquiries share user conditions and overrides without sharing
permission-input validation. `skip_options` contains the named `skip_<name>`
keywords described in the guide.
Core `.authorized` includes relationship-family handles
only; it is not Django's object-level authentication-backend OR.

`filter_by_permitted_content(queryset, user, permission, *, content, handles=None, **skip_options)`
in `trusts.core` filters rows of an intermediate model that is a
**proper prefix** of some applicable `RegisteredRelation.content_path`
whose content terminal is `content`. The function compiles `EXISTS` of root rows
correlated to `OuterRef` of that step's resolved target field (the
related `attname` from `get_path_info()`, including non-PK
`ForeignKey(..., to_field=...)`) at that node, binds user +
permission, and ORs applicable records. An `along=` registration
uses that same bounded walk: a prefix at the walk site is kept when
its identity is in the walk, and a later proper prefix is kept when
it hangs off a walk-site row the walk reaches. An ancestor of the walk
site stays the row stored on that grant, including when an ordinary sponsor
grant supplies the ordinary sponsor-grant query. A one-level delegation keeps
a prefix only when the delegation and the ordinary sponsor-grant query
both reach it. Each contributing ordinary sponsor grant's `along=` walk or
exact match must reach the prefix. A second delegation level does not. A
delegated `along=` whose content suffix is longer than one reverse hop raises
`TrustsConfigurationError`. An ordinary sponsor grant's `along=` has that
same limit. `queryset.model` equal to the
content terminal is allowed when a proper prefix step of that same model
exists (self-referential trees). A terminal-only path, an unknown
terminal, empty handles, or a scope model not on the path return
`none()`. Default and explicit handle lists include relationship-family
handles only. Core does not import Zero schema models
(`Trust`, `TrustUserPermission`, `TrustGroup`, …).

`PlanQueryCompiler.group_exists` compiles only records registered with
explicit `group=` (a forward path ending at `auth.Group`; the compiler
appends `Group.permissions`) via `RelationPlan.content_exists`.
`permission=` records stay out of that slice, including when the user
path ends in a many-to-many membership step. Core plans are relationship
records only. A plan with no explicit `group=` record makes
`group_exists` inapplicable (`None`). `complete_exists` still includes
both `permission=` and `group=` records.

