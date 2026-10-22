# Security audit guide

This is the boundary a reviewer checks. It is not a review of the
application, its data, or its deployment.

## Security model

django-trusts answers object-permission questions from registered paths
over saved rows. The same registration drives object checks, permitted
querysets, permission lists, and view guards.

The application still owns authentication, models, constraints, write
paths, migrations, settings, and every other authorization backend.

## Installation and dependencies

Runtime dependencies are Django and PyYAML. Versions are in
[the support matrix](../dev/support-matrix.md).

Django loads the database driver the application configures.
django-trusts does not. Do not add `"trusts"` to `INSTALLED_APPS`.
Install the app that owns the concrete permission models.

Review pinned dependencies with each release. A short dependency list
is not a security proof.

## Models and persisted facts

The application owns the protected models and the trust rows: constraints,
tenancy, state changes, and who may write them. Trusts reads the saved
rows it is given. It does not prove those rows were written by someone
who was allowed to.

## Backend and registration

Extend `TrustsConfigMixin` and record calls on `self.recorder` in
`ready()`, before `super().ready()`. Each Trusts backend answers from
its own catalog. Another backend's grants, registrations, and conditions
do not feed it.

Companions call `trusts.utils.parse_perm_code`,
`trusts.backends.policy_document`, the recorder methods, and the
queryset and decorator helpers.

| API | Meaning | Can grant by itself? |
| --- | --- | --- |
| `recorder.register(...)` | Ordinary grant, or a delegation | Yes, when the registration matches |
| `recorder.add_named_filter(...)` | Extra condition on a model | No |
| `recorder.set_user_condition(..., on="*")` | Required check on the users named by `on=` | No |
| `recorder.set_user_override(..., on="user")` | Optional substitute for an ordinary grant, checked user only | Yes, still subject to required user conditions |

Record user conditions and the override before `register()`. Names are
identifiers and must not collide with call arguments. `skip_<name>` is
a boolean. Replacing the override replaces its skip name. User rules
use database fields. A property such as `is_authenticated` is rejected.

### Ordinary relationship authorization

`register(*, trust, user=None, permission=None, content, group=None, delegate=None, sponsor=None, condition=None, along=None)`.

An ordinary registration passes `user=` and exactly one of `permission=`
or `group=`. A delegation passes `delegate=` and `sponsor=` instead.
Paths are a Django `__` string or a one-argument lambda. The
[setup guide](index.rst#register-the-trust) shows both.

`condition=` is a function, the same language as a named filter or a
user rule. The [setup guide](index.rst#more-expressive-permission-policies)
shows `==`, `!=`, `&`, `|`, `~` on a boolean, and `.contains()`. Pass
the function. Python `in`, `and`, `or`, and `not` are not accepted.

Several registrations for one model on one catalog are alternatives.
A condition narrows only its own registration. Another catalog's
registrations are not included.

### Delegated authority

`delegate` is who may act. `sponsor` is whose grants are the ceiling.
Swapping them changes who can act. The
[setup guide](index.rst#delegate-live-authority) shows the registration
and the row you write.

A delegation's `condition=` takes the relationship, and may take the
requested permission as a second argument. A two-argument function on
an ordinary registration is a configuration error.

For actor `u`, content `c`, and permission `p`, check this shape:

```text
user_conditions(u, "user", skip_options)
AND (
    user_override(u, "user", skip_options)
    OR ordinary(u, c, p)
    OR EXISTS delegation d:
        d.delegate = u
        AND d.content = c
        AND delegated_condition(d, p)
        AND user_conditions(d.sponsor, "sponsor", skip_options)
        AND ordinary(d.sponsor, c, p)
)
```

`get_group_permissions` uses user conditions and group grants. It does
not include the override or delegations.

Audit every condition, override, and skip. An override stands in for an
ordinary grant, so put anything that must still hold inside the override.
`on="*"` (the default) covers the checked user and sponsors. `on="user"`
and `on="sponsor"` cover one of them. Overrides accept only `on="user"`.
One skip removes that condition for every target in its `on=`.

| Rule | Default `on=` | Checked user | Sponsor | `skip_<name>=True` |
| --- | --- | --- | --- | --- |
| Condition | `"*"` | Required | Required | Removed for both |
| Override | `"user"` | Stands in for an ordinary grant | Not used | Removed |
| Condition with `on="sponsor"` | n/a | Not checked | Required | Removed for the sponsor |

### Delegation boundaries

Check:

- the delegation row's delegate, sponsor, content, and condition;
- the sponsor ceiling is that catalog's ordinary grants, not another
  backend's;
- a delegation is not itself a sponsor grant, so one delegation cannot
  sponsor another;
- relationship scope can narrow the ceiling and cannot add a permission
  the sponsor does not have;
- the actor's own ordinary grant remains a separate alternative;
- tenant, approval, revocation, and expiry data have authorized writes
  and database constraints;
- object checks, querysets, permission lists, users-from-content, and
  policy SQL agree.

`along=` on a delegation uses the same form as on an ordinary
registration. The delegation's walk and the sponsor's grant must both
reach the object.

Do not implement delegation by calling `sponsor.has_perm()`. That call
picks up Django's superuser shortcut and other backends, and it will
not match the queryset, the user list, or the policy output.

A terminal many-to-many membership can duplicate rows. Check the
identity it compares and whether the query uses `distinct()`. A path
must be used in full. `user`, `permission`, and `content` may not be
empty.

## Configure Django

Check:

- the app config extends `TrustsConfigMixin`;
- every path in `AUTHENTICATION_BACKENDS`;
- the backend's module lives in the app that owns its catalog;
- an app with registrations has a listed backend;
- duplicate, obsolete, or missing backend paths;
- registrations are recorded before `super().ready()`;
- `python manage.py check`.

django-trusts ships no concrete schema. The application owns its label,
tables, and registrations.

## Ask permission questions

Every projection uses the
[registered user conditions and overrides](index.rst#user-conditions-and-overrides).

Each Trusts backend answers from its own catalog. When more than one
Trusts backend registers the model and `backend=` is omitted,
`.permitted()`, `.authorized()`, `filter_by_permitted_content`,
`get_permitted_users`, `User.objects.permitted`, and
`authorization_required` raise and ask for `backend=`, as Django's
`with_perm` does.

| Question | What you call |
| --- | --- |
| Object permission | `user.has_perm(code, object)` |
| Permission list | `user.get_all_permissions(object)` |
| Permitted objects | `Model.objects.permitted(permission, user, conditions=())` |
| Permitted users | `content.get_permitted_users(perm)` or `User.objects.permitted(content, perm)` |
| View guard | `authorization_required(Model, code, conditions)` |

`.authorized(user, permission)` takes a permission row, not a string,
and does not select named conditions.

The queries are fixed by registration. That does not make the rows,
other backends, or the deployment trustworthy. Re-read the SQL when the
registration, Django version, or database changes.

## User conditions and overrides

The [setup guide](index.rst#user-conditions-and-overrides) shows how to
set, replace, remove, and skip them.

### Django auth's checks before calling backends

`PermissionsMixin.has_perm()` allows an active superuser before any
backend runs. Trusts does not change that. Trusts inquiries and policy
SQL do not grant superusers unless you register an override.
`authorization_required` does not use the shortcut. Django's
`has_perm()` and permission lists do not accept `skip_<name>`. Use a
Trusts call for a skip.

To leave the shortcut, override `has_perm()` and `has_module_perms()`
on the user model and ask the backends directly. That also changes
Django admin. Use a non-superuser staff account when an administrator
must still pass object, tenant, or named-filter checks.

An optional superuser override:

```python
self.recorder.set_user_override(
    "superuser", lambda u: u.is_active & u.is_superuser,
)
```

`skip_is_active` does not skip the `is_active` test inside that
override. `skip_superuser=True` skips the override while it is named
`superuser`. Remove it with
`self.recorder.set_user_override("superuser", None)`.

To stop superusers sponsoring, add a sponsor condition. It is not
installed for you. `skip_superuser` does not skip it.

```python
self.recorder.set_user_condition(
    "superuser_cannot_sponsor", lambda u: ~u.is_superuser, on="sponsor",
)
```

Django grants when any configured backend grants. Trusts cannot take
back a grant from another backend. Do not treat one denying Trusts
backend as a global deny.

## Protect a view

`authorization_required` reads only `view_kwargs["pk"]` and binds it to
the model's primary key. The request cannot choose the query.

```python
@authorization_required(Document, "documents.change_document")
def edit_document(request, pk):
    ...
```

The [setup guide](index.rst#protect-a-view) shows the surrounding setup.
A missing row is 404. An existing unauthorized row is 403. Named filters
narrow the grant. An override still requires the row to exist and the
required user conditions to pass. Pass `backend=` when two Trusts
backends register the model.

## More expressive policies

### Named filters restrict the query

```python
self.recorder.add_named_filter(
    Document, "non_confidential",
    predicate=lambda u, p, o: o.confidential != True,
)
```

The [setup guide](index.rst#named-filters) shows the `:name` suffix.
The function runs at startup in the same app code as `ready()`.
django-trusts does not sandbox it. A filter narrows an existing grant.
It does not create one. Permission lists return the permission, not
every filter name.

At a check, read it as the grant and the selected filter, both required.

### Runtime callbacks are unsupported

There is no runtime permission callback. `TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS`
does not bring one back. If it is true, `manage.py check` reports
`trusts.E007`.

A condition's shape is fixed at registration. A request value may only
fill a value you already declared.

### Many-to-many paths

A membership hop can multiply rows. Check which field is the identity,
whether a reverse accessor of the same name is the one Django resolves,
and whether duplicates are removed.

### Bounded inherited relationships

`along=` replaces one equality with a bounded walk. Check:

- direction and the ancestor or descendant you meant;
- the bound;
- cycles;
- the identity compared at each hop;
- the database you render;
- that object checks, querysets, permission lists, and user lists agree.

Compare users-from-content with a forward object check for the same
content and permission. If the walk cannot be rendered exactly, the
inquiry raises rather than returning a wider set. The policy output
does the same. CI runs Along only for the databases in the support
matrix.

## Fail-closed principle

Anything that cannot be authorized safely must not become a grant. That
includes a missing registration, a bad path, a conflicting registration,
the wrong user or model, an `auth.Permission` whose content type is not
the object's, mismatched `to_field` identities, an unknown named filter,
an unsupported condition, an unsupported database, and a `pk` that does
not coerce. The list is not complete. A path that fails open is a defect.

### Permission content type

When the permission row is an `auth.Permission`, it matches only the
content type of the protected object, including a proxy model's own
type. Any other permission model matches by primary key.

A mismatch is a denial, not a configuration error. `has_perm` is
`False`. The codename is absent from `get_all_permissions`.
`.permitted()` and the user list are empty. `authorization_required`
denies. Policy SQL carries the same condition.

String `has_perm` still guesses the model from the codename. That is
[issue #268](https://github.com/django-trusts/django-trusts/issues/268).
`.permitted()` and `authorization_required` use the model's content type.

Django's superuser shortcut, above, still applies to `user.has_perm()`.
Trusts calls do not add a superuser override unless you register one.

## Authorization policy SQL and lockfile

`python manage.py trusts_policy_sql` prints the parameterized SQL for
review. The YAML is not an input format. The
[setup guide](index.rst#permission-policy-in-sql) shows the command and
the lockfile check.

`trusts.backends.policy_document()` returns that document for every
installed Trusts backend. A backend's `policy_document()` returns that
backend's catalog only. `alias` selects the database. Each entry is one
catalog. A chain of `and`, or a chain of `or`, prints flat.
Companions use `policy_document` and `trusts.utils.parse_perm_code`.

### Renderer, connection, and stability boundary

One lockfile is one database renderer. `TRUSTS_POLICY_DATABASE` selects
it. Unset, that is Django's `default`. Use the same alias in every job
that renders or checks that file. The output does not claim another
engine would match.

Rendering does not run the authorization queries and does not read grant
rows. The driver may still connect. Audit that alias's settings, driver,
server, and account.

Byte equality is for one django-trusts version, the same Django and
PyYAML, and the same renderer. A version change can change the bytes
without an application change. Regenerate and read the diff.

The [historical policy-output record](../dev/permission-policy-sql.rst)
is one snapshot. Its field names and SQL layout are not a format you
can depend on.

### Formatter and enforcement

The formatter accepts only tokens it knows. It does not guess or return
a partial statement.

`TRUSTS_POLICY_LOCKFILE` must be an absolute path when set. Otherwise
the lockfile is the usual file under an absolute `BASE_DIR`.

`trusts.E009` compares the generated bytes with that file. It does not
parse the YAML and it does not run on a request.

### What equality does not prove

Matching bytes show that these declarations, versions, and this renderer
produced the file you reviewed. They do not show that the compiler is
correct, that grant rows are trustworthy, that the application cannot
bypass the check, how other Django backends behave, that the inspection
database matches production, or that a matching code-and-lockfile change
is safe.

Django still grants when any configured backend grants. An active
superuser is still allowed in `PermissionsMixin.has_perm()` before
backends run.

## Reference implementations

The [setup guide](index.rst#reference-implementations) links examples.
They are not security reviews of those applications.

## Validation and review discipline

Run the supported tests, the documentation build with warnings as
errors, package checks, `manage.py check`, and the companion tests the
change touches. 0.x compatibility notes belong in `django-trusts-zero`.

For a material change, answer:

1. Which statement in this guide does the change keep?
2. Does it add a way to grant?
3. Do object, queryset, permission-list, and guard results still agree?
4. Does registration touch the database, or publish a half-updated catalog?
5. Is the authorization query still within its tested bound?
6. Did a private implementation become reachable, or did one catalog
   read another's grants?
7. If a lockfile is involved, were changes to the backend, the
   registration, the operation, parameter roles, `sql`, and
   `database.engine` reviewed on their own?
8. If the code and this guide disagree, which one is wrong?

Say the discrepancy in the PR.
