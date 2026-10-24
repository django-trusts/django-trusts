# Security audit guide

This guide describes the security boundary that implementation and
documentation changes are expected to preserve. It is an audit map, not a
substitute for reviewing the application, its data, or its deployment.

## Security model

django-trusts answers object-permission questions from explicitly registered
paths over persisted relational facts. Registration uses a small set of closed,
typed declarations that are normalized and validated during application setup.
The same normalized policy supports object checks, permitted querysets,
permission enumeration, and view guards.

This makes the supported policy surface inspectable; it does not make an
application secure by itself. The application still owns authentication,
models, constraints, write paths, migrations, workflows, deployment settings,
and every authorization backend installed beside django-trusts.

## Installation and dependencies

django-trusts's direct runtime dependencies are Django and PyYAML. The supported
Python, Django, and database
combinations are recorded in [the support matrix](../dev/support-matrix.md).
Build and test dependencies are not part of the runtime authorization boundary.

Django selects and loads the database backend and driver configured by the
application; django-trusts does not import, select, or manage database drivers. The
application and deployment therefore own driver provenance and versioning,
secure connection settings, and operational availability.

django-trusts supplies no Django application or concrete permission schema. Do not add
`"trusts"` to `INSTALLED_APPS`. Install the application or package that owns
the concrete Trusts implementation instead.

A small dependency surface reduces supply-chain exposure, but dependency count
is not a security proof. Review exact dependency constraints and artifacts as
part of each release.

## Models and persisted facts

The application owns all protected models and trust records. It must
enforce their database constraints, tenancy rules, valid state transitions, and
authorized write paths.

Trusts evaluates the persisted state it is given. It does not prove that an
administrator, import job, signal, raw SQL statement, or application endpoint
was entitled to create that state.

## Backend and registration

A configured Trusts implementation backend is the public registration
boundary. Application code uses the object returned by
`backend.get_registry()`; it must not construct private registry or compiler
objects.

The registration APIs define permission sources and restrictions:

| API | Meaning | Can grant independently? |
| --- | --- | --- |
| `register(...)` | Register an ordinary grant or a delegated relationship and its protected content | Yes, when the registered policy matches |
| `add_named_filter(...)` | Bind a model-scoped name to a registration-time condition | No |
| `registry.set_user_condition(..., on="*")` | Require a named user condition on the users named by `on=` unless skipped | No |
| `registry.set_user_override(..., on="user")` | Register an optional alternative to ordinary grants for the checked user only | Yes, subject to required user conditions |

django-trusts registration is intended not to issue SQL. Unsupported paths,
types, constants, and combinations are intended to be rejected during setup.
User conditions and overrides must use database fields; properties such as `is_authenticated`
raise at registration. Registration closes when the registry freezes.

Set user conditions and overrides before any ordinary or delegated registration; later calls raise without changing the registry.
Names must be unique Python identifiers and must not conflict with inquiry
parameters. Skip values must be booleans. Replacing the override also replaces
its skip name.

### Ordinary relationship authorization

Call `registry.register()` from the owning
implementation's `AppConfig.ready()` before the registry freezes.

The public registration signature is
`register(*, trust, user=None, permission=None, content, group=None, delegate=None, sponsor=None, condition=None, along=None)`.
An ordinary registration supplies `user=` and exactly one of `permission=` or
`group=`. The required `trust=` model is the root of its non-empty paths:

```python
registry.register(
    trust=DocumentPermission,
    user="user",
    permission="permission",
    content="document",
)
```

The [setup guide](index.rst#register-the-trust) also shows the
lambda spelling.

Each path accepts either a Django `__` string or a one-argument path lambda;
django-trusts calls the
lambda once with a symbolic path value. Attribute access records a path rooted
at the `trust=` model; other operations are unsupported. django-trusts
validates the resulting path with Django model metadata, stores its normalized
`__` form, and does not retain the lambda.

The lambda runs during `AppConfig.ready()`, in the same application context
as the surrounding registration code. django-trusts does not inspect or sandbox
unrelated Python in its body. Its path validation is designed not to issue SQL;
that statement does not cover other application code executed by the lambda.
An exception, an empty or invalid path, or an unsupported relationship shape is
rejected before django-trusts updates the registry. Side effects already
performed by application code are outside that behavior.

`condition=` is the same one-argument symbolic condition, rooted at `trust=`.
It is invoked once after the freeze check. Supported operations are path equality
(`==`), collection-rooted `.contains(member)`, and conjunction (`&`). Literal
Python `in` is unsupported and is not recovered through AST, bytecode, `dis`,
or a `__contains__` side channel. The stored overlay is private and
contains no callable. Public
`register(condition=...)` rejects a prebuilt condition. `.contains` is a reserved condition-proxy method; a model field of
that name cannot be walked there. The `predicate=` keyword is reserved and
unsupported. Invalid arity, foreign roots, empty or non-expression
returns, unsupported operations, and condition exceptions fail closed.
django-trusts' own validation is designed not to issue SQL and does not
partially mutate the registry.

A matching path is positive authorization evidence. Multiple matching
relationship registrations for the same protected model are alternatives and
combine with OR in one generated query. A condition attached to a relationship
narrows only that branch and cannot create a grant.

### Delegated authority

A delegated registration replaces the ordinary `user=` plus `permission=` or
`group=` pair with `delegate=` plus `sponsor=`. The
[setup guide's delegation example](index.rst#delegate-live-authority) shows
the registration and relationship data writes.

`delegate` is the current actor receiving delegated access. `sponsor` is the
user who delegated authority and whose current ordinary grants provide
the ceiling. Reversing those paths changes who can act and is an authorization
defect.

A delegated condition builder receives either the relationship root alone or
that root plus the requested permission as symbolic values. The one-argument
form applies row-only restrictions. The two-argument form may also compare the
requested permission with relationship-owned scope data. Both forms are
invoked once during registration and may express restrictions such as
approval, tenant alignment, revocation, or expiry. The compiler stores
normalized expression data and retains no callable. A two-argument builder on
an ordinary registration, or any unsupported arity, is a configuration error.

Inputs and configuration are validated before any override. Invalid input
is denied even for a user the override would grant. An override cannot turn a
permission for another content type into a grant or bypass content identity
and candidate-existence checks, including those enforced in SQL.

For a valid inquiry by actor `u`, content `c`, and permission `p`,
the projections compile this authorization shape:

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

`get_group_permissions` instead combines required user conditions with
group grants; it does not include the override or delegated grants.

User conditions and overrides and named skip options follow the
[usage guide](index.rst#user-conditions-and-overrides).
These names describe compiled conditions, not runtime callbacks. Audit every
registered condition, optional override, and permitted skip option. An override
can stand in for an ordinary grant; include any requirements that must remain
effective when other user conditions are skipped in the override itself.
`user_conditions(x, target, ...)` includes only conditions whose `on=` covers
`target`; `"*"` covers both. Conditions default to `on="*"`.

| Rule | Default `on=` | Checked user | Sponsor | With `skip_<name>=True` |
| --- | --- | --- | --- | --- |
| Condition | `"*"` | Required | Required | Removed for both |
| Override | `"user"` | Alternative to ordinary grants | Never supported | Removed |
| Condition with `on="sponsor"` (e.g. `superuser_cannot_sponsor`) | n/a | Not checked | Required | Removed for the sponsor |

Conditions accept `on="*"` (default), `"user"`, or `"sponsor"`.
Overrides accept only `"user"`. Other values
raise at registration. One skip removes a condition for every target in its
`on=`.


### Delegation boundaries

Audit the following boundaries:

- the exact delegation row must bind its delegate, sponsor, content, and
  condition state; rows must not borrow fields from one another;
- the sponsor-grant query is the live OR-union of applicable ordinary grants
  on that backend;
- the current compiler excludes delegated registrations from the sponsor
  ordinary-grant union, preventing an unbounded chain or cycle;
- relationship scope can narrow the sponsor ceiling but cannot manufacture a
  permission the ordinary sponsor-grant query does not provide;
- delegate and sponsor eligibility must be enforced inside the shared plan,
  without loading the sponsor or issuing a second authorization inquiry;
- the actor's independent ordinary grant remains a separate OR branch;
- tenant, organization, approval, revocation, and expiry data require
  authorized write paths and database constraints; and
- object checks, permitted querysets, enumeration, inquiry for users from content, and policy
  SQL must agree and remain one queryset statement per inquiry.

A delegated registration may use the same bounded `along=` grammar as an
ordinary registration. Its relationship walk and the sponsor-authority
condition must authorize the same object. Each ordinary sponsor grant's
effective bounded reach participates in the ceiling. A delegation cannot
sponsor another delegation.

Delegation remains inside the registered declarative policy and its correlated
ordinary sponsor-grant query. An application-level nested call to
`sponsor.has_perm()` falls outside that audited policy surface: it can import
Django's superuser and authentication backend checks, separate the relationship row from its authority
condition, and disagree with queryset, users-from-content inquiry, or lockfile behavior.

A terminal many-to-many user membership is supported where validated. Review
the resolved comparison identity, duplicate-row behavior, and whether
`distinct()` is present on projections that need it. A long path must be
compiled from every segment; no implementation may validate the path
and then query only its first hop.

The `user`, `permission`, and `content` relationship path arguments may
not be empty.

## Configure Django

Audit all of the following:

- the implementation `AppConfig` in `INSTALLED_APPS`;
- every dotted path in `AUTHENTICATION_BACKENDS`;
- ownership of each configured Trusts backend path;
- duplicate, obsolete, or missing backend paths;
- the point at which registration freezes; and
- the output of `python manage.py check`.

django-trusts is schema-neutral and has no final `AppConfig`. Concrete implementations
own their application labels, migrations, tables, and registration calls.

## Ask permission questions

All Trusts projections follow the
[registered user conditions and overrides](index.rst#user-conditions-and-overrides).

The supported projections consume the same normalized registration:

| Question | Public shape | Expected database behavior |
| --- | --- | --- |
| Object permission | `user.has_perm(code, object)` | Bounded object authorization query |
| Permission enumeration | `user.get_all_permissions(object)` | Permissions produced from the same plan |
| Permitted objects | `Model.objects.permitted(permission, user, conditions=())` | Registered user conditions and overrides and relationship-family SQL before pagination |
| Permitted users | `content.get_permitted_users(perm)`; optional `User.objects.permitted(content, perm)` | Each Trusts backend answers from its own registrations, including its user conditions and overrides; `backend=` selects one backend. |
| View guard | `authorization_required(Model, code, conditions)` | Fixed `pk` URL binding and relationship-family Trusts-only authorization |

`.permitted(permission, user)` is the public content-list inquiry.
`.authorized(user, permission, extra_q=None)` is the lower-level instance
projection: it accepts permission instances rather than strings and does not
select named conditions. Both use the shared user checks.

Fixed-query behavior is intentional: registration-time structure and
parameterized runtime bindings keep the authorization surface closed and
inspectable. It is not proof that application data, neighboring backends, or
deployment choices are trustworthy. Review the actual generated query whenever
a registration shape, Django version, database backend, or compiler changes.

## User conditions and overrides

The [setup guide](index.rst#user-conditions-and-overrides) explains
registration, replacement, removal, and per-inquiry skip options.

### Django auth's checks before calling backends

Django's `PermissionsMixin.has_perm()` allows an active superuser before
consulting authentication backends. Trusts does not change that shortcut.
Trusts inquiries and policy SQL have no implicit superuser grant, including
`authorization_required`. Django's stock `has_perm()` and permission-enumeration
methods do not forward Trusts-specific skip keywords; use a Trusts inquiry API
when a skip is needed.

An application can opt out of Django's shortcut in its custom user model by
overriding `has_perm()` and `has_module_perms()` to ask the backends without
the superuser early return. This also changes superuser behavior in Django
admin. Use staff/non-superuser accounts for administrators who must remain
subject to tenant, parent, object, or named-filter restrictions.

To opt into a Trusts override, register its own activity requirement:

```python
registry.set_user_override(
    "superuser",
    lambda u: u.is_active & u.is_superuser,
)
```

`skip_is_active` does not skip the activity check inside this override.
To inspect only ordinary
grants, use a Trusts inquiry with `skip_superuser=True`. That keyword is valid
only while `superuser` names the current override. Pass
`set_user_override("superuser", None)` to remove it; any other name raises.

Conditions apply to both the checked user and sponsors by default. To prevent
superusers from sponsoring even their ordinary grants, an application can add:

```python
registry.set_user_condition(
    "superuser_cannot_sponsor",
    lambda u: ~u.is_superuser,
    on="sponsor",
)
```

This condition is not installed by default. `skip_superuser` skips the override,
not this condition.

For ordinary users, Django grants when any configured authentication backend
grants. Trusts cannot revoke authorization supplied by another backend. Audit
every configured backend for object-permission behavior; do not rely on a
rejecting Trusts branch as a global deny.

## Protect a view

The django-trusts view guard deliberately accepts only `view_kwargs["pk"]`, coerces it
through the protected model's primary-key field, and keeps it as a parameter.
Request data cannot select query structure.

```python
@authorization_required(Document, "documents.change_document")
def edit_document(request, pk):
    ...
```

The [setup guide](index.rst#protect-a-view) shows the surrounding
application setup.

The guard performs structural preflight before candidate lookup. An absent
candidate produces 404; an existing but unauthorized candidate produces 403.
Its selected named filters constrain the relationship proof. Audit how an
explicitly registered user override composes with those filters. A successful
override still requires the candidate to exist and required user conditions
to pass.


## More expressive policies

### Named filters restrict the query

A named filter is registered against the protected model during application
setup:

```python
registry.add_named_filter(
    Document,
    "non_confidential",
    predicate=lambda u, p, o: o.confidential != True,
)
```

The [setup guide](index.rst#named-filters) shows how callers select
that filter.

The backend invokes the callable once with symbolic user, permission, and
object references. Operations on those references construct a closed expression
tree; django-trusts validates and normalizes that result, stores only the
immutable IR, and discards the callable. The condition runs in the same
application-startup context as its surrounding code and receives no additional
authority from django-trusts. django-trusts does not inspect or sandbox the
callable body; SQL, I/O, request state, and mutable captures remain application
behavior outside the returned-expression validation.

At an authorization site, the named filter restricts an existing grant:

```text
SelectedAuthorizationEngine(object, user, permission)
AND
NamedFilter(object, user, permission)
```

Unknown, unbound, or untranslatable named filters are intended to produce no
grant. A filter restricts an existing grant; it is not intended to create one.
Permission enumeration returns bare permissions rather than every possible
combination of permission and filter names.

### Runtime callbacks are unsupported

Arbitrary runtime permission callbacks are not part of the public surface. They
are outside the supported object/queryset parity, startup-validation,
query-inspection, and fixed-query model.

The obsolete `TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS` setting does not
restore callbacks. If it remains true, Django's system checks report
`trusts.E007`.

Policy conditions define fixed query structure during registration. Runtime
request values may bind only to a predeclared lookup and must remain
parameterized data; they may not choose a model, backend, permission, path,
operator, condition structure, ordering, or SQL fragment.

### Many-to-many paths

A terminal membership hop may multiply permission-bearing rows. Review
cardinality, identity fields, through-model constraints, duplicate elimination,
and whether a similarly named reverse accessor is actually the query name
resolved by Django metadata.

### Bounded inherited relationships

`Along` replaces equality at one registered relationship walk-site with
bounded reachability. Audit:

- the starting direction and intended ancestor/descendant meaning;
- the maximum bound;
- termination in the presence of cycles;
- the resolved identity at every hop;
- the supported database renderer; and
- agreement among object, queryset, enumeration, and users-from-content projections.

The inquiry for users from content derives walk-site identities from the bound content and
traverses the inverse graph without the outer candidate user. Eligible grants
and users join that walk outside the CTE. The users-from-content branch carries the same
terminal condition and user checks; the condition must not move onto
intermediate walk nodes. Compare returned users with forward object
checks for the same content and permission. If the walk cannot be rendered
exactly, inquiry raises before SQL rather than returning a broader user set.
The policy output does the same for that statement, so output that would omit
or simplify the query for users from content is not emitted. Audit the declared
walk, bound, generated recursive SQL, and returned-user parity together.

Current CI exercises Along only for the database combinations listed in the
support matrix.

## Fail-closed principle

django-trusts is designed around a fail-closed principle. We intend cases that
cannot be safely authorized not to become grants silently. This includes:

- missing or unknown registrations;
- malformed paths or unsupported relationship shapes;
- conflicting registrations;
- wrong user, permission terminal, or protected model;
- an `auth.Permission` whose `content_type` is not the protected object's content type;
- incompatible `to_field` identities;
- unknown named filters;
- unsupported condition expressions;
- unsupported database renderers; and
- invalid request primary-key coercion.

This list is not exhaustive. A newly discovered path that can fail open is
treated as a defect and should be closed.

### Permission content type

`auth.Permission.content_type` is that permission row's model identity.
The typed check applies only when the permission terminal's concrete
model is `auth.Permission`, on a direct foreign key or a terminal
many-to-many. Every shared grant then requires that row's content type
to identify the protected object. The identity is the object's own
content type, including a proxy model's own type, written into the grant
as `app_label` and `model` constants. There is no second query to load a
`ContentType` row, and the codename is not parsed to guess the model.

A mismatch is ordinary authorization input, not a configuration error.
`has_perm` for a permission string is `False`. `get_all_permissions` omits
the codename. `.permitted()` and `get_permitted_users` /
`User.objects.permitted` are empty for that pair. `authorization_required`
denies an ordinary user. The generated policy SQL carries the same
condition. Any other permission terminal stays primary-key identity,
including a custom model that has a `content_type` foreign key.

String `has_perm` still infers the model from the codename suffix. That
codec gap is [issue #268](https://github.com/django-trusts/django-trusts/issues/268).
`.permitted()` and `authorization_required` bind the exact codename to the
protected model's content type instead. Each asks each backend; a backend
that does not own the names contributes nothing (an empty queryset, or
403 / 404 on the view). There is no system check for those decorator names.

The [Django backend boundary](#django-auths-checks-before-calling-backends)
still applies to native `user.has_perm()`. Trusts-owned inquiries use the
registered user conditions and overrides; they do not install a superuser override implicitly.

Where practical, configuration failures should surface during startup or system
checks. Runtime denial should not fall back to a broader Trusts path.

## Authorization policy SQL and lockfile

`python manage.py trusts_policy_sql` produces one-way review output containing
the generated parameterized SQL. It lets reviewers inspect the queries and
notice changes. The YAML is not a public schema or an input format.

### Renderer, connection, and stability boundary

One lockfile records output from one selected Django database renderer.
`TRUSTS_POLICY_DATABASE` selects the inspection alias; Django's `default`
alias is used when it is unset. Keep that choice consistent in every job that
renders or checks one lockfile. The output reflects the selected renderer and
does not imply equivalence with another database engine.

Rendering compiles the statements without executing them or reading
application or authorization rows. A selected backend or driver may still open
a connection for initialization, server-version discovery, or capability
queries. Audit the inspection alias's connection settings, driver provenance,
server capabilities, and account authority.

Byte comparison is intended only for query inspection and change detection
within one django-trusts version, with unchanged dependencies, including Django
and PyYAML, and the same selected renderer. A version or dependency change may
alter the output without changing application declarations. Regenerate the
lockfile and review that diff with the upgrade.

The [historical policy-output record](../dev/permission-policy-sql.rst) and
its examples describe one implementation snapshot. Their field names, ordering,
identifiers, parameter notation, and SQL/YAML layout are not compatibility
promises or a supported input format.

### Formatter and enforcement

The SQL formatter accepts only the tokens it understands and fails closed on an
unexpected token. It does not strip, guess, or return partially formatted SQL.

`TRUSTS_POLICY_LOCKFILE` may select an explicit absolute path; relative paths
are errors. Otherwise django-trusts uses the conventional lockfile under an
absolute `BASE_DIR`.

The Django model check `trusts.E009` compares the generated bytes with the
committed file. It does not parse the YAML and is not a request-time
authorization gate. See the [setup guide](index.rst#permission-policy-in-sql)
for lockfile-generation and CI-check commands.

### What equality does not prove

Lockfile equality proves only that the current declarations, versions,
dependencies, and selected renderer produced the reviewed bytes. It does not
prove:

- compiler correctness;
- trustworthy authorization rows or grant workflows;
- the absence of application bypasses;
- the behavior of other Django authentication backends;
- that the inspection renderer matches production; or
- that a code and lockfile change is safe merely because they match.

Django still grants when any configured authentication backend grants. An
active superuser remains globally authorized in `PermissionsMixin.has_perm()`
before backends run. Lockfile equality is a change-control aid, not a security
proof.

## Reference implementations

The [setup guide's reference implementations](index.rst#reference-implementations)
illustrate supported declaration shapes; their examples are not application
security assessments.

## Validation and review discipline

Run the complete supported test matrix, warning-fatal documentation build,
package/fresh-install checks, Django system checks, and exact companion tests
required by the changed surface. API changes require review of their migration
impact. Compatibility instructions for 0.x belong in
`django-trusts-zero`.

For every material implementation or documentation change, reviewers should
answer:

1. Which statement in this guide does the change implement or preserve?
2. Does the change expand the grant-producing surface?
3. Do object, queryset, enumeration, and guard projections still agree?
4. Does the change introduce registration-time database access or partial mutation?
5. Is the final authorization query still within its tested statement bound?
6. Did any unsupported database, callback, private registry, or private IR
   surface become reachable?
7. If a policy lockfile is in play, does equality show only that the live
   declared authorization surface and rendered SQL match the reviewed
   artifact, and has every change to the Trusts backend or registration,
   operation, parameter roles, `sql`, or `database.engine` been reviewed
   on its own?
8. If the implementation disagrees with this guide, is the code wrong, is the
   guide wrong, or has an explicit design decision changed the boundary?

Discrepancies must be surfaced in the PR rather than resolved implicitly.
