# Security audit guide

This guide describes the security boundary that implementation and
documentation changes are expected to preserve. It is an audit map, not a
substitute for reviewing the application, its data, or its deployment.

## Security model

django-trusts answers object-permission questions from explicitly registered
paths over persisted relational facts. Registration uses a small set of closed,
typed declarations that are normalized and validated during application setup.
The same normalized policy supports object checks, authorized querysets,
permission enumeration, and view guards.

This makes the supported policy surface inspectable; it does not make an
application secure by itself. The application still owns authentication,
models, constraints, write paths, migrations, workflows, deployment settings,
and every authorization backend installed beside django-trusts.

## Installation and dependencies

django-trusts's direct runtime dependencies are Django and the exact supported
`PyYAML==6.0.3` writer release. The supported Python, Django, and database
combinations are recorded in [the support matrix](docs/support-matrix.md).
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
`configured_backend()`; it must not construct private registry or compiler
objects.

The django-trusts 1.x public surface has one grant-producing family and one restricting
overlay:

| API | Meaning | Can grant independently? |
| --- | --- | --- |
| `register(...)` | Register a trust model and its paths to user, permission, and protected content | Yes |
| `add_named_filter(...)` | Bind a model-scoped name to a registration-time predicate | No |

django-trusts registration is intended not to issue SQL. Unsupported paths,
types, constants, and combinations are intended to be rejected during setup.
Registration closes when the configured registry freezes; late mutation is
rejected.

### Relationship authorization

A trust registration has the public signature
`register(*, trust, user, permission, content, condition=None, along=None)`.
The required `trust=` model is the root of the three non-empty paths:

```python
backend.register(
    trust=DocumentPermission,
    user=lambda t: t.user,
    permission=lambda t: t.permission,
    content=lambda t: t.document,
)

backend.register(
    trust=DocumentPermission,
    user="user",
    permission="permission",
    content="document",
)
```

Each path accepts either a Django `__` string or a one-argument path lambda;
both forms of the same registration are shown above. django-trusts calls the
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

`condition=` is the same one-argument symbolic predicate, rooted at `trust=`.
It is invoked once after the freeze check. 1.0 operations are path equality
(`==`), collection-rooted `.contains(member)`, and conjunction (`&`). Literal
Python `in` is unsupported and is not recovered through AST, bytecode, `dis`,
or a `__contains__` side channel. The stored overlay is private `Equal` /
`PermissionIn` / `All` and contains no callable. Public
`register(condition=...)` rejects prebuilt `All` / `Equal` / `permission_in`
values. `.contains` is a reserved condition-proxy method; a model field of
that name cannot be walked there. The `predicate=` keyword is reserved and
unsupported in 1.0. Invalid arity, foreign roots, empty or non-expression
returns, unsupported operations, and predicate exceptions fail closed.
django-trusts' own validation is designed not to issue SQL and does not
partially mutate the registry.

A complete matching path is positive authorization evidence. Multiple complete
relationship registrations for the same protected model are alternatives and
combine with OR in one generated query. A condition attached to a relationship
narrows only that branch and cannot create a grant.

A terminal many-to-many user membership is supported where validated. Review
the resolved comparison identity, duplicate-row behavior, and whether
`distinct()` is present on projections that need it. A long path must be
compiled from every segment; no implementation may validate the complete path
and then query only its first hop.

The `user`, `permission`, and `content` relationship path arguments may
not be empty.

### Named filters are outer restrictions

A named filter is registered against the protected model:

```python
backend.add_named_filter(
    Document,
    "non_confidential",
    predicate=lambda u, p, o: o.confidential != True,
)
```

The backend invokes the callable once with symbolic principal, permission, and
object references. Operations on those references construct a closed expression
tree; django-trusts validates and normalizes that result, stores only the
immutable IR, and discards the callable. The predicate runs in the same
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
deterministic-inspection, and fixed-query model.

The obsolete `TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS` setting does not
restore callbacks. If it remains true, Django's system checks report
`trusts.E007`.

Policy predicates define fixed query structure during registration. Runtime
request values may bind only to a predeclared lookup and must remain
parameterized data; they may not choose a model, backend, permission, path,
operator, predicate structure, ordering, or SQL fragment.

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

### Django's outer authorization boundary

Django treats an active superuser as globally authorized in
`PermissionsMixin.has_perm()` before consulting authentication backends.
Treat `is_superuser` as an unrestricted root override. Use
staff/non-superuser accounts for administrators who must remain subject to
tenant, parent, object, or named-filter restrictions.

For ordinary users, Django grants when any configured authentication backend
grants. Trusts cannot revoke authorization supplied by another backend. Audit
every configured backend for object-permission behavior; do not rely on a
rejecting Trusts branch as a global deny.

## Ask permission questions

The supported projections consume the same normalized registration:

| Question | Public shape | Expected database behavior |
| --- | --- | --- |
| Object permission | `user.has_perm(code, object)` | Bounded object authorization query |
| Permission enumeration | `user.get_all_permissions(object)` | Permissions produced from the same plan |
| Authorized objects | `Model.objects.authorized(user, permission)` | Relationship-family SQL before pagination; not Django backend OR |
| View guard | `authorization_required(Model, code, conditions)` | Fixed `pk` URL binding and relationship-family Trusts-only authorization |

The django-trusts view guard deliberately accepts only `view_kwargs["pk"]`, coerces it
through the protected model's primary-key field, and keeps it as a parameter.
Request data cannot select query structure.

```python
@authorization_required(
    Document,
    "documents.change_document",
    ("non_confidential",),
)
def edit_document(request, pk):
    ...
```

The guard performs structural preflight before candidate lookup. An absent
candidate produces 404; an existing but unauthorized candidate produces 403.
Its selected named filters are AND restrictions. Active superusers bypass
grants and filters only after configuration preflight and still require the
candidate to exist.


Fixed-query behavior is intentional: registration-time structure and
parameterized runtime bindings keep the authorization surface closed and
inspectable. It is not proof that application data, neighboring backends, or
deployment choices are trustworthy. Review the actual generated query whenever
a registration shape, Django version, database backend, or compiler changes.

## More expressive policies

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
- agreement among object, queryset, and enumeration projections.

Current CI exercises Along only for the database combinations listed in the
support matrix.

## Fail-closed principle

django-trusts is designed around a fail-closed principle. We intend cases that
cannot be safely authorized not to become grants silently. This includes:

- missing or unknown registrations;
- malformed paths or unsupported relationship shapes;
- conflicting registrations;
- wrong user, permission, or protected models;
- incompatible `to_field` identities;
- unknown named filters;
- unsupported predicate expressions;
- frozen-registry mutation;
- unsupported database renderers; and
- invalid request primary-key coercion.

This list is not exhaustive. A newly discovered path that can fail open is
treated as a defect and should be closed.

Where practical, configuration failures should surface during startup or system
checks. Runtime denial should not fall back to a broader Trusts path.

## Authorization policy SQL and lockfile

The user-facing [authorization policy SQL guide](docs/source/authorization-policy-sql.rst)
describes the schema, command, lockfile, and system-check workflow. This section
records the additional security boundaries.

The generated YAML is organized by backend and protected content model. Trust
legs expose the declared relationships. Each content with trusts records the
complete compiler SQL for `permitted`, `has_perm`, and `get_all_permissions`;
filter-only contents carry only their model and standalone `named_filters`, and
empty relationship backends remain visible as `contents: []`. `permitted` is
the artifact label for one backend's list query and matches `.authorized()` only
when that backend is the sole relationship-family contributor.

The artifact does not use public SQL fragments, references, reverse
reconstruction, or a YAML-to-registration contract. It also does not record
permission-code variants, QuerySet-valued `has_perm`, `get_group_permissions`,
grant-plus-named-filter SQL, zero-SQL short circuits, the relationship-family
OR compiled by `.authorized()` across multiple Trusts backends, or Django's OR
and set union across authentication backends. Those paths require separate
tests and review.

### Renderer and connection boundary

A lockfile belongs to one selected Django database renderer. `database.engine`
identifies the configured engine, while the SQL records effective quoting,
placeholders, operators, and dialect. The database alias itself is not stored.
Lockfile equality verifies rendered bytes, not database identity and not
equivalence across engines.

Rendering compiles the exported statements without executing them or reading
application or authorization rows. A selected backend or driver may still open
a connection for initialization, server-version discovery, or capability
queries. Audit the selected alias's connection settings, driver provenance,
server capabilities, and account authority.

Multi-engine CI may pin `TRUSTS_POLICY_DATABASE` to one dedicated inspection
alias while using different databases for runtime tests. Keep that pin
consistent in application settings and every job that renders or runs E009. A
validated shape uses MySQL as `default` and a separate SQLite `policy` alias;
E009 follows `policy`. This limits production exposure, but the resulting
artifact describes SQLite rather than production SQL.

### Generated bytes and dependency boundary

The writer uses the exact supported `PyYAML==6.0.3` release. Strings, parameter
flow sequences, SQL literal blocks, key order, line endings, and the trailing
newline are part of the emitted byte profile. The writer does not emit YAML
tags, anchors, or aliases. Runtime user and permission roles appear as `bind`; candidate
primary keys used to compile object checks are typed sentinel values recorded
as `const`, not application data. A repeated `const: 1` must therefore be
reviewed by SQL position rather than assumed to be an `EXISTS` probe. Private
loader and inverse helpers are test aids, not supported inputs or a reverse
policy API.

`trusts.E009` compares raw bytes and does not parse the committed document.
Hand formatting, reordering, a dependency-induced spelling change, or a changed
newline fails equality even if another YAML parser would construct similar
data.

### Check lifecycle and enforcement

The untagged Django system-check callback for `trusts.E009` is always
registered. Enforcement applies when the conventional lockfile exists or an
explicit `TRUSTS_POLICY_LOCKFILE` path is configured. The explicit path must be
absolute and is never resolved against `BASE_DIR` or the working directory.
Conventional absence returns no error before database-alias resolution or
rendering. A relative, missing, unreadable, or byte-different explicit file fails.

The system check is the only lockfile enforcement and is not a request-time
authorization gate. Silencing it with `SILENCED_SYSTEM_CHECKS`, or running a
tag-selected check set that omits untagged checks, removes that enforcement.
WSGI and ASGI startup do not prove that the check ran.

### What equality does not prove

Byte equality proves only that the finalized declarations and selected renderer
produce the reviewed artifact. It does not prove:

- compiler correctness;
- the correctness of omitted runtime compositions or short circuits;
- trustworthy database rows or grant workflows;
- the absence of application bypasses;
- the behavior of other Django authentication backends;
- that an inspection renderer matches production; or
- the safety of a change that updates both code and lockfile.

Django still grants when any configured authentication backend grants. An
active superuser remains globally authorized in `PermissionsMixin.has_perm()`
before backends run. A green lockfile check does not revoke those grants.

Review backend paths, content grouping, trust relationships, `or_group`,
operation SQL, named filters, parameter roles, IDs, and `database.engine` as
changes to the authorization surface. Lockfile equality is a change-control
mechanism, not a complete security proof.

## Reference implementations

Reference repositories validate bounded portions of the django-trusts contract:

- [django-trusts-zero](https://github.com/django-trusts/django-trusts-zero)
  preserves the concrete 0.x Trust model and migration identity.
- [django-trusts-zero-example](https://github.com/django-trusts/django-trusts-zero-example)
  is a runnable Zero application.
- [django-trusts-gh-permissions](https://github.com/django-trusts/django-trusts-gh-permissions)
  demonstrates direct and team-derived relationship grants, ceilings, and
  organization alignment.

Each reference repository provides an example for its listed schema and
operations. It should not be read as a security assessment of applications
adapted from it.

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

