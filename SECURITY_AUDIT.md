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

django-trusts's direct runtime dependency is Django. The supported Python, Django, and
database combinations are recorded in
[the support matrix](docs/support-matrix.md). Build and test dependencies are
not part of the runtime authorization boundary.

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

## Authorization policy lockfile

An application can commit the canonical normalized authorization surface as
`trusts-policy.lock.json` and require later checks to match that artifact.
Equality proves only that the live declared and normalized authorization
surface matches the reviewed artifact.

That match is a review aid for the declared surface. It is not a security
proof of the compiler, the database, the application, or the pull request
that produced the file.

`trusts_policy_generate` writes the artifact. `trusts_policy_check` compares
it. Both are deterministic and issue no SQL. Generation creates or replaces
the file when the parent directory can accept it, and it fails closed when
that parent is missing, not a directory, or not writable. It does not treat
a missing file as inactive, it does not verify, and it does not authorize.
Django system checks do not verify either. Check and runtime verification
use the same canonical comparison. Pass or fail is semantic bytes: UTF-8,
LF, with incidental whitespace and newline style normalized away. The human
diff explains a mismatch. It does not decide the mismatch. The compared
document does not carry package version, source location, process identity,
or wrapper object identity. Those are not authorization semantics. The only
nonsemantic key the reader drops is a top-level `diagnostics` object.
Every other unknown field fails closed.

### What equality does not prove

A matching lockfile does not prove:

- compiler correctness;
- trustworthy database rows or grant workflows;
- the absence of application bypasses;
- the behavior of other Django auth backends; or
- the safety of a PR that changes both code and lockfile.

Django still grants when any configured authentication backend grants. An
active superuser remains globally authorized in `PermissionsMixin.has_perm()`
before backends run. A green lockfile check does not revoke those grants and
does not make a combined code-and-lockfile change acceptable by itself.
Review the new surface with the diff below. Review the application, its
rows, and its other backends as the rest of this guide requires.

### How to read a semantic diff

`trusts_policy_check` prints the human authorization diff. Verbosity 2 also
prints the raw canonical JSON diff. Read the human diff by meaning:

| Signal | Review it as |
| --- | --- |
| Registration added or removed | A declared grant path entered or left the surface |
| Label stable, fingerprint moved | The readable name stayed. The authorization semantics did not |
| Label changed, fingerprint unchanged | A rename. The normalized registration did not move |
| Condition added, removed, or changed | The closed predicate on that registration changed |
| Path user, permission, or content | The relationship walk changed |
| Model root, user, permission, or content | A terminal model identity changed |
| Target user, permission, or content | A comparison or `to_field` identity changed |
| Strategy kind | The registration strategy kind changed |
| Strategy `along` added, removed, or a field moved | Direction, bound, walk, or edge identity changed |
| Named filter added, removed, or changed | A restricting overlay changed. A named filter does not grant by itself |
| Handle added or removed | An implementation backend entered or left the configured surface |
| Family or compiler | Ownership changed: the authorization family or the compiler identity |
| Renderer alias, engine, profile, profile version, or Along support | The declared database renderer profile changed |
| `schema_version` | The manifest schema moved |
| `compiler_version` | Normalized-policy interpretation moved |

Registrations match by fingerprint first. A single unmatched recorded row
and a single unmatched live row that share a label are reported as one
likely change (label stable, fingerprint moved). When several leftovers
share a label, they are added and removed, not paired. Named filters match
by model and code. Handle path, family, compiler, renderer, and the two
version fields are first-class.

The fingerprint is the semantic identity of one registration: kind, paths,
models, comparison targets, condition, and Along. The label is only a
reviewer-readable name. Registration order and commutative condition order
that normalize to the same semantics are not drift. A behavior-affecting
change must move the fingerprint and appear in this diff.

Core lockfile v1 serializes the relationship family only. A configured
handle in any other family, including ordered fold, fails the whole
snapshot closed. The failure names that backend path and its family. It
does not omit the handle and continue, and it does not open a second
lockfile for that family. Schema or compiler-version movement is an
interpretation change,
not a routine package bump. There is no in-place migration of an older
document: an unknown version fails closed.

A pull request that changes both code and the lockfile still needs this
review. A passing check means the file matches the code that produced it.
It does not mean the new surface is the one reviewers intended.

### Presence, checking, and process-local state

There is no off, check, or enforce mode, and no second setting that can
disable a lockfile once it is in force.

The conventional path is `settings.BASE_DIR / "trusts-policy.lock.json"`
when `BASE_DIR` is an absolute path. An explicit absolute path may be set
with `TRUSTS_POLICY_LOCKFILE` or with `--lockfile` on either command.
`--lockfile` wins when both are set. `None` means the setting is unset.
Relative paths fail closed. The process working directory is never used,
and parent directories are never searched for a lockfile.

Supplying an explicit path is enforcement intent. Absence is inactive only
for the conventional location.

| Situation | `trusts_policy_check` | Runtime authorization |
| --- | --- | --- |
| Conventional file absent, including a missing conventional parent | Inactive. No manifest is built | Sticky `INACTIVE` until this process restarts. A file created later in the same process is ignored. Results keep their previous behavior |
| No explicit path and no usable absolute `BASE_DIR` | Fail closed. The working directory is not a fallback | Sticky `INACTIVE` until restart |
| Explicit path missing, unreadable, or not a file | Fail closed | Sticky `FAILED` |
| File present but malformed, incompatible, or different | Fail closed | Sticky `FAILED`. Later calls in this process re-raise that failure and do not re-read the file |
| Canonical bytes match | Match | Sticky `VERIFIED` |

Runtime verification is one process-local state machine. It starts
`UNCHECKED`. It runs only after Django apps are ready, freezes the
configured registries, and then compares. It runs before every Trusts
authorization result, including early denials and empty results. A fresh
process starts `UNCHECKED` and reads the current file itself. It does not
inherit another process's `VERIFIED`, `INACTIVE`, or `FAILED` memory.
Leaving a sticky state requires a process restart.

When the state is `VERIFIED`, every handle that participates in a result
must belong to that snapshot: configured path, the same owner and family,
the same frozen registry, compiler identity, and the declared renderer
profile. A newly constructed wrapper is acceptable when those components
match. Wrapper identity is not written into the portable file. After a
successful verification, late registration and late named-filter
registration still fail before they can change the frozen registry or the
verified snapshot.

The recorded renderer is the conservative declared profile of Django's
already-configured default database alias. Verification does not open a
connection, probe server version, or accept a Trusts-specific dialect or
backend path.

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
   declared and normalized authorization surface matches the reviewed
   artifact, and has every semantic addition, removal, fingerprint,
   condition, path, model, strategy, renderer, ownership, schema, or
   compiler-version change been reviewed on its own?
8. If the implementation disagrees with this guide, is the code wrong, is the
   guide wrong, or has an explicit design decision changed the boundary?

Discrepancies must be surfaced in the PR rather than resolved implicitly.

