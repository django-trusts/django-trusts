# Security audit guide

This guide describes the security boundary that implementation and
documentation changes are expected to preserve. It is an audit map, not a
substitute for reviewing the application, its data, or its deployment.

## Security claim

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

Core's direct runtime dependency is Django. The supported Python, Django, and
database combinations are recorded in
[the support matrix](docs/support-matrix.md). Build and test dependencies are
not part of the runtime authorization boundary.

Django selects and loads the database backend and driver configured by the
application; Core does not import, select, or manage database drivers. The
application and deployment therefore own driver provenance and versioning,
secure connection settings, and operational availability.

Core supplies no Django application or concrete permission schema. Do not add
`"trusts"` to `INSTALLED_APPS`. Install the application or package that owns
the concrete Trusts implementation instead.

A small dependency surface reduces supply-chain exposure, but dependency count
is not a security proof. Review exact dependency constraints and artifacts as
part of each release.

## Models and persisted facts

The application owns all protected models and permission-bearing rows. It must
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

The pre-1.0 public surface has two grant-producing families and one restricting
overlay:

| API | Meaning | Can grant independently? |
| --- | --- | --- |
| `register_relationship(...)` | Register paths from a permission-bearing model to user, permission, and protected content | Yes |
| `register_ordered_fold(...)` *(provisional)* | Register an ordered allow/deny evaluator for one protected model | Yes |
| `add_named_filter(...)` | Bind a model-scoped name to a registration-time predicate | No |

Registration must issue no SQL. Unsupported paths, types, constants, and
combinations fail during setup. Registration closes when the configured
registry freezes; late mutation is rejected.

### Relationship authorization

A relationship registration names three non-empty Django `__` paths from one
permission-bearing root:

```python
backend.register_relationship(
    DocumentPermission,
    user="user",
    permission="permission",
    content="document",
)
```

A complete matching path is positive authorization evidence. Multiple complete
relationship registrations for the same protected model are alternatives and
combine with OR in one generated query. A condition attached to a relationship
narrows only that branch and cannot create a grant.

A terminal many-to-many user membership is supported where validated. Review
the resolved comparison identity, duplicate-row behavior, and whether
`distinct()` is present on projections that need it. A long path must be
compiled from every segment; no implementation may validate the complete path
and then query only its first hop.

The `user`, `permission`, and `content` relationship path arguments may not be empty. Empty paths appear only in
specifically documented OrderedFold/token positions where the model instance
itself is the identity.

### Ordered allow and deny

The complete supported OrderedFold construction surface is
`register_ordered_fold()`, `OrderedFold`, `PermissionMaskDomain`, `MaskEntry`,
`PolarityMap`, and `FlatToken`. This surface is provisional and excluded from
the normal 1.x compatibility guarantee. Its signatures or location may change,
or it may be removed, in a future feature release. Other OrderedFold compiler,
validation, expression, and renderer names are implementation details.

`register_ordered_fold(source_model, OrderedFold(...))` selects the
OrderedFold evaluator. It has its own declaration, validation, stored plan,
and PostgreSQL remaining-bits renderer.

The declaration identifies:

- the protected content model;
- the content-relative descriptor path;
- the source-relative descriptor path;
- deterministic ACE ordering;
- allow and deny values;
- the requested-permission mask domain;
- trustee identity; and
- direct or flat-group requester tokens.

The content and source descriptor paths must converge on one validated
comparison identity. Malformed, unknown, null, negative, or out-of-domain state
must fail closed according to the documented evaluator contract.

At the current 1.0 boundary, object-level ``user.has_perm`` uses Django's
ordered authentication-backend OR. A relationship grant or an OrderedFold
grant on another configured backend can authorize that single object.
An OrderedFold deny cannot veto an independent relationship grant or
revoke a grant returned by another configured Django authentication
backend.

Core list, guard, and common-permission helpers are relationship-family
local. ``Model.objects.authorized``, ``authorization_required``,
``filter_authorized_scopes``, and module-level ``granted`` /
``common_permissions`` include only handles whose implementation
``_authorization_family`` is ``"relationship"``. They do not compile a
mixed-family one-SQL OR. Django's object-level backend OR is a different
layer and must not be read as Core list/guard aggregation.

Until the OrderedFold engine leaves Core, one exact relationship backend
path may still hold both families on one plan. That same-path family-local
OR is a provisional deferral, not the 1.0 QuerySet or view-guard contract.

### Named filters are outer restrictions

A named filter is registered against the protected model:

```python
backend.add_named_filter(
    Document,
    "non_confidential",
    predicate=lambda u, p, o: o.confidential != True,
)
```

The callable is a trusted registration-time builder. The backend invokes it
once with symbolic principal, permission, and object references. Operations on
those references construct a closed expression tree; Core validates and
normalizes that result, stores only the immutable IR, and discards the
callable. Core does not inspect or parse the callable's Python source. Do not query,
perform I/O, capture request state, or rely on mutable captured values inside
the predicate.

At an authorization site, the named filter restricts an existing grant:

```text
SelectedAuthorizationEngine(object, user, permission)
AND
NamedFilter(object, user, permission)
```

For OrderedFold, the filter compiles against the outer protected-object query.
It is not injected into the recursive CTE and does not:

- select or reject individual ACE rows;
- alter traversal bounds, direction, or cycle handling;
- change ordering, polarity, mask consumption, or trustee tokens; or
- act as a recursive stopping rule.

A rule that changes ACE eligibility or recursive evaluation belongs in the
closed OrderedFold grammar. It must not be hidden in an object filter.

Unknown, unbound, or untranslatable named filters fail closed. A filter cannot
create a grant. Permission enumeration returns bare permissions rather than every possible
combination of permission and filter names.

### Runtime callbacks are unsupported

Arbitrary runtime permission callbacks are not part of the public surface. They
cannot provide object/queryset parity, startup validation, deterministic
inspection, or fixed-query proof.

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

Core is schema-neutral and has no final `AppConfig`. Concrete implementations
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

The Core view guard deliberately accepts only `view_kwargs["pk"]`, coerces it
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

The current Along renderer is verified only for the database combinations
listed in the support matrix.

### OrderedFold PostgreSQL renderer

This provisional evaluator is currently rendered for PostgreSQL. Its SQL contains a recursive
ordered remaining-bits evaluation that Django treats as a custom expression.
PostgreSQL execution tests—not string inspection alone—are required for nested
`OuterRef`, alias scoping, aggregation, enumeration, and composition changes.

## Fail-closed expectations

The following must not silently become grants:

- missing or unknown registrations;
- malformed paths or unsupported relationship shapes;
- conflicting registrations;
- wrong user, permission, or protected models;
- incompatible `to_field` identities;
- unknown named filters;
- unsupported predicate expressions;
- frozen-registry mutation;
- malformed OrderedFold rows or permission domains;
- unsupported database renderers; and
- invalid request primary-key coercion.

Configuration failures should be reported during startup or system checks where
possible. Runtime denial must not fall back to a broader Trusts path.

## Reference implementations

Reference repositories validate bounded portions of the Core contract:

- [django-trusts-zero](https://github.com/django-trusts/django-trusts-zero)
  preserves the concrete 0.x Trust model and migration identity.
- [django-trusts-zero-example](https://github.com/django-trusts/django-trusts-zero-example)
  is a runnable Zero application.
- [django-trusts-gh-permissions](https://github.com/django-trusts/django-trusts-gh-permissions)
  demonstrates direct and team-derived relationship grants, ceilings, and
  organization alignment.
- [django-trusts-windows-acl](https://github.com/django-trusts/django-trusts-windows-acl)
  demonstrates ordered allow/deny masks and bounded inheritance.

A passing reference implementation proves only its declared schema and tested
operations. It is not a universal security proof for applications that adapt
the example.

## Validation and review discipline

Run the complete supported test matrix, warning-fatal documentation build,
package/fresh-install checks, Django system checks, and exact companion tests
required by the changed surface. API changes require a same-PR
`migrates.md` entry and migration-bot checklist.

For every material implementation or documentation change, reviewers should
answer:

1. Which statement in this guide does the change implement or preserve?
2. Does the change expand the grant-producing surface?
3. Do object, queryset, enumeration, and guard projections still agree?
4. Does registration remain zero-SQL and fail before partial mutation?
5. Is the final authorization query still within its tested statement bound?
6. Did any unsupported database, callback, private registry, or private IR
   surface become reachable?
7. If the implementation disagrees with this guide, is the code wrong, is the
   guide wrong, or has an explicit design decision changed the boundary?

Discrepancies must be surfaced in the PR rather than resolved implicitly.

A future policy manifest/lockfile may make normalized declarations and generated
SQL independently reviewable. That work is tracked separately and is not part
of the 1.0 public contract.
