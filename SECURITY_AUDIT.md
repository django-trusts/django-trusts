# Security audit guide

This guide owns the policy and security contract beyond the
[getting-started example](docs/source/index.rst). It is an audit map, not a
security assessment of an application or its data.

## Application and dependency boundary

The application owns authentication, model constraints, tenant isolation,
authorized grant writes, migrations, and deployment. Trusts evaluates the
persisted facts it receives; it cannot establish whether an endpoint, import,
signal, administrator, or raw SQL statement was entitled to create them.

The authentication method, whether a session or token, does not select a
broader permission path.

The runtime dependencies are Django and PyYAML. Django loads the configured
database driver; the deployment owns its provenance, credentials, connection
settings, and availability. Build tools are outside the permission boundary.

Trusts supplies no concrete permission schema or Django `AppConfig`: do not
put `trusts` in `INSTALLED_APPS`. The application owns each configured backend
path and its `TrustsImplementationConfig`. Audit every installed backend;
examples listed in the usage guide are not substitutes for an application audit.

## Registration boundary

Use the handle returned by `configured_backend()` rather than constructing
private registry or compiler objects. Multiple backend paths require an exact
path; registries are isolated by path and freeze after application startup.
Rejected declarations must not partially mutate a registry. Trusts validation
uses model metadata without issuing SQL.

Path lambdas and condition/filter builders execute once at registration.
Trusts stores validated expression data, not those callables. It does not
inspect or sandbox other Python inside a builder: its I/O, queries, mutable
captures, and side effects remain application behavior. Arbitrary runtime
callbacks are unsupported; `TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS=True`
reports `trusts.E007` rather than restoring them.

### Relationship paths

The public signature is
`register(*, trust, user=None, permission=None, content, group=None, delegate=None, sponsor=None, condition=None, along=None)`.
Paths accept a one-argument path lambda or a Django `__` string. The required
`trust=` is their common root. Paths must be non-empty and resolve through
Django metadata to one comparison field at each step, including `to_field`.
Generic, composite, and unbounded multi-valued correlations are rejected.

| Argument | Accepted relationship shape |
| --- | --- |
| `user=` | One forward single-valued step, or forward single-valued steps ending in one many-to-many membership |
| `permission=` | One forward single-valued step to a permission model, or forward single-valued steps ending in one forward many-to-many to `auth.Permission` |
| `group=` | A forward path to `auth.Group`; Trusts appends its permissions |
| `content=` | One direct forward single-valued step, or single-valued prefix steps, one reverse one-to-many gateway, and at most two supported suffix steps |

A content prefix may include reverse one-to-one relations. Its suffix steps
may be forward single-valued, reverse one-to-one, or reverse one-to-many.
A reverse one-to-one is not itself a content terminal or gateway. An
intermediate or reverse many-to-many permission collection is unsupported;
the terminal collection must compare permission primary keys.

An ordinary registration supplies `user=` and exactly one of `permission=`
or `group=`. Only explicit `group=` registrations contribute to group
permission enumeration, even if another user path traverses a Django group.
Distinct matching registrations are OR alternatives. An exact duplicate or
conflicting binding raises; a different condition on the same binding is an
alternative, not an in-place replacement.

### Relationship conditions

An ordinary `condition=` lambda takes the relationship row as a symbolic
value. Supported operations are path equality (`==`), collection-rooted
membership (`.contains(member)`), and conjunction (`&`). Parenthesize equality
inside a conjunction:

```python
backend.register(
    trust=TeamDocumentPermission,
    user=lambda t: t.team.members,
    permission=lambda t: t.permission,
    content=lambda t: t.document,
    condition=lambda t: (
        t.team.allowed_operations.contains(t.permission)
        & (t.team.organization == t.document.organization)
    ),
)
```

The collection member must be this registration's permission identity.
Equality must compare compatible resolved model/field identities, not merely
values that happen to collide. A condition narrows its own grant branch.
Python `in`, `and`/`or`/`not`, foreign roots, unsupported arity or operations,
and prebuilt `All`/`Equal`/`permission_in` records are rejected by the public
handle. `contains` is reserved on the condition proxy, and `predicate=` is
not a registration keyword.

### Delegated authority

A **delegate** acts with a **sponsor**'s live ordinary authority on protected
content. Use `delegate=` and `sponsor=` instead of `user=` and
`permission=`/`group=`. For a relationship with a `permissions` collection:

```python
backend.register(
    trust=DocumentDelegation,
    delegate=lambda d: d.delegate,
    sponsor=lambda d: d.sponsor,
    content=lambda d: d.document,
    condition=lambda d, p: d.permissions.contains(p),
)
```

Here `DocumentDelegation` is an application model with `delegate` and
`sponsor` foreign keys to the user model, a `document` foreign key, and a
`permissions` many-to-many to `auth.Permission`. The second lambda argument
is the requested permission; a one-argument lambda may restrict only the row.

All of the relationship's delegate, sponsor, content, selected operations,
and condition must belong to the same matching row. Its sponsor authority is
the live union of applicable ordinary grants across configured Trusts handles.
An override applies only to the checked user and never supplies sponsor
authority. A delegation cannot sponsor another delegation.

The delegation and each contributing sponsor grant must reach the same object,
including their applicable `along=` walks. Conditions stay on the terminal
grant, not on intermediate walk nodes. Never substitute a nested Python
`sponsor.has_perm()` call: it imports a different Django boundary and breaks
the shared SQL proof. Authorized write paths still govern approval, tenant
alignment, revocation, and any other application-owned scope data.

### Named filters restrict the query

Register an additional restriction on the protected model:

```python
backend.add_named_filter(
    Document,
    "not_internal",
    predicate=lambda u, p, o: o.title != "Internal",
)
```

The symbolic arguments are the requesting user, requested permission, and
protected object. A selected filter is ANDed with the permission result; it
cannot create a grant. Unknown, unbound, or untranslatable filters must not
become unfiltered grants. Enumeration returns bare permission codes, not all
possible code/filter combinations. Filter selection syntax belongs in the
[inquiry reference](docs/dev/permission-inquiries.md#permission-inputs).

## User-rule validation and composition

The [usage guide](docs/source/index.rst#user-conditions-and-overrides) owns
the default condition, setter lifecycle, and ordinary skip example.
Explicit user rules require concrete `BooleanField` attributes; Python
properties such as `is_authenticated`, text fields, and missing fields raise
without changing the registry. The symbolic grammar is fields, `&`, and `~`.
Names must not conflict with inquiry parameters or between conditions and
the override. Skip keywords are Boolean `skip_<identifier>` values naming a
current rule; replacing an override invalidates its old skip name.

Conditions accept `on="*"` (default), `"user"`, or `"sponsor"`; the override
accepts only `"user"`. A skip removes its condition for every target it names.
Separate controls therefore require separately named conditions. Tuple
targets, unknown names, invalid values, and changes after permission or
delegation registration raise.

After input/configuration validation, the authorization shape is:

```text
checked-user conditions
AND (
    enabled checked-user override
    OR ordinary grant
    OR (matching delegation AND sponsor conditions AND ordinary sponsor grant)
)
```

Each required condition is `(skip_<name> OR condition)` and the enabled
override is `(NOT skip_<name> AND override)`. Input errors still raise for a
user whose override would succeed. Neither an override nor a skip bypasses
content identity, required candidate existence, or named filters. Some of
those checks occur inside SQL. Group enumeration uses conditions and group
grants without the override or delegated grants.

Anonymous, unauthenticated, and `None` users receive no positive result.
Skip-key shape and type are checked first; rule-name lookup does not run for
that denial. Permission SQL uses persisted user identities, not arbitrary
Python objects or instance-only properties. Mapping anonymous identities and
instance evaluation are not supplied by this contract.

### Django auth's checks before calling backends

Django's `PermissionsMixin.has_perm()` returns early for an active superuser.
Trusts-owned inquiries, including `authorization_required()`, do not add an
implicit superuser grant. To opt into one, give it its own activity requirement:

```python
registry.set_user_override(
    "superuser", lambda u: u.is_active & u.is_superuser,
)
```

`skip_is_active` does not skip the activity check inside that expression.
Use `skip_superuser=True` to inspect ordinary grants while that override is
registered. An application may additionally prevent superusers from sponsoring:

```python
registry.set_user_condition(
    "superuser_cannot_sponsor", lambda u: ~u.is_superuser, on="sponsor",
)
```

That condition is opt-in; `skip_superuser` skips the override, not this condition.

Django's stock user permission methods do not forward Trusts skip keywords.
A custom user model can override `has_perm()` and `has_module_perms()` to ask
backends without Django's early return; this also changes Django admin behavior.
Other backends may independently grant permission. A rejecting Trusts branch
cannot revoke those grants; audit the whole configured backend set.

## Permission identity and failure behavior

An `auth.Permission` grants only on its own content type, including a proxy
model's own identity. This is enforced for both direct and group paths.
Other permission-terminal models retain primary-key identity even if they
have a field named `content_type`. Accepted permission inputs with a mismatched content identity contribute no
grant; inquiry input validation may still raise. Public string codecs differ by
inquiry; see the [input table](docs/dev/permission-inquiries.md#permission-inputs).

Unsupported registrations, expression shapes, query renderers, and frozen
mutation must fail closed. Invalid input may raise instead of returning an
empty result. A defect must not be hidden by dropping a branch, broadening a
grant, suppressing an error, or falling back to Python per-object checks.
The [inquiry reference](docs/dev/permission-inquiries.md) owns return shapes,
query budgets, routing, and the guard's 404/403 behavior.

## Bounded inherited relationships

`along=("parent", 8)` adds provisional bounded reachability at one registered
walk site. The bound is an integer in `1..64`, excluding booleans. The edge is
one forward self-relation (`S`), one reverse self one-to-many (`C`), or one
reverse edge relation followed by a forward return to the walk model (`E`). Grant and edge ends
must use the same resolved identity. Supported identity families are integer,
text, and UUID; mixed families and composite identities are rejected. Exact
field-type classification is in the [compiler record](docs/dev/core-registry.md#identity-field-classification).

The seed is depth zero; nodes at the bound are included but not expanded.
NULL or dangling steps add no reachability. The recursive statement uses
`UNION ALL` and a depth cap. Cycles and diamonds can multiply intermediate
rows even though final results are distinct; choose the bound with the data's
fan-out in mind. PostgreSQL additionally uses `CYCLE` to prune a repeated
identity on one path. The supported renderers are SQLite, PostgreSQL, and
MySQL 8.4+; MariaDB and other engines raise before walk SQL.

To get users from content, the compiler starts at the content's walk-site
identities and walks the opposite direction without the outer user, then joins
grants and users outside the CTE. The returned users must agree with each
candidate's backend object check under the same inputs. An unrenderable walk
raises before evaluation or partial policy output.

`filter_by_permitted_content` has an additional limit: delegated walks and
ordinary sponsor walks may have at most one reverse suffix hop. Audit terminal
conditions, resolved `to_field` identities, duplicate elimination, and the
relation between both sides' reach. Renderer diagnostics use `trusts.E005`
only for the aliases Django supplies; an absent/empty `databases` argument
does not probe every database or establish an all-clear. Silencing the check
does not change runtime enforcement.

## Authorization policy SQL and lockfile

Inspect the executed permission statements and commit their rendered bytes:

```console
python manage.py trusts_policy_sql
python manage.py trusts_policy_sql --lock
python manage.py check
```

`TRUSTS_POLICY_DATABASE` selects the renderer alias, defaulting to `default`;
`--database` overrides it for one invocation. Output is deterministic YAML,
organized by backend/content, with declared relationships, inquiry SQL, and
ordered parameters. The [format record](docs/dev/policy-sql-format.rst) owns
the wire schema, identifiers, token grammar, and serialization examples.

`TRUSTS_SQL_BIND_ONCE` defaults to true and reuses bind parameters in the
executed SQL. Setting it false uses the plain queryset. If rewriting cannot
handle a query structure, Trusts logs a warning and keeps that queryset
unchanged. Policy output always records the statement actually selected;
there is no lockfile-only rewrite or separate skipped-rule statement.

`TRUSTS_POLICY_LOCKFILE` selects an explicit absolute path. Otherwise the
conventional path is `BASE_DIR / "trusts-policy.lock.yaml"` when `BASE_DIR` is
absolute. Relative explicit paths are errors, not paths relative to `BASE_DIR`.

### Renderer and connection boundary

A lockfile describes one renderer, recorded as `database.engine`, not a
database identity. Dialects differ. Multi-engine CI may use one inspection
alias while testing other runtime databases; pin that alias consistently in
every render and check job. An artifact rendered with SQLite does not certify
production MySQL SQL.

Rendering does not execute permission queries or read grant rows. A backend
or driver may still connect for initialization, version discovery, or capability
checks. Audit that connection's authority as well as its SQL dialect.

### Check lifecycle and enforcement

`trusts.E009` compares raw bytes when the conventional file exists or an
explicit path is configured. A missing, unreadable, or different explicit file
fails. With neither configuration nor a conventional file, it returns without
resolving the renderer. Whitespace, ordering, newline, or dependency-induced
serialization changes can fail equality despite equivalent parsed YAML.

System checks are the enforcement mechanism, not a request-time permission
gate. Run them in CI and before deployment; WSGI/ASGI startup alone does not
establish that they ran. Regenerate and review intentional output changes with
the declaration or dependency change that caused them.

### What equality does not prove

Matching bytes establish only that declarations and the selected renderer
produce the reviewed artifact. They do not prove compiler correctness,
authorized database writes, application workflows, other backend behavior,
production-renderer equivalence, or the safety of changing both code and lock.

Review backend paths, content groups, relationship identities, conditions,
walks, named filters, SQL Boolean grouping, parameter roles/values, and engine
changes. Then compare object checks, permitted objects, enumeration, users
from content, and guards using equivalent inputs. Request data may fill only
validated parameter values, never select SQL structure or authorization paths.

Discrepancies between code and this guide must be surfaced in review rather
than resolved implicitly. Developer verification commands and release
procedures live in [the development record](docs/dev/development.md).
