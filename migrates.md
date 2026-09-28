# Migrating to django-trusts 1.0

django-trusts 1.0 is a step change from django-trusts 0.x. It is not API,
model, or schema compatible with the 0.x package. Version 1.0 is a
schema-neutral authorization library and does not provide a direct migration
path for applications using the historical Trust and Content implementation.

The compatibility layer for django-trusts 0.x is
[django-trusts-zero](https://github.com/django-trusts/django-trusts-zero).
Existing 0.x applications should install that package and follow its
[migration guide](https://github.com/django-trusts/django-trusts-zero/blob/dev/migrates.md).
That is the supported 0.x migration path.

Applications adopting schema-neutral django-trusts 1.0 as a new integration
should follow the
[usage guide](https://django-trusts.readthedocs.io/en/dev/).

## Policy lock snapshot seam (#147 C1)

Additive inspection API. Authorization entry points are unchanged: C1
does not call `ensure_policy_lockfile_verified` and does not alter
`has_perm`, permission enumeration, `.authorized()`, or
`authorization_required`.

| | Old | New |
| --- | --- | --- |
| Finalized policy snapshot | No manifest API | `trusts.policy_lock.build_policy_manifest` returns an immutable `PolicyManifest` projected from frozen relationship handles |
| Public conversion | No JSON-ready export | `manifest_to_json_data` returns a detached dict. It is not a mutable alias of live `RegisteredRelation`, `AlongWalk`, or `Expr` objects |
| Registration identity | No semantic fingerprint | `fingerprint_registration` is `sha256:` plus lowercase hex of the UTF-8 canonical payload. Readable labels are diagnostic and gain a fingerprint suffix only when they collide on one handle |
| Renderer profile | Not recorded | Each handle records Django's `DEFAULT_DB_ALIAS` through `django.db.connections` (`alias`, `engine`, `profile`, `profile_version`, `along`) with zero SQL. A caller-supplied alias is ignored |
| Unsupported family | Not applicable | A configured handle whose family is not `relationship` fails closed. Empty relationship handles are still emitted |

C2 (below) adds the quiet serializer, the strict reader, and `int_dec`. Generate/check commands, runtime gating, and audit-doc organization are not in the C1 change.

Migration-bot checklist:

- `trusts.policy_lock`
- `build_policy_manifest`
- `manifest_to_json_data`
- `fingerprint_registration`
- `PolicyManifest`
- `DEFAULT_DB_ALIAS`

## Policy lock canonical document (#147 C2)

Additive document boundary on the C1 snapshot. Authorization entry points
are unchanged: C2 does not add management commands, path selection, or
`ensure_policy_lockfile_verified`.

| | Old (through C1) | New |
| --- | --- | --- |
| Quiet lockfile bytes | No public serializer. An internal UTF-8 form feeds registration fingerprints only | `canonicalize(source)` returns UTF-8, no BOM, LF-only, two-space indent, schema key order, trailing newline. A `PolicyManifest` never emits `diagnostics`. Bytes, `str`, or a dict are strict-read first, so regeneration drops a `diagnostics` object. A non-object `diagnostics` value is rejected |
| Strict reader | None. Unknown document fields were not a read boundary | `read_canonical_policy` accepts UTF-8 bytes, text, or a JSON object. `schema_version` and `compiler_version` must be integer `1`. Unknown fields fail at every semantic level. Top-level `diagnostics`, when present, must be an object; it is the only nonsemantic key and is omitted from the result. Duplicate handle paths, registration fingerprints, and named-filter `(model, code)` keys are rejected, so an admitted document has one canonical byte form |
| Named-filter AND/OR | Binary `left` / `right` as stored | Commutative `and` / `or` flatten to a sorted `args` list. `eq` / `ne` stay ordered pairs |
| Integers | IEEE-safe `int` only. Out-of-range integers fail closed | IEEE-safe values use `{"type":"int","value": <JSON number>}` (`abs(n) <= 2**53 - 1`, bool excluded). Outside that range, `{"type":"int_dec","value":"<decimal text>"}` with an optional leading `-`, ASCII digits, no `+`, and no leading zeroes. Cross-shape encodings and noncanonical `int_dec` spellings fail. Floats, `ModelIdentity`, and other constants still fail |

Migration-bot checklist:

- `canonicalize`
- `read_canonical_policy`
- `int_dec`
- `diagnostics`
- named-filter `args`

## Policy lock generate and check (#147 C3)

Additive commands and path resolution. Authorization entry points are
unchanged: C3 does not define `ensure_policy_lockfile_verified` and does
not alter `has_perm`, permission enumeration, `.authorized()`, or
`authorization_required`. Core remains absent from `INSTALLED_APPS` and
still does not ship `trusts/management` (#129). The commands register
from `TrustsImplementationConfig.ready()`; a subclass that replaces
`ready()` must call `super()`.

| | Old (through C2) | New |
| --- | --- | --- |
| Generate / check | No command and no path API | `trusts_policy_generate` writes quiet canonical bytes. `trusts_policy_check` compares them. Both are zero SQL and do not authorize |
| Conventional path | None | `resolve_lockfile_path()` uses `settings.BASE_DIR / "trusts-policy.lock.json"` when `BASE_DIR` is absolute. The process working directory is not used and parent directories are not searched |
| Explicit path | None | `settings.TRUSTS_POLICY_LOCKFILE`, or `--lockfile` on either command, is an absolute override. `--lockfile` wins when both are set. A relative path fails closed. `None` means unset |
| Conventional absence | Not applicable | Check returns inactive and does not create the file. Generate creates it when the parent directory exists |
| Explicit absence | Not applicable | Generate creates the file. Check fails closed. A missing parent, a parent that is not a directory, and permission denied are different failures. Generate does not create missing parents |
| Present file | Not applicable | Generate replaces it, including a malformed file, and drops `diagnostics`. Check fail-closes on malformed, unknown `schema_version` / `compiler_version`, unknown fields, a directory path, or semantic drift |
| Comparison | None | Pass/fail is canonical semantic bytes (whitespace and top-level `diagnostics` are not drift). `format_policy_diff` reports fingerprint-first registration add/remove/change, then condition, path, model, target, and Along strategy lines. A label match is a likely change only when exactly one unmatched row remains on each side. Named filters match on `(model, code)`. Handle, compiler, renderer, and version lines are included. Verbosity 2 also prints a unified canonical JSON diff. The human diff does not decide pass/fail |
| Runtime gate | None | Still none |

Migration-bot checklist:

- `trusts_policy_generate`
- `trusts_policy_check`
- `TRUSTS_POLICY_LOCKFILE`
- `--lockfile`
- `trusts-policy.lock.json`
- `resolve_lockfile_path`
- `generate_policy_lockfile`
- `check_policy_lockfile`
- `format_policy_diff`
- `PolicyLockDrift`
- `PolicyLockLocation`
- `PolicyLockCheck`
- `CONVENTIONAL_LOCKFILE_NAME`
- `TrustsImplementationConfig.ready`

## Unused `get_short_model_name` helper (#217)

| | Old | New |
| --- | --- | --- |
| `trusts.utils.get_short_model_name` | Existed on the historical/pre-1.0 surface | schema-neutral django-trusts does not provide it |

0.x applications must follow [django-trusts-zero's migration guide](https://github.com/django-trusts/django-trusts-zero/blob/dev/migrates.md); django-trusts offers no replacement recipe. Detailed Old-behavior, replacement, and casing guidance are on [django-trusts-zero#39](https://github.com/django-trusts/django-trusts-zero/pull/39).

Migration-bot checklist:

- detect `get_short_model_name` imports/calls and send them to the Zero checklist

## Relationship condition language (#210)

| | Old | New |
| --- | --- | --- |
| Public condition | `All(permission_in("team__allowed_operations"), Equal("team__organization", "repository__organization"))` | `lambda t: t.team.allowed_operations.contains(t.operation) & (t.team.organization == t.repository.organization)` |
| Membership | `permission_in("team__allowed_operations")` | collection-rooted `.contains(member)` whose member is this registration's `permission=` path |
| Equality | `Equal("team__organization", "repository__organization")` | `t.team.organization == t.repository.organization` |
| Conjunction | `All(...)` | `p & q` (parenthesize `==`; `&` binds tighter) |
| `predicate=` | n/a | reserved; unsupported in 1.0 (`TypeError` unexpected keyword) |

```python
# Old public handle (prebuilt nodes)
backend.register(
    trust=TeamDocumentPermission,
    user="team__members",
    permission="permission",
    content="document",
    condition=All(
        permission_in("team__allowed_operations"),
        Equal("team__organization", "document__organization"),
    ),
)

# New public handle (one symbolic callable)
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

The predicate runs once after the freeze check, in the same `AppConfig.ready()`
world as path lambdas. The stored overlay is private `Equal` /
`PermissionIn` / `All` and contains no callable. Literal Python `in` is
unsupported and is not recovered through AST, bytecode, `dis`, or a
`__contains__` side channel. Public `register(condition=...)` rejects
prebuilt `All` / `Equal` / `permission_in` values (`TypeError`). Internal
`TrustsRegistry.register` may still accept those private records.

`.contains` is a reserved method on the condition proxy. A model field
actually named `contains` cannot be walked in `condition=`. Path lambdas
(`user=` / `permission=` / `content=`) do not grow `.contains`.

Consumer Zero group-ceiling registrations and the GH conjunction stay on the
post-#208 / #210 consumer train. Do not migrate them in the django-trusts
slice.

Migration-bot checklist:

- `condition=All(`
- `condition=Equal(`
- `condition=permission_in(`
- `permission_in(`
- `Equal(`
- `.contains(`
- ` in `
- `predicate=`
- `condition=lambda`
- `Python 'in' is unsupported`
- reserved field name `contains` on a condition proxy walk

## Application-owned AuthorizedManagerMixin (#209)

| | Old | New |
| --- | --- | --- |
| Authorized manager | Use the concrete `AuthorizedManager`, or duplicate `.authorized()` in an application manager | Optionally mix `AuthorizedManagerMixin` into the application-owned manager while retaining its behavior |

No mandatory consumer change. `AuthorizedManager` remains supported.

Migration-bot checklist:

- `AuthorizedManager(`
- custom manager definitions
- application-owned `authorized(` methods

## Archaeology

The pre-1.0 development migration record is preserved for historical reference
at the
[archive tag](https://github.com/django-trusts/django-trusts/blob/migration-archive-pre-1.0/migrates.md)
and an
[immutable commit](https://github.com/django-trusts/django-trusts/blob/7414886263faafb6edfb44c0c5fcf9fc8fa14e79/migrates.md).
Those records describe unpublished development transitions; they are not an alternative 0.x migration path.
