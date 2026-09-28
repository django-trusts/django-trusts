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

Later lockfile slices (generate/check commands, runtime gating, audit-doc organization) are not in the C1 change. C2, below, adds the quiet serializer, strict reader, and `int_dec` boundary.

## Policy lock canonical document (#147 C2)

Quiet lockfile bytes and a strict reader on the C1 snapshot. Authorization
entry points are unchanged: C2 does not add management commands, path or
presence behavior, or runtime gating.

| | Old (C1 snapshot) | New |
| --- | --- | --- |
| Quiet bytes | No document serializer. Fingerprint payloads already used UTF-8, LF, two-space indent, and a trailing newline | `canonicalize(manifest)` returns that quiet form for the whole document: UTF-8, no BOM, LF only, schema key order, one trailing newline, and no `diagnostics` |
| Reader | No reader | `read_policy_document` accepts UTF-8 JSON text or bytes. It rejects unknown fields at every semantic level, unknown schema or compiler versions, and fingerprints that do not match their canonical payloads |
| Regeneration | Not available | `encode_policy_document(read_policy_document(payload))` rewrites quiet bytes. A top-level `diagnostics` object is dropped on read and rejected by the encoder |
| Semantic comparison | Not available | Equality of `read_policy_document` results. `diagnostics` is omitted before that comparison |
| Named-filter AND/OR | Binary `left` / `right` trees | Flattened commutative `operands` lists, sorted by canonical subtree text. `A & B` and `B & A` encode the same document; the same rule applies to `\|` |
| Integers | IEEE-safe JSON `int` only. A larger integer failed export | IEEE-safe values stay `{"type":"int","value": <JSON number>}`. Larger integers are `{"type":"int_dec","value":"<decimal text>"}`: optional leading `-`, digits only, no `+`, no leading zeroes. The other shape, and any noncanonical spelling, fails |
| Other constants | `null`, bool, and str were portable. Float, `ModelIdentity`, and every other constant type failed | Unchanged allowlist. Those rejected types still fail closed |
| Versions | `schema_version` and `compiler_version` were recorded as `1` | Still `1`. The reader accepts only those integers |

`schema_version` stays 1 because no quiet lockfile had been emitted yet. The C1 binary AND/OR spelling was the unfinished snapshot, not a second document schema.

Migration-bot checklist:

- `canonicalize`
- `read_policy_document`
- `encode_policy_document`
- `int_dec`
- `diagnostics`
- `operands`

Migration-bot checklist:

- `trusts.policy_lock`
- `build_policy_manifest`
- `manifest_to_json_data`
- `fingerprint_registration`
- `PolicyManifest`
- `DEFAULT_DB_ALIAS`

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
