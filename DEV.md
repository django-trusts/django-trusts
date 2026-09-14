# DEV.md — contributor / development history

This file is an internal development record. It may describe
unsupported or superseded states. The user-facing package introduction
is [README.md](README.md). `pyproject.toml` long-description metadata
points at `README.md`, not this file.

## Current architecture

Historical django-trusts 0.x was the concrete Trust / Content / group
implementation. Current django-trusts is the schema-neutral django-trusts
library. [django-trusts-zero](https://github.com/django-trusts/django-trusts-zero)
is the continuation and bridge for that historical concrete behavior.
Package-version identity for this tree is recorded in
[docs/development-version.md](docs/development-version.md), not here.

django-trusts is a Python dependency only: do **not** list `'trusts'` in
`INSTALLED_APPS`. Current django-trusts ships no Django `AppConfig`, no
`kernel_config()`, and no `trusts.backends.TrustModelBackend`. The
mixin stays at `trusts.backends.TrustModelBackendMixin`. Historical
Trust / Content / settlor / trustee models and the concrete backend
live only in `django-trusts-zero`.

Pair CI runs historical tests from the pinned Zero companion
`tests/legacy/`, not from core package paths. Exact companion pins
are in [`.github/workflows/ci.yml`](.github/workflows/ci.yml).

## What this package is not

Earlier top-level README copy described django-trusts itself as a
multiple-organization Trust/settlor/trustee add-on with concrete
`Content` / `Group` models. That product description is false for
current django-trusts. Readers who want that 0.x behavior should use
[django-trusts-zero](https://github.com/django-trusts/django-trusts-zero).

## Supported versions

Supported Python, Django, and database versions are in
[docs/support-matrix.md](docs/support-matrix.md). Exact test and
companion pins are in CI and project metadata. User installation is
in [README.md](README.md).

Install from a local checkout with current project metadata:

```
python -m pip install .
```

A host implementation owns `INSTALLED_APPS` and
`AUTHENTICATION_BACKENDS`. One supported pairing is:

```
INSTALLED_APPS = (
    'trusts.zero.apps.ZeroConfig',
)
AUTHENTICATION_BACKENDS = (
    'trusts.zero.backends.TrustModelBackend',
)
```

API and compatibility notes are in [migrates.md](migrates.md).

## Change sizing and surface discovery

Design tasks must estimate the complete implementation and review surface before
implementation is authorized. Use the Fibonacci scale
`1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144`. This is a comparative
risk/complexity size, not an hour estimate or a count of changed lines.

Every design review must surface sizing near the top in three layers:

- the entire controlling ticket, with a realistic range covering all known and
  not-yet-designed stages;
- completed points from accepted subtasks; and
- the current proposed subtask, with one size or a bounded range.

Do not hide unplanned stages inside a precise-looking total. Mark them
`unknown`, give a reasoned comparison where possible, and widen the whole-task
range accordingly. For example:

```text
#247 — v3.7 automatic relationship extraction
Whole ticket: 34–144
Completed: 5 (S1 accepted)
Current: S2 — size 8
S3–S7 — unknown; command, validation, stability, migration,
and consumer surfaces remain unbounded
```

Completed points are the sum of the final reviewed sizes of accepted subtasks.
If a subtask was re-sized during implementation, count its final size and show
the change. If historical work was never sized, label it `unscored` or
`retrospective estimate`; do not invent precision.

The whole-task range is a planning envelope, not a mechanical sum of subtask
points. It should include integration, discoveries between stages, review
rounds, cross-repository sequencing, and final acceptance proof. Completed
points show progress but must not be subtracted mechanically from that range to
claim a precise remaining size while stages remain unknown.

The calibration anchor for a **3** is
[django-trusts #129 / PR #140](https://github.com/django-trusts/django-trusts/pull/140):
a bounded one-repository cleanup with no intended API change that nevertheless
required migration wording, package and companion-wheel proof, preservation of
historical evidence, a focused review correction, and the full django-trusts matrix.
[PR #124](https://github.com/django-trusts/django-trusts/pull/124), a
one-file Read the Docs configuration using an already-proven build, is a useful
**1** reference.

Estimate the surface that must be understood and proved, including:

- public API and migration consequences;
- grant-producing semantics and fail-closed behavior;
- object, queryset, enumeration, and decorator projections;
- relationship identity, many-to-many, recursion, and database dialects;
- registry lifecycle, startup, and zero-SQL guarantees;
- affected consumer repositories and exact-version staging;
- documentation, packaging, CI, deployment, and rollback proof; and
- uncertainty about existing behavior or historical compatibility.

A design handoff must state the subtask size, whole-ticket range, comparison
task used as its anchor, surface drivers, proposed proof, and the known/unknown
status of later stages. A size is not a promise that discovery will stop. If
implementation or review exposes a material surface that the estimate omitted,
stop expanding the patch, report the discovery, and re-size both the current
subtask and the whole-ticket range before continuing.

A task estimated at **13 or larger** is not implementation-ready. Split it at
clean dependency or release boundaries and size the resulting tasks
independently. A task that grows to 13 during implementation follows the same
rule.

## Test

```
python -m pip install -e ".[test]"
python -m tests.runtests
python -m django check --settings=tests.settings
```

`scripts/verify-legacy-upgrade.py` and `scripts/legacy/trusts_0001_sqlite.sql`
remain in this tree as historical already-applied-`0001` evidence. The
runner is currently broken (imports inert `trusts.models`, lists
`'trusts'` in `INSTALLED_APPS`) and is **not** in CI. It is not a live
operator path. Live `create_trust_root`,
`grandfather_trust_group_permissions`, and `update_roles_permissions`
commands require `trusts.zero.apps.ZeroConfig`. Zero's
fresh-install / migration-identity / grandfather tests are complementary;
they are not an already-applied-`0001` → `0002` → grandfather replay.
Only that Zero replay should authorize deleting this django-trusts evidence.

CI is GitHub Actions (`.github/workflows/ci.yml`): kernel-only
authorization tests, a fresh migrate, `manage.py check`, pair proofs
against the supported Zero companion, and a `package` job that builds
an sdist/wheel, checks that the long description comes from the user
`README.md` (not this file), verifies BeeDesk 2015-2026 / BSD-2-Clause
`LICENSE` metadata, and imports the wheel from a temporary directory so
the source tree cannot satisfy the import. OrderedFold PostgreSQL proof
lives in `django-trusts-ordered-fold`. Do not treat a removed Travis
check as a stand-in green status.

## Legacy baseline

The exact pre-modernization default-branch commit, existing release tags,
source archive checksum, and historical Python/Django requirements are
recorded in [docs/legacy-baseline.md](docs/legacy-baseline.md). That
snapshot is historical documentation only.

## License

BSD-2-Clause. Copyright holder is exactly BeeDesk, Inc. Notice years
are 2015-2026.
