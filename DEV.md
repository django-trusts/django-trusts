# DEV.md — contributor / development history

This file is an internal development record. It may describe
unsupported or superseded states. The user-facing package introduction
is [README.md](README.md). `pyproject.toml` long-description metadata
points at `README.md`, not this file.

## Architecture

Historical django-trusts 0.x was the concrete Trust/Content/group
implementation. Current django-trusts is the schema-neutral Core
library. [django-trusts-zero](https://github.com/django-trusts/django-trusts-zero)
is the continuation/bridge for that historical concrete behavior.

Core is not itself a Django app and owns no concrete permission schema.
It is a Python dependency only: do **not** list `'trusts'` in
`INSTALLED_APPS`. Current Core ships no Django `AppConfig`, no
`kernel_config()`, and no `trusts.backends.TrustModelBackend`. The
mixin stays at `trusts.backends.TrustModelBackendMixin`. Historical
Trust / Content / settlor / trustee models and the concrete backend
live only in `django-trusts-zero`.

## What this package is not

Earlier top-level README copy described django-trusts itself as a
multiple-organization Trust/settlor/trustee add-on with concrete
`Content` / `Group` models. That product description is false for
current Core. Readers who want that 0.x behavior should use
[django-trusts-zero](https://github.com/django-trusts/django-trusts-zero).

## Supported versions

Supported Python, Django, database, and companion-package versions are
recorded in [docs/support-matrix.md](docs/support-matrix.md). Exact
test and companion pins live in CI and configuration
([.github/workflows/ci.yml](.github/workflows/ci.yml)). User
installation is documented in [README.md](README.md) and
[docs/source/index.rst](docs/source/index.rst).

A host implementation owns `INSTALLED_APPS` and
`AUTHENTICATION_BACKENDS`. One supported host configuration is:

```
INSTALLED_APPS = (
    'trusts.zero.apps.ZeroConfig',
)
AUTHENTICATION_BACKENDS = (
    'trusts.zero.backends.TrustModelBackend',
)
```

API and compatibility notes for this modernization are in
[migrates.md](migrates.md).

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
Only that Zero replay should authorize deleting this Core evidence.

CI is GitHub Actions (`.github/workflows/ci.yml`): kernel-only
authorization tests, a fresh migrate, `manage.py check`, an OrderedFold
PostgreSQL job, pair proofs against the supported Zero companion, and a
`package` job that builds an sdist/wheel, checks that the long description
comes from the user `README.md` (not this file), verifies BeeDesk
2015-2026 / BSD-2-Clause `LICENSE` metadata, and imports the wheel from a
temporary directory so the source tree cannot satisfy the import. Do not
treat a removed Travis check as a stand-in green status.

## Legacy baseline

The exact pre-modernization default-branch commit, existing release tags,
source archive checksum, and historical Python/Django requirements are
recorded in [docs/legacy-baseline.md](docs/legacy-baseline.md). That
snapshot is historical documentation only.

## License

BSD-2-Clause. Copyright holder is exactly BeeDesk, Inc. Notice years
are 2015-2026.
