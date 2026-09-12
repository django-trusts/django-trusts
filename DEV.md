# DEV.md — contributor / development history

This file is an internal development record. It may describe
unsupported or superseded states. The user-facing package introduction
is [README.md](README.md). `pyproject.toml` long-description metadata
points at `README.md`, not this file.

## Current pairing

This tree is `django-trusts==1.0.0.dev3`, the final core-library cut
([#112](https://github.com/django-trusts/django-trusts/pull/112)
merge `11058641b533e0f8489598e0b1f5cbe5d42a81db`). That mark is a
development-line identifier, not a production 1.0 release. See
[docs/development-version.md](docs/development-version.md).

The completed Zero user path is django-trusts-zero
[#14](https://github.com/django-trusts/django-trusts-zero/pull/14)
merge `f0b25c5562c4f9803d861503dd2acac21613119d`
(`django-trusts-zero==1.0.0.dev0`).

Core is a Python dependency only: do **not** list `'trusts'` in
`INSTALLED_APPS`. Final core ships no Django `AppConfig`, no
`kernel_config()`, and no `trusts.backends.TrustModelBackend`. The
mixin stays at `trusts.backends.TrustModelBackendMixin`. Historical
Trust / Content / settlor / trustee models and the concrete backend
live only in `django-trusts-zero`.

Pair CI pins the Zero #37 STAGE 1 destination
`904a51f922df4d0dc9a20ccadc37f34eb481fcff` so historical tests run
from Zero `tests/legacy/`, not from core package paths.

## What this package is not

Earlier top-level README copy described django-trusts itself as a
multiple-organization Trust/settlor/trustee add-on with concrete
`Content` / `Group` models. That product description is false for this
library after the final core cut. Readers who want that 0.x behavior
should use [django-trusts-zero](https://github.com/django-trusts/django-trusts-zero).

## Supported versions

The `1.0.0.dev3` development line requires **Python 3.12–3.14** and
**Django 6.1**. Sources checked on 2026-09-07 and the rationale are in
[docs/support-matrix.md](docs/support-matrix.md).

This is not a published PyPI release. Install from a local checkout or
sdist/wheel built from this tree.

```
python -m pip install "Django>=6.1,<6.2"
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

API and compatibility notes for this modernization are in
[migrates.md](migrates.md).

## Test

```
python -m pip install "Django>=6.1,<6.2" coverage
python -m pip install -e .
python -m tests.runtests
python -m django check --settings=tests.settings
python scripts/verify-legacy-upgrade.py
```

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
