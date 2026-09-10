# Development version 1.0.0.dev0

The revived Trusts development line is **1.0.0.dev0**. This is a
development-version mark only. It is not a production 1.0 release, not a PyPI
publication, and not a claim that the declarative permission model has been
validated.

## Why a new major version

The last published package was **0.10.3** (`v0.10.3`). The Python 3 and
Django 6.1 work is a compatibility break with that historical stack
(Python 2.7 / Django 1.8). The version was marked `1.0.0.dev0` in #18 before
those runtime changes landed.

## Current runtime claim

See [support-matrix.md](support-matrix.md). Declared and CI-tested:

- Python 3.12, 3.13, 3.14
- Django `>=6.1,<6.2`

Package metadata lives in `pyproject.toml`. `setup.py` is a thin setuptools
wrapper. Obsolete Python 2 classifiers and `six` / `funcsigs` / `mock` / `pbr`
install dependencies are removed.

API and method changes for the modernization are recorded in
[../migrates.md](../migrates.md).

## What this line still does not do

- No final `1.0.0` tag or GitHub Release
- No PyPI publication
- No move or replacement of existing tags, including `v0.10.3` and
  `legacy-pre-modernization`
- No permission-model redesign

## Internal registration primitive

`trusts.core` adds an isolated `TrustsRegistry` and root-relative `Ref`
(issue #57). That is an additive development API: it is not re-exported
from `trusts`, does not change authorization results, and does not add a
schema or migration. See [core-registry.md](core-registry.md).

## Preserved legacy source

The pre-modernization tree remains available at:

| Location | Reference |
| --- | --- |
| Annotated tag | `legacy-pre-modernization` → `20ef23946d4fcfd9463fcf5953bb9414b8f0521b` |
| Record | [docs/legacy-baseline.md](legacy-baseline.md) |
| Release archive | https://github.com/django-trusts/django-trusts/releases/download/legacy-pre-modernization/django-trusts-legacy-pre-modernization.tar.gz |
| In-repo archive | [docs/legacy/django-trusts-legacy-pre-modernization.tar.gz](legacy/django-trusts-legacy-pre-modernization.tar.gz) |
| SHA-256 | `ae79e1f0e45c957b33a9acabeb7389aa75dcea714f1621eed6c714d3ef71e084` |

Those artifacts are historical. Retrieve them as documented in
`docs/legacy-baseline.md`; do not treat them as the current development
version.

## Version sources

| Location | Role | Value |
| --- | --- | --- |
| `pyproject.toml` | Authoritative package metadata | `1.0.0.dev0` |
| `setup.py` | Thin wrapper; no duplicate version field | defers to `pyproject.toml` |
| `docs/source/conf.py` | Sphinx `version` / `release` | `1.0.0.dev0` |
| `trusts/__init__.py` | No `__version__` | unchanged |
| `docs/legacy-baseline.md`, `docs/legacy/baseline.json` | Historical 0.10.3 record | preserved |
