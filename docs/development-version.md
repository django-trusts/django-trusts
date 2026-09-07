# Development version 1.0.0.dev0

The revived Trusts development line is now **1.0.0.dev0**. This is a
development-version mark only. It is not a production 1.0 release, not a PyPI
publication, and not a claim that the declarative permission model has been
validated.

## Why a new major version

The last published package was **0.10.3** (`v0.10.3`). Upcoming Python 3 and
modern Django work is expected to break compatibility with that historical
stack (Python 2.7 / Django 1.8). Starting the next line at `1.0.0.dev0`
records that planned break before those runtime changes land.

This note does not change runtime support claims. Classifiers and
`requirements.txt` still describe the historical environment until a later
modernization PR updates them.

## What this bump does not do

- No API or method changes
- No `migrates.md` entry (none is required)
- No final `1.0.0` tag or GitHub Release
- No move or replacement of existing tags, including `v0.10.3` and
  `legacy-pre-modernization`

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

| Location | Role | Previous | Now |
| --- | --- | --- | --- |
| `setup.py` | Authoritative package metadata | `0.10.3` | `1.0.0.dev0` |
| `docs/source/conf.py` | Sphinx `version` / `release` | `0.9.4` (already stale vs 0.10.3) | `1.0.0.dev0` |
| `trusts/__init__.py` | No `__version__` | — | unchanged |
| `docs/legacy-baseline.md`, `docs/legacy/baseline.json` | Historical 0.10.3 record | `0.10.3` | preserved |

No `pyproject.toml` or `setup.cfg` version field exists. Existing git tags were
not moved.
