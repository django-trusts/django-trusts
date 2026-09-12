# Supported Python and Django matrix

Recorded on **2026-09-07** while implementing #14 and the coordinated
Django/CI work from #15. This is the current development-line claim for
`1.0.0.dev3`. It is not a published PyPI release.

A Python-only intermediate against Django 1.8 is not a supported or testable
state: Django 1.8 does not install on current CPython, and the preserved
implementation uses removed Django 1.8 APIs. The merged tree therefore
declares one matrix and tests it in CI.

## Sources checked at implementation time

| Source | What it established | URL |
| --- | --- | --- |
| Django download page | Latest official Django is **6.1.1**. 6.1 mainstream support ends April 2027. Django 5.2 is the current LTS (extended support through April 2028). Django 4.2 LTS ended 2026-04-07. | https://www.djangoproject.com/download/ |
| Django install FAQ (stable) | Django **6.1** officially supports **Python 3.12, 3.13, and 3.14** only. | https://docs.djangoproject.com/en/stable/faq/install/ |
| Django 6.1 release notes | Same Python list; only the latest micro of each series is officially supported. | https://docs.djangoproject.com/en/6.1/releases/6.1/ |
| CPython Developer's Guide | Supported CPython on 2026-09-07: 3.14 and 3.13 (bugfix), 3.12 / 3.11 / 3.10 (security). 3.15 is prerelease (first release scheduled 2026-10-01). 3.9 ended 2025-10-31. | https://devguide.python.org/versions/ |

## Declared support

| Component | Requirement | Rationale |
| --- | --- | --- |
| Python | 3.12, 3.13, 3.14 (`requires-python >=3.12`) | Intersection of currently supported CPython and Django 6.1's official matrix. 3.10/3.11 remain in CPython security support but are not in Django 6.1's matrix. 3.15 is not a stable release yet. |
| Django | `>=6.1,<6.2` (tested against 6.1.1) | Latest stable Django at implementation time, per #15. |

CI (`.github/workflows/ci.yml`) runs kernel-only authorization tests, a
fresh migrate (no Trusts schema), and `manage.py check` on **each**
declared Python version with Django 6.1, plus the OrderedFold PostgreSQL
job, the Core/Zero pair job, and a `package` job. The `package` job
(sdist/wheel build, `twine check`, metadata/LICENSE proof, and an
out-of-checkout wheel import) runs on **Python 3.12** as a representative
install of the declared range. Core still retains
`scripts/verify-legacy-upgrade.py` as historical already-applied-`0001`
evidence; that runner is currently broken, off CI, and not a live
operator path. Live Trusts management commands require
[django-trusts-zero](https://github.com/django-trusts/django-trusts-zero)
and `trusts.zero.apps.ZeroConfig`.

## Database (Along reachability, issue #92)

V1 `Along` / `GrantReach` is claimed only for Django's
`django.db.backends.sqlite3` engine together with the JSON functions
`json_array`, `json_group_array`, `json_array_length`, and `json_each`,
plus `WITH RECURSIVE`. That combination is what CI executes.

This is not a claim for PostgreSQL, MySQL, MariaDB, Oracle, or any other
vendor. Those engines need a separate renderer and CI proof. Runtime
compilation on a non-sqlite3 connection raises `TrustsConfigurationError`
before walk SQL. `trusts.E005` is a database-tagged check over exactly
the aliases Django passes in `databases`; it is not an all-clear when
that argument is absent or empty.

## What is intentionally not declared

- **Django 5.2 LTS** is still in extended support. It was not added to this
  first modernization matrix so the project does not maintain an extra
  intermediate stack. Revisit if downstream projects need the LTS line.
- **Python 3.10 / 3.11** are still in CPython security support but are not
  official Django 6.1 runtimes.
- **Python 3.15** is a prerelease as of this record.
- The historical Python 2.7 / Django 1.8 stack is documented only in
  [legacy-baseline.md](legacy-baseline.md). That snapshot is unchanged.

## Historical requirements (not current)

At `legacy-pre-modernization` (`20ef239`): Python 2.7 and `Django>=1.8,<1.9`,
plus `six`, `funcsigs`, `mock`, `pbr`, `docutils`, and `wheel` as install
requirements. Those compatibility packages are removed from the development
line.
