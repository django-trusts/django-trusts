# DEV.md — contributor / development record

This file is an internal development record. It may describe
unsupported or superseded states. The user-facing package introduction
is [README.md](README.md). `pyproject.toml` long-description metadata
points at `README.md`, not this file.

## Final library cut (correcting earlier README copy)

`django-trusts==1.0.0.dev3` is a **Python library**, not an installed
Django app and not a concrete Trust/settlor/trustee product.

- Do **not** list `'trusts'` in `INSTALLED_APPS`.
- Core ships no Django `AppConfig`, no Django app label, and no
  `kernel_config()`.
- `trusts.core_backends` is gone. The generic mixin lives only at
  `from trusts.backends import TrustModelBackendMixin`.
- Historical concrete models and `TrustModelBackend` live under
  `trusts.zero.*` when `django-trusts-zero` is installed.
- The Trust/settlor/trustee introduction that used to lead this
  repository described the 0.x product. That product continues as
  [django-trusts-zero](https://github.com/django-trusts/django-trusts-zero).

A host `TrustsImplementationConfig` owns the backend path and registry.
Kernel-only tests use `tests.kernel_host.apps.KernelHostConfig`. The
supported Zero pair uses `trusts.zero.apps.ZeroConfig`:

```
INSTALLED_APPS = (
    'trusts.zero.apps.ZeroConfig',
)
AUTHENTICATION_BACKENDS = (
    'trusts.zero.backends.TrustModelBackend',
)
```

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
authorization tests, a fresh migrate, ``manage.py check``, an
OrderedFold PostgreSQL job, pair proofs against the supported Zero
companion, and a `package` job that builds an sdist/wheel and imports
it from a temporary directory so the source tree cannot satisfy the
import. Do not treat a removed Travis check as a stand-in green status.

## Development version

The active package version is **1.0.0.dev3**. That is a development-line
mark, not a production 1.0 release. See
[docs/development-version.md](docs/development-version.md).

`1.0.0.dev2` remains the merged implementation-owned registry bridge.
`1.0.0.dev1` remains the merged mixin-extract checkpoint. Those are
internal marks only.

## Legacy baseline

The exact pre-modernization default-branch commit, existing release
tags, source archive checksum, and historical Python/Django
requirements are recorded in
[docs/legacy-baseline.md](docs/legacy-baseline.md). That snapshot is
historical documentation only.

## Historical 0.x product copy (superseded)

The following is the pre-library-cut product introduction. It is not
the current core contract.

``django-trusts`` began as an add-on to Django's builtin authorization
that added a ``trust`` relationship so a project hosting users of
multiple organizations could keep maintainable per-object permission
settings in a single user namespace. A ``trust`` permitted content
access from a creator (``settlor``) to specific users (``trustee`` s)
or groups. Content could be a ``Content`` subclass or an existing model
via a junction table. Permissions checking used ``has_perm()`` /
``has_perms()`` against an individual object or a ``QuerySet``.

That concrete schema is no longer part of core. Use
`django-trusts-zero` for the 0.x continuation.

## License

BSD 2-Clause Simplified. Copyright holder is exactly BeeDesk, Inc.
Notice years are 2015-2026.
