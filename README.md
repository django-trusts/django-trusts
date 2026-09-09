Django Trusts
-------------

[![Docs](https://readthedocs.org/projects/django-trusts/badge/)](http://django-trusts.readthedocs.org) [![CI](https://github.com/django-trusts/django-trusts/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/django-trusts/django-trusts/actions/workflows/ci.yml)

Django authorization add-on for multiple organizations and object-level permission settings

Introduction
------------

``django-trusts`` is a add-on to Django's builtin authorization. It strives to be a **minimal** implementation, adding only a single concept, ``trust``, to enable maintainable per-object permission settings for a django project that hosts users of multiple organizations  with a single user namespace.

A ``trust`` is a relationship whereby content access is permitted by the creator [``settlor``] to specific user(s) [``trustee`` (s)] or ``group`` (s). Content can be an instance of a `Content` subclass, or of an existing model via a junction table. Access to multiple content can be permitted by a single ``trust`` for maintainable permssion settings. Django's builtin model, `group`, is supported and can be used to define reusuable permissions for a ``group`` of ``user``'s.

``django-trusts`` also strives to be a **scalable** solution. Permissions checking is offloaded to the database by design, and the implementation minimizes database hits. Permissions are cached per ``trust`` for the lifecycle of ``request user``. If a project's request lifecycle resolves most checked content to one or few ``trusts``, which should be very typically the case, this design should be a winner in term of performance. Permissions checking is done against an individual content or a ``QuerySet``.

``django-trusts`` supports Django's builtins User models ``has_perm()`` / ``has_perms()`` and does not provides any in-addition.

Read more: http://django-trusts.readthedocs.org/en/latest/

Supported versions
------------------

The `1.0.0.dev0` development line requires **Python 3.12–3.14** and **Django 6.1**.
Sources checked on 2026-09-07 and the rationale are in
[docs/support-matrix.md](docs/support-matrix.md).

This is not a published PyPI release. Install from a local checkout or sdist/wheel
built from this tree.

```
python -m pip install "Django>=6.1,<6.2"
python -m pip install .
python -m pip install django-trusts-zero
```

Add explicit AppConfig paths (do **not** use bare ``'trusts'``). Concrete
Trust/Content models live in the companion
[`django-trusts-zero`](https://github.com/django-trusts/django-trusts-zero)
distribution as ``trusts.zero``:

```
INSTALLED_APPS = [
    'trusts.apps.KernelConfig',
    'trusts.zero.apps.ZeroConfig',
]
AUTHENTICATION_BACKENDS = (
    'trusts.zero.backends.TrustModelBackend',
)
```

Import concrete models from ``trusts.zero.models``. Kernel APIs stay
``trusts.context``, ``trusts.trustee``, ``trusts.path``, ``trusts.runtime``,
``trusts.query``, ``trusts.backends``, and ``trusts.decorators``. This
package does not ship ``trusts/zero``.

API and compatibility notes for this modernization are in [migrates.md](migrates.md).

Test
----

```
python -m pip install "Django>=6.1,<6.2" coverage
python -m pip install -e .
python -m pip install --no-deps -e ../django-trusts-zero --config-settings editable_mode=compat
python -m tests.runtests
python -m tests.runtests_custom
python -m django check --settings=tests.settings
python -m django check --settings=tests.custom_settings
python scripts/verify-legacy-upgrade.py
python scripts/verify-migration-split.py
python scripts/verify-namespace-install.py
```

Authorization tests import ``trusts.zero`` from the companion checkout,
not from this tree. CI clones
[`django-trusts-zero`](https://github.com/django-trusts/django-trusts-zero)
at the **stable ``main`` merge SHA** in ``scripts/zero-companion.pin``
(django-trusts-zero#1 / ``19b0775e6a477ebcf8a2f1accef5df39491a4793``),
not an ephemeral PR branch.

The executable suite lives under `tests/` (`tests/core/`,
`tests/regressions/`, and the isolated `tests/custom_content/` app).
Shared fixtures are in `tests/support.py`. Those modules are not part of
the installable `trusts` package.

CI is GitHub Actions (`.github/workflows/ci.yml`): reads the stable
Zero ``main`` SHA from ``scripts/zero-companion.pin``, checks out that
commit of ``django-trusts-zero``, then runs authorization tests, a fresh
migrate, ``manage.py check``, the isolated custom-user suite, the
legacy-upgrade script, and migration-identity on Python 3.12, 3.13, and
3.14 with Django 6.1. The `package` job (Python 3.12 only) builds an
sdist/wheel, imports the kernel wheel from a temporary directory, and
pairs it with a wheel built from that pinned companion SHA. Job names:
`tests (Python 3.12)`, `tests (Python 3.13)`, `tests (Python 3.14)`,
`package`. Do not treat a removed Travis check as a stand-in green
status.

Development version
-------------------

The active package version is **1.0.0.dev0**. That is a development-line mark,
not a production 1.0 release. See [docs/development-version.md](docs/development-version.md).

Legacy baseline
---------------

The exact pre-modernization default-branch commit, existing release tags, source
archive checksum, and historical Python/Django requirements are recorded in
[docs/legacy-baseline.md](docs/legacy-baseline.md). That snapshot is historical
documentation only.
