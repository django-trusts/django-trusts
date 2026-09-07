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
```

Add `trusts` to `INSTALLED_APPS` and set:

```
AUTHENTICATION_BACKENDS = (
    'trusts.backends.TrustModelBackend',
)
```

API and compatibility notes for this modernization are in [migrates.md](migrates.md).

Test
----

```
python -m pip install "Django>=6.1,<6.2" coverage
python -m pip install -e .
python -m tests.runtests
```

CI is GitHub Actions (`.github/workflows/ci.yml`): authorization tests on
Python 3.12, 3.13, and 3.14 with Django 6.1, plus an sdist/wheel build and
install check. Those job names (`tests (Python 3.12)`, `tests (Python 3.13)`,
`tests (Python 3.14)`, `package`) are the current required-status candidates.
Do not treat a removed Travis check as a stand-in green status.

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
