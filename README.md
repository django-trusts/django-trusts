Django Trusts
-------------

[![Docs](https://readthedocs.org/projects/django-trusts/badge/)](http://django-trusts.readthedocs.org) [![Coverage](https://coveralls.io/repos/github/beedesk/django-trusts/badge.svg?branch=master)](https://coveralls.io/github/beedesk/django-trusts?branch=master) [![Version](https://badge.fury.io/py/django-trusts.svg)](https://pypi.python.org/pypi/django-trusts)

Django authorization add-on for multiple organizations and object-level permission settings

Introduction
------------

``django-trusts`` is a add-on to Django's builtin authorization. It strives to be a **minimal** implementation, adding only a single concept, ``trust``, to enable maintainable per-object permission settings for a django project that hosts users of multiple organizations  with a single user namespace.

A ``trust`` is a relationship whereby content access is permitted by the creator [``settlor``] to specific user(s) [``trustee`` (s)] or ``group`` (s). Content can be an instance of a `Content` subclass, or of an existing model via a junction table. Access to multiple content can be permitted by a single ``trust`` for maintainable permssion settings. Django's builtin model, `group`, is supported and can be used to define reusuable permissions for a ``group`` of ``user``'s.

``django-trusts`` also strives to be a **scalable** solution. Permissions checking is offloaded to the database by design, and the implementation minimizes database hits. Permissions are cached per ``trust`` for the lifecycle of ``request user``. If a project's request lifecycle resolves most checked content to one or few ``trusts``, which should be very typically the case, this design should be a winner in term of performance. Permissions checking is done against an individual content or a ``QuerySet``.

``django-trusts`` supports Django's builtins User models ``has_perms()`` / ``has_perms()`` and does not provides any in-addition.

Read more: http://django-trusts.readthedocs.org/en/latest/

Test
----

To run unit tests:

```
pip install virtualenv
virtualenv venv/
source venv/bin/activate
python setup.py test
```

Development version
-------------------

The active package version is **1.0.0.dev0**. That is a development-line mark
ahead of the planned Python/Django compatibility break, not a production 1.0
release. See [docs/development-version.md](docs/development-version.md).

Legacy baseline
---------------

The exact pre-modernization default-branch commit, existing release tags, source
archive checksum, and historical Python/Django requirements are recorded in
[docs/legacy-baseline.md](docs/legacy-baseline.md). That snapshot is historical
documentation only.
