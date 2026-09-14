# django-trusts

![django-trusts badger mascot holding a green key](docs/source/_static/django-trusts-mascot.png)

[![Coverage](https://coveralls.io/repos/github/django-trusts/django-trusts/badge.svg?branch=dev)](https://coveralls.io/github/django-trusts/django-trusts?branch=dev)

`django-trusts` is a Django permission system for object-level authorization.
It integrates with Django's authentication backend interface, allowing
applications to use familiar checks such as
`user.has_perm(permission, object)` while defining authorization policies
with ordinary Django models.

## How permissions are represented

A **trust model** is the application-owned Django model from which three
authorization paths begin:

- **user** — who is requesting access;
- **permission** — the operation being requested; and
- **content** — the object being protected.

Each matching trust record is a candidate grant. A trust model is often an
explicit many-to-many relation model, but it may represent another relational
shape. More than one complete trust may reach the same protected model; each is
an alternative grant and the branches combine with OR.

django-trusts supplies the compiler and authorization APIs. It does not impose a
permission schema, grant editor, or application workflow.

## Usage

Start with **[Installation in the complete usage guide](https://django-trusts.readthedocs.io/en/latest/#installation)**.
The RST guide covers models, backend configuration, trust registration
(both one-argument registration-time path builders and Django `__` strings,
shown together),
named filters, object and queryset authorization, inherited relationships, and
ordered allow/deny policies.

## Other documents

- [Security audit guide](SECURITY_AUDIT.md)
- [Migration guide](migrates.md)
- [Supported Python, Django, and database combinations](docs/support-matrix.md)
- [Development and contribution guide](DEV.md)
- [BSD 2-Clause License](LICENSE)

## Other repositories

- [django-trusts-zero](https://github.com/django-trusts/django-trusts-zero) — continuation of the concrete django-trusts 0.x model
- [django-trusts-zero-example](https://github.com/django-trusts/django-trusts-zero-example) — runnable application using Zero
- [django-trusts-gh-permissions](https://github.com/django-trusts/django-trusts-gh-permissions) — organization, team, and repository relationship reference
- [django-trusts-ordered-fold](https://github.com/django-trusts/django-trusts-ordered-fold) — PostgreSQL ordered allow/deny backend
- [django-trusts-windows-acl](https://github.com/django-trusts/django-trusts-windows-acl) — Windows ACL consumer of OrderedFold

Copyright BeeDesk, Inc., 2015–2026. Released under the BSD 2-Clause License.
