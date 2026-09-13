# django-trusts

![django-trusts badger mascot holding a green key](docs/source/_static/django-trusts-mascot.png)

[![Coverage](https://coveralls.io/repos/github/django-trusts/django-trusts/badge.svg?branch=dev)](https://coveralls.io/github/django-trusts/django-trusts?branch=dev)

`django-trusts` is a Django permission system for object-level authorization.
It integrates with Django's authentication backend interface, allowing
applications to use familiar checks such as
`user.has_perm(permission, object)` while defining authorization policies
with ordinary Django models.

## How permissions are represented

A permission-bearing relationship connects three paths from one
application-owned model:

- **user** — who is requesting access;
- **permission** — the operation being requested; and
- **content** — the object being protected.

The paths describe persisted application-owned facts. More than one complete
relationship may reach the same protected model; each is an alternative grant
and the branches combine with OR.

Core supplies the compiler and authorization APIs. It does not impose a
permission schema, grant editor, or application workflow.

## Usage

Start with **[Installation in the complete usage guide](https://django-trusts.readthedocs.io/en/latest/#installation)**.
The RST guide covers models, backend configuration, relationship registration,
named filters, object and queryset authorization, inherited relationships, and
ordered allow/deny policies.

## Other documents

- [Security audit guide](SECURITY_AUDIT.md)
- [Migration router](migrates.md)
- [Supported Python, Django, and database combinations](docs/support-matrix.md)
- [Development and contribution guide](DEV.md)
- [BSD 2-Clause License](LICENSE)

## Other repositories

- [django-trusts-zero](https://github.com/django-trusts/django-trusts-zero) — continuation of the concrete django-trusts 0.x model
- [django-trusts-zero-example](https://github.com/django-trusts/django-trusts-zero-example) — runnable application using Zero
- [django-trusts-gh-permissions](https://github.com/django-trusts/django-trusts-gh-permissions) — organization, team, and repository relationship reference
- [django-trusts-windows-acl](https://github.com/django-trusts/django-trusts-windows-acl) — ordered allow/deny reference

Copyright BeeDesk, Inc., 2015–2026. Released under the BSD 2-Clause License.
