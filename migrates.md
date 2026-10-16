# Migrating from django-trusts 1.0 to 1.1

Only required application changes belong here; optional additions are in
[What's new](docs/whats-new.md).

## `filter_authorized_scopes` renamed (#302)

Replace `filter_authorized_scopes(...)` with `filter_by_permitted_content(...)`.
The old name remains a deprecated alias with the same signature and behavior.

## Superuser bypass (#273)

Applications relying on an implicit Trusts superuser bypass must register an
explicit override; see the [audit example](SECURITY_AUDIT.md#django-auths-checks-before-calling-backends).

## Permission content type must match the object (#267)

Crossed `auth.Permission`/object pairs that previously granted now deny.
Correct grants that relied on that mismatch and regenerate the policy lockfile;
no schema migration is needed. See the [identity contract](SECURITY_AUDIT.md#permission-identity-and-failure-behavior).

```python
# Wrong content type: do not rely on this check granting.
owner.has_perm("gh_permissions.read_repository", organization)
# Ask the organization's permission instead.
owner.has_perm("gh_permissions.manage_organization", organization)
```

## Migrating to django-trusts 1.0

The 0.x concrete models and schema are not compatible with this library.
Existing 0.x applications should use django-trusts-zero and follow its
[migration guide](https://github.com/django-trusts/django-trusts-zero/blob/dev/migrates.md).
New integrations start with the [usage guide](docs/source/index.rst).

Earlier development transitions remain in the
[pre-1.0 archive](https://github.com/django-trusts/django-trusts/blob/migration-archive-pre-1.0/migrates.md)
and the [immutable pre-reorganization record](https://github.com/django-trusts/django-trusts/blob/426b7ea33f817e78290cf2e769105aaa6bfd69a5/migrates.md).
