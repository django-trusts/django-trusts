# Authorization test coverage

Recorded with the #14/#15 modernization. Existing tests were kept and
extended. This is not a claim that the declarative permission model is
complete.

## Tests that must keep passing

Denied access and organization isolation (a trust is the organization
boundary):

- `TrustContentTestMixin.test_user_not_in_group_has_no_perm`
- `TrustContentTestMixin.test_has_perm_disallow_no_perm_content`
- `TrustContentTestMixin.test_has_perm_disallow_no_perm_perm`
- `TrustContentTestMixin.test_mixed_trust_queryset`
- `TrustContentTestMixin.test_denied_access_without_grant` (added)
- `TrustContentTestMixin.test_organization_isolation_denies_cross_trust_access` (added)
- `TrustTest.test_own_condition_requires_settlor` (added; `:own` is settlor-only)
- Role tests that a stronger role on one trust does not leak to another

These run for `Content` subclasses, `Junction` content, and `Trust` as content
where the mixin applies.

## Known expected failure

`TrustJunctionTestCase.test_read_permissions_added` remains
`@unittest.expectedFailure`. Junctions do not add `read_*` permissions on the
joined model. That is historical, not a new denial-widening.

## Coverage gaps (not closed here)

| Area | Why it is a gap |
| --- | --- |
| Anonymous request users | Settlor-anonymous is rejected; object-level anonymous grants are not specified. |
| Superuser short-circuit | Django's `ModelBackend` still treats superusers as having all perms; no extra Trusts test. |
| Nested / inherited trusts | `Trust.trust` is a parent pointer with a readonly check; no recursive ACL evaluation (out of scope). |
| `has_perm` without `obj` | Falls through to Django model-level perms; only lightly covered via role tests. |
| `get_group_permissions` content path | Returns a permission queryset, not the string set `ModelBackend` uses; no dedicated assertion. |
| Decorator `raise_exception=True` | Most decorator tests use `raise_exception=False`. |
| `TRUSTS_ENTITY_MODEL` swap | Custom entity model is configurable but untested. |
| Captured production MySQL/Postgres dump | `scripts/verify-legacy-upgrade.py` upgrades a representative 0.10.3-shaped SQLite DB (`trusts.0001_initial` already recorded, historical table DDL). It is not a customer dump and does not replay Django 1.8 contrib tables. |
| Admin / i18n surfaces | Registered, not exercised. |

Do not treat a gap as license to widen access. New grants need an explicit
test.
