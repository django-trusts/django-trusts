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
| Admin / i18n surfaces | Core models registered; `auto_modeladmin` opt-in is exercised in `AutoModelAdminTest`. |

## Issue #8 recovery tests (do not close #8)

These must keep passing in addition to the table above:

- `PermittedQuerySetTest` — trustee / TrustGroup local/global intersection / role-as-ceiling list-direct parity, SQL filter, inactive empty, `get_permission`, grant/revoke, conditioned names raise `PermissionConditionNotQueryable`
- `FilterByUserContentPermTest` — create-under-trust, no settlor shortcut, no parent-trust leak, inactive empty, `test_filter_by_user_perm` still discovered, conditioned names raise
- `AuthorizationTest` — reader/member denial with no mutation, scoped entity IDs, shared-group ceiling vs local grants, shared-group membership requires admin on every trust
- `TeamViewAuthorizationTest` — member GET/POST 403, admin add, unknown user PK does not mutate
- `AutoModelAdminTest` — Content and Junction proxies with `auto_modeladmin = True` register; opt-out does not
- `TrustGroupIntersectionTest` — issue #23 acceptance: no TrustGroup / empty local / local-without-ceiling deny; both layers allow; per-trust local subsets; removing either layer revokes; two groups combine without widening; trustee unchanged; role-derived ceiling; inactive/anonymous deny; `has_perm` / `.permitted` / `filter_by_user_content_perm` parity; legacy association grants nothing; grandfather dry-run/apply; later ceiling adds stay local-off; configured group/permission models

Do not treat a gap as license to widen access. New grants need an explicit
test.
