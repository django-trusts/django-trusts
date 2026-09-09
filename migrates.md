# Migration record (1.0.0.dev0 Python/Django modernization)

This record covers API and method changes in the coordinated #14/#15
modernization. Authorization semantics are intended to be preserved. This is
not a permission-model redesign.

## No change to these public call sites

These keep their previous signatures and intended allow/deny behavior:

- `User.has_perm` / `User.has_perms` via `trusts.backends.TrustModelBackend`
- `trusts.decorators.permission_required`, `P`, `K`, `G`, `O`
- `Trust.objects.get_or_create_settlor_default`, `get_root`,
  `filter_by_content`, `filter_by_user_perm`
- `Content` / `Junction` subclassing, role `Meta` options, management commands
  `create_trust_root` and `update_roles_permissions`

Runtime requirements changed (Python 2.7 / Django 1.8 → Python ≥3.12 /
Django 6.1). That is a compatibility break, not a Trusts method rename.

## Changes

### 1. `ForeignKey` fields now require `on_delete=CASCADE`

| | |
| --- | --- |
| Previous | Django 1.8 `ForeignKey(...)` with implicit cascade-on-delete. |
| New | Every Trusts `ForeignKey` (models and historical `0001_initial`) declares `on_delete=models.CASCADE`. |
| Replacement | Same field, explicit argument matching the 1.8 default. |
| Affected | `Content.trust`, `Trust.settlor` / `Trust.trust`, `RolePermission`, `TrustUserPermission`, `Junction.trust`. Downstream `ForeignKey`s on project models also need `on_delete` (Django, not Trusts). |
| Authorization | Delete still cascades as in 1.8. Not switched to Django 6.1 `DB_CASCADE` (that would skip `pre_delete` / `post_delete`). |

Migration-bot checklist:

- [ ] Find project `ForeignKey` / `OneToOneField` declarations missing `on_delete`.
- [ ] Set `on_delete=models.CASCADE` unless a different policy is documented.
- [ ] Do not add a new Trusts schema migration solely for this; `0001_initial` was updated in place so already-applied installs keep the same migration name.
- [ ] Verify delete of a `Trust` / user still cascades related trustee rows.

### 2. `P.__unicode__` removed; `__str__` is the Python 3 display method

| | |
| --- | --- |
| Previous | `P.__unicode__` returned `self.perm` (attribute did not exist; leaf `repr` was already broken) or `'P object'`. |
| New | `P.__str__` returns `self._perm` or `'P object'`. `__unicode__` is gone. |
| Replacement | `str(p)` / `repr(p)`. |
| Affected | Debug logging only. Permission evaluation uses `P.solve`, not stringification. |
| Authorization | None. |

Migration-bot checklist:

- [ ] Replace `P.__unicode__` / `.unicode()` calls with `str(...)`.
- [ ] Re-run decorator expression tests.

### 3. Django user anonymity is a property

| | |
| --- | --- |
| Previous | `user.is_anonymous()` (Django 1.8 method). |
| New | `user.is_anonymous` (Django ≥1.10 property). Used by `TrustManager.get_or_create_settlor_default` and `TrustModelBackendMixin`. |
| Replacement | Property access. Trusts' public method signatures are unchanged. |
| Affected | Internal checks only. Anonymous settlors remain unsupported (`ValueError`). |
| Authorization | Same reject of anonymous settlors. Anonymous users still fall through to `ModelBackend`. |

Migration-bot checklist:

- [ ] Replace project `user.is_anonymous()` / `user.is_authenticated()` calls with property access if still on the old form.
- [ ] Confirm anonymous users cannot obtain trust-scoped grants.

### 4. `create_trust_root` is idempotent; `apps=` is no longer a command option

| | |
| --- | --- |
| Previous | Always inserted the root row; a second run raised `IntegrityError`. `call_command('create_trust_root', apps=apps)` passed historical models. |
| New | Returns the existing root when `pk` already exists. Django 6.1 rejects unknown command options, so `0001_initial` calls `create_root_trust` with `apps.get_model(...)` instead of `call_command(..., apps=apps)`. |
| Replacement | `create_root_trust(Trust, pk, settlor, title)` or `manage.py create_trust_root`. |
| Affected | Tests and `0001_initial` `RunPython`. Project code that passed `apps=` to the command must stop doing so. |
| Authorization | Does not create extra roots or change `TRUSTS_ROOT_PK`. |

Migration-bot checklist:

- [ ] You may run `create_trust_root` on an upgraded database; it is a no-op when the root exists.
- [ ] Confirm a single root (`Trust.objects.filter(trust=F('id')).count() == 1`).

### 5. Internal Django/Python compatibility (same Trusts signatures)

These are required for Django 6.1 / Python 3 and do not change Trusts call
signatures:

| Previous | New |
| --- | --- |
| `django.utils.translation.ugettext_lazy` | `gettext_lazy` |
| `field.rel` / `field.rel.to` | `field.remote_field` / `field.remote_field.model` |
| `dict.iteritems()` | `dict.items()` |
| `six.string_types` / `django.utils.six` | `str` |
| `from mock import Mock` | `unittest.mock` |
| `urllib` / `urlparse` (Python 2) | `urllib.parse` |
| `django.utils.decorators.available_attrs` | `functools.wraps` defaults |
| `django.contrib.auth.views.redirect_to_login` | unchanged (still in `auth.views`) |
| `default_app_config` | `trusts.apps.AppConfig` discovery |
| `ManyToManyField(..., null=True)` | `null` dropped (it had no effect) |
| `connection.creation.sql_create_model` (tests) | `schema_editor.create_model` |

Bugfixes included because the previous names crashed on modern Python:

- `get_group_model()` now uses `GROUP_MODEL_NAME` (was undefined `GROUP_MODEL`).
- `get_*_model()` helpers import `ImproperlyConfigured`.
- `permission_condition_met` iterates `obj` (was `hasattr(trusts, ...)`, a `NameError`). Iterable object lists are now evaluated item-by-item, matching the QuerySet path. Single model instances are unchanged.
- `ReadonlyFieldsMixin` snapshots ForeignKey column values (`trust_id`, `settlor_id`) instead of following the relation. Django 6.1 fetch modes would otherwise recurse on the self-referential root trust. The readonly rule is unchanged: `trust` and `settlor` still cannot be reassigned after create.

Authorization implication of the `permission_condition_met` fix: a caller who
passed a non-QuerySet iterable previously crashed. They now get an all-must-match
result. No change for the supported QuerySet and single-object paths.

## Migration history

- Historical migration `trusts.0001_initial` is kept. `on_delete=CASCADE` was
  added in place so Django 6.1 can load it. That matches the implicit 1.8
  default and does not change the database schema. `Trust.trust.related_name`
  in that migration uses the same `%(app_label)s_%(class)s_content` template
  as the model (the rendered `trusts_trust_content` value is unchanged).
- Primary keys remain `AutoField`. `AppConfig.default_auto_field` is set to
  `django.db.models.AutoField` so new Trusts models do not switch to
  `BigAutoField`.
- `unique_together` is kept (still valid in Django 6.1) to avoid a new schema
  migration.

### Fresh database

```
python -m django migrate --settings=tests.settings
```

Applies `0001_initial` and creates the root trust when `TRUSTS_CREATE_ROOT`
is true (default).

### Upgrade of a representative legacy database

`scripts/verify-legacy-upgrade.py` is the executable check. It:

1. Applies Django contrib migrations only.
2. Creates Trusts tables from `scripts/legacy/trusts_0001_sqlite.sql`
   (0.10.3 / `0001_initial` field layout).
3. Records `trusts.0001_initial` as already applied. It does **not** fake
   or re-run that migration.
4. Seeds a root row and two organizations.
5. Runs modern `migrate` and asserts the Trusts plan stays empty and the
   applied set remains `{0001_initial}`.
6. Checks the root row plus allow/deny/isolation on `Trust` content.

```
python scripts/verify-legacy-upgrade.py
```

That is a representative Trusts upgrade, not a captured production dump
and not a full Django 1.8→6.1 contrib-schema upgrade. Project models still
need Django's own 1.8→6.1 path (removed APIs, `on_delete`, middleware,
auto fields). No intermediate Trusts migration is required.

## Migration-bot summary

- [ ] Locate `ForeignKey` without `on_delete` and `user.is_anonymous()` call sites.
- [ ] Update those to CASCADE (unless documented otherwise) and property access.
- [ ] Replace `P.__unicode__` with `str`.
- [ ] Confirm `INSTALLED_APPS` includes `trusts` and
      `AUTHENTICATION_BACKENDS` includes `trusts.backends.TrustModelBackend`.
- [ ] `pip install` the modernized package; do not install `six` / `funcsigs` /
      `mock` / `pbr` for Trusts itself.
- [ ] Migrate a fresh DB (`python -m django migrate --settings=tests.settings`).
- [ ] Run `python scripts/verify-legacy-upgrade.py` for the already-applied `0001_initial` path.
- [ ] Verify allow, deny, `:own`, and cross-organization isolation tests.

# Issue #8 recovery (1.0.0.dev0 APIs and authorization)

This record covers the replacement PR for historical #9 / example #1.
Version remains **1.0.0.dev0**. No 0.11.0, no `TrustGroup` through table,
and `trusts.0001_initial` is not rewritten. Authorization is stricter than
the 2016 UI.

## No change to these public call sites

- `User.has_perm` / `User.has_perms` via `TrustModelBackend` (same grant
  tables: trustee, `Group.permissions` ∩ `Trust.groups`, role ∩ `Trust.groups`)
- `trusts.decorators.permission_required`, `P`, `K`, `G`, `O`
- `Trust.objects.get_or_create_settlor_default`, `get_root`,
  `filter_by_content`, **`filter_by_user_perm`** (name and signature kept)
- Implicit `Trust.groups` M2M (no through model)

## Changes

### 6. `ContentQuerySet.permitted(perm, user)` (new)

| | |
| --- | --- |
| Previous | Not on master. #9's `permitted` omitted role grants and hardcoded `auth.Permission`. Example PR #2 reimplemented the JOIN in `projects/query.py`. |
| New | `Content.objects.permitted(perm, user)` — SQL filter of trustee **or** `Group.permissions` **or** role grants on `content.trust`. Empty for inactive/anonymous. Paginate the QuerySet. Superuser short-circuit is **not** duplicated (Django `ModelBackend`). A ``:condition`` suffix (``:own`` or a custom condition) raises ``PermissionConditionNotQueryable``. Conditions stay Python predicates on ``has_perm``; they are not compiled into SQL. |
| Replacement | `Model.objects.permitted('read', user)` or `permitted('app.read_model', user)`. For ``:own`` / custom conditions, filter unconditioned then `has_perm(..., obj)` per row until conditions are SQL-queryable. |
| Affected | New callers; Content subclasses inherit `ContentManager`. `Trust.objects` is a `TrustManager` that also inherits `permitted`. |
| Authorization | Unconditioned list results match `has_perm` on the supported relational paths. Conditioned requests fail closed (do not silently return every object covered by the underlying grant). |

Migration-bot checklist:

- [ ] Replace Python `[obj for obj in qs if user.has_perm(perm, obj)]` list filters with `.permitted(perm, user)` before pagination **only** for unconditioned perms.
- [ ] Do not call `.permitted('app.read_model:own', user)`; catch `PermissionConditionNotQueryable` or use `has_perm` per object.
- [ ] Do not treat `permitted` as a superuser "return all" API.
- [ ] Confirm inactive users get an empty queryset.

### 7. `Content.objects.get_permission(perm)` (new)

| | |
| --- | --- |
| Previous | #9 hardcoded `from django.contrib.auth.models import Permission`. |
| New | Resolves via `get_permission_model()` (`auth.Permission`; see issue #26). Accepts a permission instance, codename, bare action (`read` → `read_<model>`), or dotted code. May strip a leftover `:condition` when resolving a grant/revoke target. Queryset callers must reject conditions first (`permitted` / `filter_by_user_content_perm` do). |
| Replacement | `Model.objects.get_permission('read')` or `get_permission('read_model')`. |
| Affected | `grant` / `revoke`. List APIs do not use this helper alone. |
| Authorization | Lookup only; does not grant. Not a list filter. |

Migration-bot checklist:

- [ ] Resolve grants through `get_permission()` / `auth.Permission`.
- [ ] Re-run permission resolution tests after changing `AUTH_USER_MODEL`.

### 8. `Content.grant(perm, user)` / `Content.revoke(perm, user)` (new)

| | |
| --- | --- |
| Previous | Not on master. #9 `grant` wrote `TrustUserPermission` on `self.trust`. |
| New | Same write target (`self.trust`). `revoke(perm, user)` deletes that perm; `revoke(None, user)` deletes every trustee row for `user` on that trust. These methods do **not** check the actor; views must call `trusts.authorization.grant_trustee` / `revoke_trustee`. |
| Replacement | `content.grant('read', user)` / `content.revoke('change', user)`. |
| Affected | Example `projects.grants.grant_user` / `revoke_user` can delegate here. |
| Authorization | Unchecked instance methods. Administrative wrapping is mandatory for request handlers. |

Migration-bot checklist:

- [ ] Do not expose `grant`/`revoke` on a `read`-only view.
- [ ] Use `authorization.grant_trustee(actor, content, user, perm)` for HTTP POSTs.

### 9. `Trust.objects.filter_by_user_content_perm(user, content, perm_name, exclude_root=True, **kwargs)` (new)

| | |
| --- | --- |
| Previous | Master has only `filter_by_user_perm(user, **kwargs)` (any trustee or group membership). #9 renamed that method, used parent-trust lookups (`trust__trustees`), ignored `fieldlookup`, and treated settlor as a grant. The #9 test was renamed to `filter_by_user_content_perm` (no `test_` prefix) so discovery failed. |
| New | **Additional** method. Create-under-trust: Trusts where `user` holds `perm_name` for `content` on **that Trust row** via trustee / group.permissions / role. No parent lookup. No settlor shortcut. `fieldlookup` unused (no existing content required). Inactive → empty. `exclude_root` defaults True. A ``:condition`` suffix raises ``PermissionConditionNotQueryable`` (same fail-closed rule as `permitted`). `filter_by_user_perm` and `TrustTest.test_filter_by_user_perm` are unchanged. |
| Replacement | `Trust.objects.filter_by_user_content_perm(user, Project, 'add_project')` for create-target trust pickers. Keep `filter_by_user_perm` for "trusts this user is attached to". Settlor-only create still uses `has_perm(..., :own)` per trust, not this queryset. |
| Affected | Example `ProjectForm` trust queryset (historical #1). |
| Authorization | Settlor-only is **not** implied. Conditioned names do not silently return every trust covered by the underlying grant. |

Migration-bot checklist:

- [ ] Do not rename or remove `filter_by_user_perm`.
- [ ] Update any #9-era `filter_by_user_content_perm(self.user)` (old signature) to the four-argument form.
- [ ] Confirm settlors without an `add_*` grant are omitted.
- [ ] Do not pass `:own` / custom conditions to this API.
- [ ] Keep the test named `test_filter_by_user_perm`.

### 10. `trusts.authorization` administrative helpers (new)

| | |
| --- | --- |
| Previous | #9 `TeamView`: group membership was enough to add members. Example #1 `ProjectView`: `read` OR `change` then mutate collaborators / `Group.permissions` / `TrustGroup` in `dispatch`. |
| New | `can_administer_content` requires `change`. `grant_trustee` / `revoke_trustee` / `associate_group_with_trust` / `disassociate_group_from_trust` refuse `read` and unknown IDs (`AuthorizationDenied`, no write). `add_group_member` / `remove_group_member` require `change` on **every** trust that uses the group. `refuse_group_permission_write()` always raises. `create_team` requires trust-row `change` and attaches the new group via `Trust.groups` only. |
| Replacement | Call these helpers from project settings / team views. Do not copy the 2016 `dispatch` mutations. |
| Affected | Any UI that adds collaborators, teams, or members. |
| Authorization | Membership/`read` cannot administer. Shared-group membership is a cross-trust write. |

Migration-bot checklist:

- [ ] Gate POSTs on `change`, not `read` and not `user.groups`.
- [ ] Resolve submitted user/group PKs; unknown IDs must 403/400 with no write.
- [ ] Never assign `group.permissions` from a project form.
- [ ] If a group is used by two trusts, require admin on both before changing members.

### 11. Team views (`trusts.views`, `trusts.urls`)

| | |
| --- | --- |
| Previous | #9 views treated membership as admin. Templates: `auth/group_detail.html`, `auth/group_form.html`. |
| New | Same URL shape (`/teams/new/`, `/teams/<pk>/`). GET/POST require trust-row `change` (or membership-management authority). Create requires a `trust` the actor administers. Add-member form is hidden without authority. Include `trusts.urls` to enable. |
| Replacement | `path('', include('trusts.urls'))`. Project-settings UI stays in the example app. |
| Affected | Example #1 wired `trusts.views.team` / `newteam`. |
| Authorization | Member GET is 403. Invalid user PK does not add a member. |

Migration-bot checklist:

- [ ] Include `trusts.urls` only after granting `change_trust` to intended admins.
- [ ] Provide a `base.html` (or override the `auth/group_*.html` templates).

### 12. `Meta.auto_modeladmin` (new, milestone two)

| | |
| --- | --- |
| Previous | Core `admin.py` registered only Trust / Role / RolePermission / TrustUserPermission. |
| New | `options.DEFAULT_NAMES` includes `auto_modeladmin`. `AppConfig.ready` registers concrete `Content` / `Junction` subclasses with `auto_modeladmin = True` **only when `django.contrib.admin` is installed**. Default is False. Already-registered models are skipped. Proxy and abstract subclasses do not re-register content fieldlookups (a proxy Junction must not overwrite the concrete junction's Group lookup). |
| Replacement | `class Meta: auto_modeladmin = True` on a concrete subclass. |
| Affected | Project Content/Junction models that want admin without a local `admin.py` line. |
| Authorization | Django admin permissions still apply; this only registers the class. |

Migration-bot checklist:

- [ ] Set the flag only on concrete, non-abstract models you want in `/admin/`.
- [ ] Do not set it on `Trust` (already registered).

### 13. Schema: no `TrustGroup`

| | |
| --- | --- |
| Previous | #9 added `TrustGroup` by editing `0001_initial` and bumped the package to 0.11.0. |
| New | Implicit `Trust.groups` M2M is retained. No forward through-table migration. Package stays `1.0.0.dev0`. |
| Replacement | `trust.groups.add(group)` / `.remove(group)`. |
| Affected | Historical example #1 `TrustGroup(...)` callers. |
| Authorization | Association is per-trust. `Group.permissions` remains global (see policy note in the PR). |

Migration-bot checklist:

- [ ] Do not fake or re-run `0001_initial` to pick up a through table.
- [ ] Fresh migrate and `scripts/verify-legacy-upgrade.py` still see only `{0001_initial}`.
- [ ] Replace `TrustGroup` writes with `trust.groups.add`.

## Policy not implemented (needs Thomas)

Per-trust group permission *levels* (group G has `change` on trust A and
only `read` on trust B) and per-trust group *membership* are not in the
schema. This PR refuses to fake them with `Group.permissions` / shared
`Group.user_set` writes. A redesign (`TrustGroupPermission` or similar)
must not merge without an explicit go-ahead.

**Superseded by issue #23** for per-trust group permission *levels*.
Per-trust group *membership* remains out of scope.

## Migration-bot summary (issue #8)

- [ ] Adopt `permitted` / `grant` / `revoke` / `filter_by_user_content_perm` instead of #9 copies.
- [ ] Keep `filter_by_user_perm` and `test_filter_by_user_perm`.
- [ ] Wrap mutations with `trusts.authorization` (`change`, scoped IDs).
- [ ] Do not write `Group.permissions` from a project form.
- [ ] Do not add `TrustGroup` or edit `0001_initial`.
- [ ] Set `auto_modeladmin = True` only where you want automatic admin.
- [ ] Leave package version at `1.0.0.dev0`.

# Issue #23: fail-closed per-Trust group permission intersection (1.0.0.dev0)

This record covers the `TrustGroup` through model and the four-part AND
invariant. Version remains **1.0.0.dev0**. `trusts.0001_initial` is not
edited. Example-project UI is out of scope
(`django-trusts/django-trusts-example#5`).

## Decision

A group permission applies to Trust-controlled content only when **all**
of these facts exist:

```
effective(user, permission, trust, group) =
    user ∈ group
    AND TrustGroup(trust, group) exists
    AND permission ∈ TrustGroup.permissions
    AND permission ∈ Group.permissions
```

`Group.permissions` is the global capability **ceiling**. Role assignments
on a group participate in that ceiling; they are not per-Trust role
grants. `TrustGroup.permissions` is the locally enabled subset. Missing
membership, association, local grant, or ceiling permission denies access
(fail closed). Direct `TrustUserPermission` trustee grants are unchanged.

## No change to these public call sites

- `User.has_perm` / `User.has_perms` signatures via `TrustModelBackend`
- `trusts.decorators.permission_required`, `P`, `K`, `G`, `O`
- `Trust.objects.get_or_create_settlor_default`, `get_root`,
  `filter_by_content`, **`filter_by_user_perm`** (membership/trustee, still
  no permission name)
- `Content.grant` / `Content.revoke` (still write `TrustUserPermission`)
- `filter_by_user_content_perm` / `ContentQuerySet.permitted` signatures
- Package version `1.0.0.dev0`

Authorization **behavior** for group-derived Trust access **does** change
(see below). Trustee grants and inactive/anonymous denial do not.

## Changes

### 14. `Trust.groups` uses explicit `TrustGroup` through model

| | |
| --- | --- |
| Previous (#8) | Implicit M2M. `trust.groups.add(group)` plus `Group.permissions` (or a role on the group) granted that permission on the trust. |
| New | `through='trusts.TrustGroup'` on the same table (`trusts_trust_groups`). Association rows are preserved. `TrustGroup.permissions` (via `TrustGroupPermission`) is the local grant set and starts empty. |
| Replacement | `trust.groups.add(group)` still associates. Enable a local subset with `trust.grant_group_permission(group, permission)` or `TrustGroup.grant_permission`. `trusts.authorization.associate_group_with_trust` / `grant_trust_group_permission` wrap those writes with `change`. |
| Affected | Any caller that treated `Trust.groups.add` as a grant. |
| Authorization | Association without local tuples grants nothing. |

Migration-bot checklist:

- [ ] Apply `trusts.0002_trustgroup`. Do not edit or fake `0001_initial`.
- [ ] Confirm every previous `Trust.groups` pair still exists as a `TrustGroup` row.
- [ ] Confirm `TrustGroup.permissions` is empty after migrate (no inferred policy).
- [ ] Replace project code that assumed `groups.add` granted access with an explicit local grant.
- [ ] Do not write `Group.permissions` from a project form (`refuse_group_permission_write`).

### 15. Group-derived `has_perm` / `.permitted()` / `filter_by_user_content_perm`

| | |
| --- | --- |
| Previous | SQL and `get_all_permissions` treated `Group.permissions` and role permissions on an associated group as Trust grants. |
| New | Group-derived access requires the local/global intersection on the **same** `TrustGroup` / group. Two groups union their *effective* rights without mixing one group's local grant with another group's ceiling. Role-derived permissions are ceiling only. Incomplete or inconsistent `TrustGroupPermission` rows deny (read path still requires the ceiling JOIN/Exists). |
| Replacement | Same APIs. Direct trustee path is unchanged. |
| Affected | List views, create-under-trust pickers, team/project authorization helpers that use `has_perm` / `trust_grant_q`. |
| Authorization | Fail closed at every partial state. |

Migration-bot checklist:

- [ ] Re-run allow/deny tests for group members after migrate (expect deny until local tuples exist).
- [ ] Confirm `has_perm` and `.permitted()` still agree.
- [ ] Confirm a later add to `Group.permissions` does not enable that permission on existing Trusts until a local grant is created.

### 16. Application API and ceiling enforcement

| | |
| --- | --- |
| Previous | `trust.groups.add` / `.remove`. No local grant API. |
| New | `Trust.associate_group`, `grant_group_permission`, `revoke_group_permission`, `set_group_permissions`. `TrustGroup.grant_permission` / `revoke_permission` / `set_permissions`. Direct writes outside the ceiling raise `ValidationError` (`save`, `bulk_create`, `.permissions.add`). Actor-gated wrappers: `grant_trust_group_permission`, `revoke_trust_group_permission`, `set_trust_group_permissions`. Optional `permissions=` on `associate_group_with_trust`. |
| Replacement | Call the Trust/TrustGroup methods or authorization helpers. |
| Affected | Project settings / team UIs (example app tracks UI separately). |
| Authorization | Ceiling violations are rejected at write time and still deny at read time if a row is forced in. A rejected `grant_group_permission` / `set_group_permissions` / `associate_group_with_trust(..., permissions=...)` does not create a TrustGroup row for a previously unassociated group. |

Migration-bot checklist:

- [ ] Gate local-grant POSTs on `change`, same as associate/disassociate.
- [ ] Catch `AuthorizationDenied` / `ValidationError` when a submitted permission is not in the group's ceiling.

### 17. `grandfather_trust_group_permissions` management command

| | |
| --- | --- |
| Previous | None. Old implicit access was the default. |
| New | Operator-controlled copy of each TrustGroup's **current** global ceiling (`Group.permissions` ∪ role permissions) into `TrustGroupPermission`. Default is `--dry-run` (prints exact `trust_id` / `group_id` / `permission_id` tuples, writes nothing). `--apply` inserts. Not run from schema migration. |
| Replacement | `manage.py grandfather_trust_group_permissions --dry-run` then `--apply` only when a deployment deliberately wants former group-derived access. |
| Affected | Existing deployments that relied on implicit `Trust.groups` + `Group.permissions`. |
| Authorization | After `--apply`, former effective group access can be reproduced from the ceiling at apply time. Permissions added to the ceiling later are still not local. |

Migration-bot checklist:

- [ ] Run `--dry-run` and review the tuple list before `--apply`.
- [ ] Do not invoke this command from `0002` or `post_migrate`.
- [ ] After `--apply`, confirm a later `Group.permissions.add` still does not grant locally until a new local tuple is created.

## Old vs new behavior

| Situation | Before #23 | After `0002` (no grandfather) | After optional `--apply` |
| --- | --- | --- | --- |
| Group member + `Group.permissions` + `Trust.groups` | Allow | Deny (association kept, local empty) | Allow (local copies of then-current ceiling) |
| `Trust.groups.add` with no `Group.permissions` | Deny | Deny | Deny |
| Same group, `change` on Trust A and `read` on Trust B | Impossible (global permissions) | Expressible via local grants | Same, if those tuples were in the ceiling at apply |
| Remove global permission | Revoke everywhere | Revoke everywhere (ceiling) | Same |
| Remove local permission | N/A | Revoke that Trust only | Same |
| Add global permission later | Grant on every associated Trust | Ceiling only; local unchanged | Ceiling only; local unchanged |
| Direct `TrustUserPermission` | Unchanged | Unchanged | Unchanged |
| Role on a group associated with a Trust | Role perms granted on that Trust | Role perms are ceiling only | Local copies of those ceiling perms if `--apply` |
| Inactive / anonymous | Deny | Deny | Deny |

## Schema

- Forward migration `trusts.0002_trustgroup` only. **Do not edit `0001_initial`.**
- `SeparateDatabaseAndState` reuses `trusts_trust_groups` as `TrustGroup` (`unique_together` `(trust, group)`).
- New table `trusts_trustgrouppermission` for local tuples. Empty after migrate.
- `TRUSTS_GROUP_MODEL` and `TRUSTS_PERMISSION_MODEL` must remain `auth.Group` / `auth.Permission` (see the issue #26 section). Custom group/permission models are not supported. Swapping these settings after tables exist is not a supported upgrade.

### Fresh database

```
python -m django migrate --settings=tests.settings
```

Applies `0001_initial` then `0002_trustgroup` and creates the root trust when
`TRUSTS_CREATE_ROOT` is true.

### Upgrade of a representative legacy database

`scripts/verify-legacy-upgrade.py` now:

1. Applies Django contrib migrations only.
2. Creates Trusts tables from `scripts/legacy/trusts_0001_sqlite.sql`.
3. Records `trusts.0001_initial` as already applied.
4. Seeds organizations **and** a `Trust.groups` association.
5. Runs modern `migrate` (applies `0002_trustgroup`, does not re-run `0001`).
6. Asserts association preserved, local grants empty, group-derived access
   denied; trustee isolation still holds; grandfather `--dry-run` reports
   without mutation and `--apply` can restore former group-derived access.

```
python scripts/verify-legacy-upgrade.py
```

## Out of scope (unchanged)

- Parent/child Trust inheritance or ceilings
- Explicit deny / Windows ACL ordering
- Per-Trust group membership
- SQL compilation of **arbitrary** Python permission callbacks
  (V1 declarative conditions are compiled; see the issue #4 section)
- Local role assignment on TrustGroup
- Example-project UI

## Migration-bot summary (issue #23)

- [ ] Apply `trusts.0002_trustgroup`. Do not edit `0001_initial`.
- [ ] Expect existing `Trust.groups` associations to remain and to grant **nothing** until local tuples exist.
- [ ] Review `manage.py grandfather_trust_group_permissions --dry-run` if you want former implicit access; `--apply` only with an explicit operator decision.
- [ ] Stop treating `trust.groups.add` as a grant; use `grant_group_permission` / authorization helpers.
- [ ] Keep `Group.permissions` and roles as the global ceiling; grant per-Trust subsets on `TrustGroup`.
- [ ] Reload user objects after grant changes (`_trust_perm_cache`).
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] Example UI is a separate issue; do not block this core change on it.

# Issue #4: queryable V1 permission conditions (1.0.0.dev0)

This record covers the first queryable-condition experiment. Version
remains **1.0.0.dev0**. It does **not** close #4 (arbitrary callbacks,
cross-language serialization, and a policy service remain open).

## Decision

A permission condition is a **restricted declarative expression**, not
source/bytecode parsing and not arbitrary Python execution. Callers
build a language-neutral ``Expr`` tree from ``condition_refs()``
(``u``, ``p``, ``o``) and register that object. Django ``Q`` is one
compiler target. Callables keep an object-only path when
``TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS`` is True (see issue #29)
and are never invoked with symbolic refs.

V1 grammar: principal/object field refs and relationship traversal;
literal constants; ``==`` / ``!=``; nested ``&`` / ``|``.

## No change to these public call sites

- `User.has_perm('app.change_model:cond', obj)` signature
- `ContentQuerySet.permitted(perm, user)` signature
- `filter_by_user_perm` / `filter_by_user_content_perm` signatures
- Package version `1.0.0.dev0`

`Content.register_permission_condition(model, code, condition)` still
accepts a callable. Passing an ``Expr`` is the new queryable form.
Issue #29 disables callables unless
``TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS`` is True.

## Changes

### 18. V1 declarative conditions are queryable on `.permitted()`

| | |
| --- | --- |
| Previous | Any ``:condition`` suffix on `.permitted()` raised ``PermissionConditionNotQueryable``. Conditions were Python predicates on ``has_perm`` only. |
| New | If the registered value is an ``Expr`` tree, `.permitted()` filters ``trust_grant_q AND compiled condition`` in SQL before pagination. ``has_perm`` evaluates the same tree. Nested ``&`` / ``|`` keep grouping. Object field paths are validated against the target model. |
| Replacement | Register ``(u == o.owner) | ...`` from ``condition_refs()``, then ``Model.objects.permitted('app.change_model:editable', user)``. Keep ``has_perm`` per object for callables. |
| Affected | List views that previously caught ``PermissionConditionNotQueryable`` for ``:own``-style field equality. ``Trust``'s built-in ``own`` is registered as ``u == o.settlor``. |
| Authorization | A condition still never grants the base permission. Inactive/anonymous stay empty. Unsupported or malformed expressions fail closed (specific exception); the underlying grant is not returned. |

Migration-bot checklist:

- [ ] Replace Python ``[obj for obj in qs if user.has_perm('app.change_model:cond', obj)]`` with ``.permitted('app.change_model:cond', user)`` **only** when the condition is a registered ``Expr``.
- [ ] Convert V1 lambdas to ``u, p, o = condition_refs()`` plus ``register_permission_condition(..., expr)``. A lambda that looks like V1 stays object-only.
- [ ] Do not use Python ``and`` / ``or`` when building expressions; use ``&`` / ``|``. Construction raises ``PermissionConditionBooleanError``.
- [ ] Keep catching ``PermissionConditionNotQueryable`` for callables.
- [ ] Do not pass ``:condition`` to ``filter_by_user_content_perm`` (still refused: that API filters Trust rows).
- [ ] Confirm ``has_perm`` and ``.permitted()`` agree for each registered ``Expr``.
- [ ] Leave package version at ``1.0.0.dev0``.

### 20. ``parse_perm_code`` partitions ``:condition`` before the last ``_``

| | |
| --- | --- |
| Previous | ``app.change_ticket:python_or`` parsed the condition as empty because ``rsplit('_')`` ran first. |
| New | Colon is partitioned first; condition codes may contain underscores. |
| Replacement | Same ``app.action_model:cond`` strings. |
| Affected | Condition names with ``_``. Unconditioned codes are unchanged. |
| Authorization | Lookup only. |

### 21. Principal field paths fail closed (review on #28)

| | |
| --- | --- |
| Previous (this PR head) | Unvalidated ``u.attr`` plus ``except Exception: return None`` treated a misspelled principal attribute as ``None``, matching nullable object fields. |
| New | Principal paths are resolved against ``TRUSTS_ENTITY_MODEL`` ``_meta`` (same FK/O2O rules as object paths). Missing names raise ``PermissionConditionError`` on ``has_perm`` and ``.permitted()``. Legitimate nullable relations still compare as ``None``. Python properties are not executed. |
| Replacement | Keep ``u == o.owner``. Use ``u.username`` only when that column exists on the entity model. |
| Affected | V1 conditions that traversed an unvalidated user attribute. |
| Authorization | Fail closed. A typo cannot grant NULL-region rows. |

### 22. Permission paths and terminal multi-valued relations fail closed (review on #28)

| | |
| --- | --- |
| Previous | Non-empty ``p.*`` was not part of the advertised V1 grammar. Terminal ``ManyToManyField`` / reverse one-to-many compiled to Django SQL membership while Python compared a manager to the right-hand value, so ``has_perm`` and ``.permitted()`` diverged. |
| New | Every non-empty permission path raises ``PermissionConditionError``. Terminal (and intermediate) M2M and reverse one-to-many refs raise on both paths. Membership is not defined in V1. |
| Replacement | Keep ``u == o.owner``. Do not write ``p.codename`` or ``o.owner.groups == group``. |
| Affected | V1 conditions that traversed ``p`` or a multi-valued relation. |
| Authorization | Fail closed. ``p.codenmae == None`` cannot become always-true. ``o.owner.groups == group`` cannot list-allow while object-deny. |

### 19. Arbitrary callbacks remain object-only

| | |
| --- | --- |
| Previous | Every condition was object-only. |
| New | Callables still run in ``has_perm`` with real arguments only (never ``Ref``s). Queryset use raises ``PermissionConditionNotQueryable``. Issue #29 disables this path unless ``TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS`` is True. |
| Replacement | Same as #8 for those callbacks. |
| Affected | Custom ``lambda u, p, o: False`` / method-call predicates. |
| Authorization | Fail closed on lists. |

### 23. Registered expression objects (option 4 on #28)

| | |
| --- | --- |
| Previous (this PR before option 4) | Every registered callback was probed with symbolic ``Ref``s. Legacy ``or`` callbacks ran twice on ``has_perm``; I/O before an unsupported op ran at compile time. |
| New | ``register_permission_condition`` dispatches by type. An ``Expr`` is queryable policy data. A callable is object-only and is never invoked with ``Ref``s. ``Trust`` ``:own`` is ``u == o.settlor``. ``django_trusts.Query`` / ``TQ`` is reserved for later lookups; V1 does not implement them. |
| Replacement | ``u, p, o = condition_refs()`` then register the ``Expr``. Leave existing lambdas unchanged for object-only ``has_perm``. |
| Affected | Any project that expected auto-discovery of V1 lambdas. Those lambdas stay object-only until rewritten as ``Expr``. |
| Authorization | Fail closed on lists for callables. Invalid ``Expr`` trees fail on both paths. |

Migration-bot checklist:

- [ ] Rewrite queryable conditions as ``Expr`` objects; do not add ``queryable=True``.
- [ ] Do not wrap arbitrary callbacks as expressions; they will fail closed on ``has_perm`` if they are not V1 predicates.
- [ ] Confirm callables are invoked once with real objects on ``has_perm``, never during registration or ``.permitted()``.

### 24. Incompatible ``Eq`` / ``Ne`` operands fail closed (review on #28)

| | |
| --- | --- |
| Previous (this PR head) | ``o.status == 1`` compiled to ``Q(status=1)``; Django coerced the int through ``CharField`` so ``.permitted()`` matched ``"1"`` while ``has_perm`` used Python ``"1" == 1`` (false). ``o.owner == "1"`` similarly coerced through the FK. ``Ne`` diverged in the opposite direction. |
| New | V1 compares Python types, not Django lookup-prepared values. ``CharField`` vs ``int`` and a relation vs a raw PK raise ``PermissionConditionError`` on both paths. ``None`` remains valid. Related instances and same-type scalars still match. |
| Replacement | Write ``o.status == "1"`` and ``u == o.owner`` (or ``o.owner == user``). Do not rely on Django coercing ``1`` or ``"1"``. |
| Affected | V1 conditions that mixed a field with a differently typed literal. |
| Authorization | Fail closed. Django backend coercion is not canonical V1 semantics. |

Migration-bot checklist:

- [ ] Replace ``o.char_field == 1`` with a string literal if the comparison was intentional.
- [ ] Replace ``o.fk == pk`` with a model instance comparison.
- [ ] Confirm ``has_perm`` and ``.permitted()`` still agree after the type check.

## Noted conflict (no broader DSL)

Queryable compile is **opt-in by type**. Callables are never invoked with
``Ref`` values. Building an expression with Python ``and`` / ``or`` /
``if`` or a chained comparison such as ``0 < o.amount < 100`` raises
``PermissionConditionBooleanError`` at construction. No source/bytecode
parser. Ordering comparisons are not in V1 (do not treat
``(o.amount > 0) & (o.amount < 100)`` as supported).

Object paths are validated against the content model's ``_meta`` fields.
Principal paths are validated against ``TRUSTS_ENTITY_MODEL`` /
``AUTH_USER_MODEL`` the same way. A missing or misspelled attribute
raises ``PermissionConditionError`` on both ``has_perm`` and
``.permitted()``; it is never collapsed to ``None`` (which would match
a nullable object field). Python ``@property`` access is not a V1 field
path and is not executed during compile or evaluation. Arbitrary user
properties remain a decision for a later issue, not an implicit grant.

``filter_by_user_content_perm`` is not a content-row filter; compiling a
content-model condition against Trust rows would change that surface.
It still rejects every ``:condition`` suffix.

## Out of scope (not acceptance criteria)

- Cross-language serialization / policy service / multi-language framework
- Closing #4 for arbitrary Python callbacks
- Arithmetic, calls, indexing, ``not``, ordering comparisons, ``TQ`` lookups

# Issue #29: validate declarative permission expressions before request time (1.0.0.dev0)

This record covers Django system-check validation of registered ``Expr``
conditions and the explicit legacy-callback compatibility flag. Version
remains **1.0.0.dev0**. It closes the #29 slice; it does **not** close #4
(arbitrary callbacks, serialization, policy service). It does **not**
raise from ``AppConfig.ready()``.

## Decision

Invalid registered ``Expr`` policy is reported by Django's system-check
framework (`python manage.py check`) as ``checks.Error`` messages with
stable IDs. Construction-time operator/rejection errors from #28 stay
exceptions. Model-aware semantic validation is **not** thrown from
registration or import — including after ``apps.models_ready`` — so
``SILENCED_SYSTEM_CHECKS`` can filter the diagnostic. Silencing an ID
does not make the policy executable: ``has_perm()`` / ``.permitted()``
still validate and fail closed.

Legacy callables are opt-in:

```python
TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS = True  # opt-in escape hatch
```

Missing / ``False`` (default): registered callables are ``trusts.E002``
and remain runtime-fail-closed (the callback is never invoked). ``True``:
#28 object-only ``has_perm`` behavior; ``.permitted()`` still refuses
them; ``trusts.W001`` is emitted as a ``checks.Warning`` (not
``DeprecationWarning``, which is commonly filtered). Enabling the flag
is the only way to run the callback.

## No change to these public call sites

- `User.has_perm` / ``ContentQuerySet.permitted`` signatures
- ``Content.register_permission_condition(model, code, condition)`` signature
- Authentication-backend composition (OR across backends is unchanged)
- Package version `1.0.0.dev0`

## Changes

### 25. Registered ``Expr`` conditions are reported by ``manage.py check``

| | |
| --- | --- |
| Previous (#28) | Invalid field names, traversal, multi-valued relations, and operand types raised ``PermissionConditionError`` on first ``has_perm`` / ``.permitted()`` use. |
| New | The same ``validate_expression`` runs in a registered Django system check (``trusts.E001``) after models load. Every invalid condition is aggregated in one run. ``class_prepared`` registrations retain ``(model, code, Expr)`` identity so they can be checked without importing extra application modules or assuming ``trusts`` loads after the entity-model app. ``AppConfig.ready()`` does not raise. |
| Replacement | Keep registering ``Expr`` objects. Run ``python manage.py check`` in CI and before deploy. |
| Affected | ``Meta.permission_conditions`` and dynamic ``register_permission_condition`` of ``Expr`` values. |
| Authorization | Runtime still fail-closed. Silencing ``trusts.E001`` hides the diagnostic only. |

Migration-bot checklist:

- [ ] Add ``python manage.py check`` to CI and the deploy gate.
- [ ] Fix ``trusts.E001`` messages (unknown fields, multi-valued relations, incompatible ``Eq``/``Ne`` operands) before serving traffic.
- [ ] Do not rely on ``SILENCED_SYSTEM_CHECKS = ['trusts.E001']`` to make a bad expression executable.
- [ ] Confirm valid ``Trust:own``, custom content ``Expr``s, proxy models, and cross-app FK/O2O registrations still load.
- [ ] Leave package version at ``1.0.0.dev0``.

### 26. Legacy callable conditions require an explicit opt-in

| | |
| --- | --- |
| Previous (#28) | A callable argument was object-only ``has_perm`` by default; ``.permitted()`` raised ``PermissionConditionNotQueryable``. Callables were never invoked with ``Ref``s. |
| New | Missing / ``False`` (default): ``trusts.E002`` and runtime ``PermissionConditionError`` without invoking the callable. ``True``: previous object-only ``has_perm`` behavior plus ``trusts.W001``. ``.permitted()`` still refuses callables. Declarative ``Expr`` registrations are unaffected. Checks never inspect or invoke callables. |
| Replacement | Rewrite callables as ``Expr`` from ``condition_refs()``. Set ``TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS = True`` only as a transitional escape hatch. |
| Affected | ``lambda u, p, o: ...`` and other callable registrations. |
| Authorization | Fail closed. Silencing ``trusts.E002`` does not enable the callback. |

Migration-bot checklist:

- [ ] Inventory ``register_permission_condition(..., callable)`` and ``Meta.permission_conditions`` callables.
- [ ] Rewrite V1-shaped callables as ``u, p, o = condition_refs()`` plus an ``Expr``.
- [ ] If a callable cannot be rewritten yet, set ``TRUSTS_ALLOW_LEGACY_PERMISSION_CALLBACKS = True`` and treat ``trusts.W001`` as a visible deprecation.
- [ ] Do not silence ``trusts.E002`` expecting the callback to run.
- [ ] Confirm ``.permitted()`` still raises ``PermissionConditionNotQueryable`` for remaining callables.
- [ ] Leave package version at ``1.0.0.dev0``.

## Old vs new behavior

| Situation | After #28 | After #29 |
| --- | --- | --- |
| Valid ``Trust:own`` / custom ``Expr`` | Runtime validate | ``manage.py check`` passes; runtime still validates |
| Misspelled field / bad operand type | Fail on first request | ``trusts.E001`` at check; runtime still raises |
| ``SILENCED_SYSTEM_CHECKS`` includes ``trusts.E001`` | n/a | Check passes; ``has_perm`` / ``.permitted()`` still raise |
| Callable, flag missing/False | Object-only ``has_perm`` | ``trusts.E002``; runtime raises; callback not invoked |
| Callable, flag True | Object-only ``has_perm`` | ``trusts.W001``; object-only ``has_perm``; ``.permitted()`` still refuses |
| ``AppConfig.ready()`` with invalid ``Expr`` | n/a (no early check) | Does not raise; ``manage.py check`` reports |
| Python ``and`` / ``or`` / calls at construction | Exception | Unchanged exception |

## Out of scope (not acceptance criteria)

- Raising from ``AppConfig.ready()`` to block shell/migrations
- A custom ``manage.py`` command parallel to ``check``
- Authentication-backend composition / multi-backend OR semantics
- Closing #4 for arbitrary Python callbacks

# Issue #25: dependent-content Trust resolution (1.0.0.dev0)

This record covers relational reuse of one Trust through related
non-Content rows. Version remains **1.0.0.dev0**. **No Trusts schema
migration is required.** Test fixtures add `trusts_tests` models only
(`0003_receipt`).

## Decision

A dependent model does not carry a `trust` FK. Its authorizing Trust is
the related `Content` object's Trust, reached by an ORM lookup from
`Trust`. `Content.get_content_fieldlookup` returns that lookup as a
composable string for every registered model. Direct `Content` subclasses
resolve to the reverse of `Content.trust` (`app_label_model_content`),
never `None`. One- and two-hop dependents register with
`Content.compose_content_fieldlookup(parent, related_name)`.

This is not parent/child permission ceilings, explicit deny, delegation,
or Windows ACL inheritance. Granting `change_receipt` does not grant
`change_receiptimage` on the same Trust.

## No change to these public call sites

- `User.has_perm` / `User.has_perms` signatures
- `Trust.objects.filter_by_content(obj)` signature (instance or QuerySet)
- `Content.register_content(klass, fieldlookup=None)` signature
- Package version `1.0.0.dev0`

## Changes

### 27. `get_content_fieldlookup` returns a resolved lookup

| | |
| --- | --- |
| Previous | Direct `Content` subclasses stored `None`. `'%s__image' % Content.get_content_fieldlookup(Receipt)` produced `None__image`. |
| New | Registered models store a string. `get_content_fieldlookup` returns that string, or `direct_content_fieldlookup(klass)` if a legacy `None` is still stored. Unregistered models still return `None`. |
| Replacement | `Content.get_content_fieldlookup(Receipt)` → `'app_receipt_content'`. Compose with `compose_content_fieldlookup` or interpolate the returned string. |
| Affected | Callers that treated `None` as "this is a direct Content model". Use `is_content_model` plus a lookup that equals `direct_content_fieldlookup` if that distinction is still needed. |
| Authorization | Same Trust rows. Lookups are no longer built from `None`. |

Migration-bot checklist:

- [ ] Replace `'%s__hop' % Content.get_content_fieldlookup(parent)` with `Content.compose_content_fieldlookup(parent, 'hop')` (safer if `parent` is unregistered).
- [ ] If you compared `get_content_fieldlookup(klass) is None` to detect a `Content` subclass, compare to `Content.direct_content_fieldlookup(klass)` or inspect the model.
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] No Trusts migrate step. Do not edit `0001_initial` or `0002_trustgroup`.

### 28. `compose_content_fieldlookup` and fail-closed registration

| | |
| --- | --- |
| Previous | RST documented string interpolation of a possibly-`None` lookup. Invalid paths were not rejected at register time. A scalar hop such as `compose(Receipt, 'title')` was accepted; if `receipt.title == str(note)`, Django coerced the instance and `filter_by_content` / `has_perm` could grant the receipt's Trust. |
| New | `Content.compose_content_fieldlookup(klass, related_name)` joins one reverse hop. Unregistered parent → `AttributeError`. Empty / multi-hop `related_name` → `ValueError`. A named scalar field → `InvalidContentFieldlookup`. `register_content` rejects empty lookups, `None__…` paths, non-relation hops, and paths whose terminal model is not the registered class. Missing registration: `has_perm` denies, `filter_by_content` is empty. Relation-path validation may defer until `apps.models_ready`; `filter_by_content` / `has_perm` call `require_valid_content_fieldlookup` and raise rather than query an invalid registration. |
| Replacement | Register `ReceiptImage` / `ReceiptImageMeta` as in the RST Dependent content section. Catch `InvalidContentFieldlookup` (a `ValueError`) for bad hops. |
| Affected | Manual `register_content` of non-Content models. Junction auto-registration still passes an explicit relation path. |
| Authorization | Fail closed. Invalid or missing registration never broadens access, including scalar-field coercion. |

Migration-bot checklist:

- [ ] Register each dependent hop; do not leave related models implicit.
- [ ] Use a relation `related_name`, not a scalar field, as the hop.
- [ ] Confirm `has_perm` at the Content row and each dependent hop.
- [ ] Confirm `filter_by_content` accepts an instance and a QuerySet.
- [ ] Confirm a forced scalar lookup raises on `filter_by_content` and `has_perm`.
- [ ] Do not implement parent/child ceilings or per-object Python loops.

## Out of scope (unchanged)

- Parent/child Trust permission ceilings
- Explicit deny / Windows ACL ordering
- Delegation
- `.permitted()` on non-Content dependent models (they have no `trust` FK)
- Example-app UI (core fixtures are sufficient)

# Issue #26: advertised custom model support (1.0.0.dev0)

This record covers the end-to-end verification of `TRUSTS_ENTITY_MODEL`,
`TRUSTS_GROUP_MODEL`, and `TRUSTS_PERMISSION_MODEL`. Version remains
**1.0.0.dev0**. Isolated core tests were sufficient; no example-app change.
Historical `0001_initial` is not rewritten.

## Decision

Django does not swap `auth.Group` or `auth.Permission`. Ticket
[#29748](https://code.djangoproject.com/ticket/29748) (`AUTH_GROUP_MODEL`)
reached an implementation PR and was closed `wontfix` in April 2024.
The [Django Internals discussion](https://forum.djangoproject.com/t/custom-group-model/30070)
concluded that Group swappability adds disproportionate migration and
ecosystem complexity. There is no active official `AUTH_PERMISSION_MODEL`.

Verified contract:

- Support custom `AUTH_USER_MODEL`.
- `TRUSTS_ENTITY_MODEL`, while it exists, must resolve to
  `AUTH_USER_MODEL` (`trusts.E003`). A separate non-user model is not a
  Django permission principal. Silencing `trusts.E003` does not authorize
  that path: grants raise and `has_perm` / `.permitted()` deny, including
  group-derived object-level evaluation.
- Use standard `auth.Group` and `auth.Permission`. Values other than
  those models are `trusts.E004` / `trusts.E005`. Silencing those IDs
  does not route grants or queries through another model. django-trusts
  does not maintain a private parallel swappability contract for
  Group/Permission. Deprecation and the 1.1.0 removal of the unused
  settings are [#33](https://github.com/django-trusts/django-trusts/issues/33)
  (see the issue #33 section below).

An experiment that treated `TRUSTS_GROUP_MODEL` /
`TRUSTS_PERMISSION_MODEL` as swappable replacements (convention-shaped
custom group/permission models, Role `AlterField` retarget, permission
row copy) is a **negative architectural result**, not supported behavior.
That work is not shipped. Deprecation and the 1.1.0 removal of the unused
settings are [#33](https://github.com/django-trusts/django-trusts/issues/33).
Trust-scoped Role/Group assignment semantics are
[#34](https://github.com/django-trusts/django-trusts/issues/34).

## No change to these public call sites

- `User.has_perm` / `ContentQuerySet.permitted` signatures
- `Content.grant` / `Content.revoke` signatures
- TrustGroup / authorization helper signatures
- `update_roles_permissions` command name
- Package version `1.0.0.dev0`

## Changes

### 29. Custom user is the supported entity swap; Group/Permission stay auth

| | |
| --- | --- |
| Previous | RST advertised three model settings. Role schema in `0001_initial` hardcoded `auth.Group` / `auth.Permission` while `models.py` used the settings. There was no fresh-install proof. |
| New | Isolated suite `python -m tests.runtests_custom` migrates with custom `AUTH_USER_MODEL` / matching `TRUSTS_ENTITY_MODEL` selected before migrate. Settlor and trustee FKs target the custom user table. Group, Permission, Role, and TrustGroup stay `auth.Group` / `auth.Permission`. System checks `trusts.E003`–`E005` report a non-user entity or a non-auth group/permission model (lookup failures keep their own IDs). Runtime grants and authorization queries fail closed even when those IDs are silenced. Mismatched model instances fail closed (`ValidationError` / `AuthorizationDenied`); PKs are not taken from the wrong class. |
| Replacement | Set `AUTH_USER_MODEL` and `TRUSTS_ENTITY_MODEL` to the same custom user **before** the first migrate. Leave `TRUSTS_GROUP_MODEL` / `TRUSTS_PERMISSION_MODEL` unset. |
| Affected | Projects that set `TRUSTS_GROUP_MODEL` / `TRUSTS_PERMISSION_MODEL` to something other than `auth.Group` / `auth.Permission` now fail `manage.py check`. Runtime still refuses the discarded path if the check is skipped or silenced. That combination was never a coherent Django swap. |
| Authorization | Object-level paths use `AUTH_USER_MODEL` for the principal and `auth.Group` / `auth.Permission` for group ceiling and Role. No fallback to a parallel group/permission table. Silencing `trusts.E003`–`E005` does not enable those settings. |

Migration-bot checklist:

- [ ] Keep `TRUSTS_ENTITY_MODEL` equal to `AUTH_USER_MODEL`.
- [ ] Leave `TRUSTS_GROUP_MODEL` / `TRUSTS_PERMISSION_MODEL` as `auth.Group` / `auth.Permission` (or unset).
- [ ] Do not apply or expect `trusts.0003_role_configured_models`. Historical `0001_initial` is unchanged (no extra configured-app graph dependencies; Role stays `auth.*`).
- [ ] Do not pass a non-user instance into trustee APIs, or a non-`auth.Group` / non-`auth.Permission` instance into TrustGroup/Role APIs.
- [ ] Do not treat `SILENCED_SYSTEM_CHECKS = ['trusts.E003']` (or E004/E005) as enabling a discarded model; runtime still refuses grants and queries.
- [ ] Run `python -m tests.runtests` (default models) and `python -m tests.runtests_custom` (fresh custom user).
- [ ] Run `python scripts/verify-legacy-upgrade.py`.
- [ ] Run `python -m django check`.
- [ ] Leave package version at `1.0.0.dev0`.

## Fresh database

```
python -m django migrate --settings=tests.settings
python -m django migrate --settings=tests.custom_settings
```

Default settings apply `0001`–`0002` against `auth.User` / `auth.Group` /
`auth.Permission`. Custom settings select `AUTH_USER_MODEL` /
`TRUSTS_ENTITY_MODEL` **before** migrate; Group and Permission remain
`auth.*`. `0001` already depends on `AUTH_USER_MODEL`, so the custom
user app migrates first.

## Upgrade of a representative legacy database

`scripts/verify-legacy-upgrade.py` expects pending `0002_trustgroup`
after recording `0001_initial`, then `{0001_initial, 0002_trustgroup}`
after migrate. Role FKs stay on `auth.*`. No Role retarget migration.

## Out of scope (unchanged)

- Making Django `auth.Group` / `auth.Permission` swappable
- Using `TRUSTS_ENTITY_MODEL` as a non-user principal
- Trust-scoped Role/Group assignment semantics (#34)
- Example-app UI
- Rewriting historical `0001_initial` field targets or adding a Role
  retarget migration
- Removing `TRUSTS_GROUP_MODEL` / `TRUSTS_PERMISSION_MODEL` before 1.1.0
  (deprecation is the issue #33 section below)

# Issue #33: deprecate TRUSTS_GROUP_MODEL / TRUSTS_PERMISSION_MODEL (1.0.0.dev0)

This record deprecates the unused Group/Permission settings in the 1.0
line. Version remains **1.0.0.dev0**. Isolated core tests were
sufficient; no example-app change. Historical `0001_initial` is not
rewritten. The discarded PR #32 custom Group/Permission migration
workaround is not restored.

## Deprecation plan

| Release | Status |
| --- | --- |
| **1.0.0.dev0 / 1.0** | `TRUSTS_GROUP_MODEL` and `TRUSTS_PERMISSION_MODEL` are deprecated. They do not select a model. Field targets, getters, and runtime Group/Permission stay `auth.Group` / `auth.Permission`. |
| **1.1.0** | Proposed removal release. The settings will be ignored no longer as a contract: `getattr` / `is_overridden` support and `trusts.W002` / `W003` go away. A leftover setting should then be an ordinary unused Django setting or a later hard error, decided at removal time. |

`AUTH_USER_MODEL` (with matching `TRUSTS_ENTITY_MODEL`) remains the only
supported principal swap.

## Decision

Django does not swap `auth.Group` or `auth.Permission`. Leaving decorative
settings that worked in only some authorization paths hid that boundary.
`get_group_model()` / `get_permission_model()` now always return
`auth.Group` / `auth.Permission`. `GROUP_MODEL_NAME` /
`PERMISSION_MODEL_NAME` are pinned to those labels so historical
migrations that import the names reconstruct the supported field graph
without editing `0001_initial` or `0002_trustgroup`.

A leftover setting still fail-closes when it names anything other than
the standard model (`trusts.E004` / `E005`, including when silenced).
An explicit setting that already names `auth.Group` / `auth.Permission`
is `trusts.W002` / `trusts.W003`. Unset remains the supported default
and emits neither.

The `hasattr(manager, 'get_by_natural_key')` fallback in
`resolve_content_permission` existed only to tolerate a non-Django
Permission manager. It is retired. Resolution uses
`auth.Permission.objects.get_by_natural_key`.

Team views bind `django.contrib.auth.models.Group` directly.

## Migration-state compatibility (no stop)

Supported installs (settings unset, or set to `auth.Group` /
`auth.Permission`) already applied `0001` / `0002` against `auth.*`.
Pinning the imported names does not change reconstructed state.

`0001_initial` Role fields were already hardcoded `auth.Group` /
`auth.Permission`. Trust.groups / TrustUserPermission.permission /
TrustGroup / TrustGroupPermission imported `GROUP_MODEL_NAME` /
`PERMISSION_MODEL_NAME`, which defaulted to `auth.*` on every supported
install.

**Unsupported leftover:** if a project applied `0001` / `0002` while
`TRUSTS_GROUP_MODEL` / `TRUSTS_PERMISSION_MODEL` named a custom model,
Django's reconstructed state will now say `auth.*` while physical FKs
might still name that custom table. That configuration was never a
coherent Django swap (E004 / E005 + fail-closed; the #26 experiment was
discarded). This PR does not invent a conversion or Role retarget
migration. Unset the settings. If a database actually has non-auth
Group/Permission FKs, that is an unsupported state to raise in review —
not a migration we ship.

No historical migration file is edited.

## No change to these public call sites

- `User.has_perm` / `ContentQuerySet.permitted` signatures
- `Content.grant` / `Content.revoke` signatures
- TrustGroup / authorization helper signatures
- `update_roles_permissions` command name (still uses `auth.Permission`)
- Package version `1.0.0.dev0`
- Historical `0001_initial` / `0002_trustgroup` file contents

## Changes

### 30. Deprecated Group/Permission settings; runtime stays auth.*

| | |
| --- | --- |
| Previous | `TRUSTS_GROUP_MODEL` / `TRUSTS_PERMISSION_MODEL` selected `GROUP_MODEL_NAME` / `PERMISSION_MODEL_NAME` and `get_*_model()`. Non-auth values were `trusts.E004` / `E005` and fail-closed at runtime. Field `to=` followed the setting at import time. |
| New | Settings are deprecated in 1.0 and scheduled for removal in **1.1.0**. `GROUP_MODEL_NAME` / `PERMISSION_MODEL_NAME` and the getters are pinned to `auth.Group` / `auth.Permission`. An explicit standard value is `trusts.W002` / `W003`. Any other value remains `trusts.E004` / `E005` and still fail-closes. `resolve_content_permission` uses `auth.Permission.objects.get_by_natural_key` only. |
| Replacement | Leave both settings unset. Use `AUTH_USER_MODEL` / `TRUSTS_ENTITY_MODEL` for a custom principal. Use `django.contrib.auth.models.Group` and `Permission`. |
| Affected | Projects that set either setting: `manage.py check` warns (standard value) or errors (any other value). Runtime Group/Permission do not follow the setting. Projects that never set them are unchanged. |
| Authorization | Object-level paths keep using `AUTH_USER_MODEL` for the principal and `auth.Group` / `auth.Permission` for group ceiling and Role. No fallback to a parallel group/permission table. Silencing `trusts.E004` / `E005` still refuses grants and `group__user` queries. Default installations and existing standard Group/Permission data are unchanged. Role/TrustGroup semantics are unchanged (#34 owns that). |

Migration-bot checklist:

- [ ] Unset `TRUSTS_GROUP_MODEL` and `TRUSTS_PERMISSION_MODEL`.
- [ ] Keep `TRUSTS_ENTITY_MODEL` equal to `AUTH_USER_MODEL` when using a custom user.
- [ ] Do not treat `get_group_model()` / `get_permission_model()` as a swap point; they return `auth.Group` / `auth.Permission`.
- [ ] Do not apply or expect `trusts.0003_role_configured_models`. Historical `0001_initial` is unchanged.
- [ ] Do not restore the discarded custom Group/Permission migration workaround from PR #32.
- [ ] Confirm `manage.py check` is clean on the default contract (no `trusts.E004` / `E005` / `W002` / `W003`).
- [ ] Confirm an explicit `auth.Group` / `auth.Permission` setting reports `trusts.W002` / `W003` and names 1.1.0.
- [ ] Confirm a non-standard setting reports `trusts.E004` / `E005` and still fail-closes when silenced.
- [ ] Run `python -m tests.runtests` (default models, including issue #33).
- [ ] Run `python -m tests.runtests_custom` (custom user + standard Group + standard Permission).
- [ ] Run `python -m django migrate --settings=tests.settings` and `--settings=tests.custom_settings`.
- [ ] Run `python scripts/verify-legacy-upgrade.py`.
- [ ] Run `python -m django check`.
- [ ] Leave package version at `1.0.0.dev0`.

## Fresh database

```
python -m django migrate --settings=tests.settings
python -m django migrate --settings=tests.custom_settings
```

Default settings apply `0001`–`0002` against `auth.User` / `auth.Group` /
`auth.Permission`. Custom settings select `AUTH_USER_MODEL` /
`TRUSTS_ENTITY_MODEL` **before** migrate; Group and Permission remain
`auth.*`. Do not set `TRUSTS_GROUP_MODEL` / `TRUSTS_PERMISSION_MODEL`.

## Upgrade of a representative legacy database

`scripts/verify-legacy-upgrade.py` still expects pending `0002_trustgroup`
after recording `0001_initial`, then `{0001_initial, 0002_trustgroup}`
after migrate. Role FKs stay on `auth.*`. No new Trusts migration.
Standard Group/Permission rows are unchanged.

## Out of scope (unchanged)

- Making Django `auth.Group` / `auth.Permission` swappable
- Redesigning Role / TrustGroup semantics (#34)
- Rewriting historical `0001_initial`
- Restoring PR #32's discarded custom Group/Permission workaround
- Example-app UI
- Removing the settings before the named 1.1.0 release

# Issue #39: registry-driven Context resolution contract (1.0.0.dev0)

This record covers the first additive Context-extraction slice. Version
remains **1.0.0.dev0**. **No Trusts schema migration is required.** Test
fixtures add `trusts_tests` models only (`0004_context_contract`). This
PR does **not** close
[#39](https://github.com/django-trusts/django-trusts/issues/39); review
owns that. Trustee extraction is
[#40](https://github.com/django-trusts/django-trusts/issues/40). A
separate `django-trusts-core` distribution is not created here.

## Decision

The reusable question is: starting from this resource model, what
validated relational path resolves its authorization scope? That
contract lives in `trusts.context` and must not name `Trust`, `Content`,
or `Junction`.

Two registration forms:

```python
from trusts.context import Context

Context.register_direct(ResourceModel, scope_field="scope")
Context.register_related(RelatedModel, through="document")
```

- **Direct:** the resource owns a single-valued relationship to its
  policy scope.
- **Related:** the resource reaches an already registered resource
  through a validated, single-valued relational path and therefore
  resolves the same scope. Multi-hop paths are allowed when every hop
  is relational and single-valued. Many-valued hops are out of this
  slice (they need an explicit future all/any policy).

Registration is static during Django application loading. The map
freezes before the first authorization query and before
`manage.py check`. Validation uses Django `_meta` only: no getters,
descriptors, properties, or callbacks. Missing, cyclic, ambiguous,
scalar, many-valued, or wrong-terminal paths fail closed
(`ContextRegistrationError`) and are reported as `trusts.E006` if a
stale adapter remains. Direct exists-checks and list filters share the
same registered lookup (`Context.scope_path` / `Context.filter_by_scope`
/ `Context.resolves_to_scope`) and stay one SQL query each.

django-trusts conveniences route through that map and keep their
observable 1.x behavior:

- `Content` is the direct-Context convenience (`scope_field='trust'`).
- Dependent `Content.register_content(..., fieldlookup)` is the related
  form (the Trust-origin lookup is inverted to a resource-origin
  `through`).
- `Junction` remains a public abstract class
  (`from trusts.models import Junction`). Auto-registration registers
  the junction table as a direct Context and the wrapped model as a
  related Context. The wrapped model stays the public content
  registration. Existing concrete junction tables and migrations are
  unchanged.

`Junction` is **not** removed in 1.x and this slice does **not** emit a
runtime deprecation warning (that would be a behavior/noise change).
New dependents should use `Context.register_related`. `Junction`
remains the compatibility wrapper for models you do not own.

## No change to these public call sites

- `User.has_perm` / `User.has_perms` signatures
- `ContentQuerySet.permitted(perm, user)` signature
- `Trust.objects.filter_by_content(obj)` signature
- `Content.register_content(klass, fieldlookup=None)` signature
- `from trusts.models import Junction` and `Junction` subclassing
- Package version `1.0.0.dev0`
- Historical `0001_initial` / `0002_trustgroup` file contents

Authorization **behavior** is unchanged. `Content.objects.permitted`
now reads `Context.scope_path(model)` instead of a hardcoded `'trust'`
string; for every current Content subclass that path is still `'trust'`.

## Changes

### 31. `trusts.context.Context` registry (new)

| | |
| --- | --- |
| Previous | Content / dependent / Junction registration stored Trust-origin lookups on `Content._contents` only. |
| New | Abstract/model-free `Context.register_direct` / `Context.register_related`. `Context.adapters()` is the complete deterministic set. `Context.add_finalizer` runs pending integration work once before every freeze (`filter_by_scope` / `resolves_to_scope` / `prepare_context_registry`). After freeze, every public path (`Content.register_content`, `Junction.register_junction`, `Context.register_*`) is idempotent-only or rejected; Junction identity must match the existing direct/related adapters. `related_name='+'` / `'bad__path'` / `'bad_'` and partial `UniqueConstraint(condition=...)` are not single-valued/invertible. `trusts.E006` re-walks the installed map and leftover deferred `Content._contents` declarations. |
| Replacement | New kernel callers use `from trusts.context import Context`. Existing `Content.register_content` / `Junction` keep working. |
| Affected | New registrations; documentation distinguishes the core contract from django-trusts conveniences. |
| Authorization | Same Trust rows and the same one-query evaluation. No schema change. |

Migration-bot checklist:

- [ ] Prefer `Context.register_direct(Model, scope_field=...)` /
      `Context.register_related(Model, through=...)` for new resources.
- [ ] Keep using `Content` subclasses when the resource owns a `trust` FK.
- [ ] Keep `from trusts.models import Junction` for existing junction
      tables; do not rename or drop those tables.
- [ ] Do not register many-valued hops (M2M / reverse one-to-many).
- [ ] Related `through` must terminate at an already registered Context
      resource. Register parents before dependents.
- [ ] Run `python -m django check` (`trusts.E006` is fail-closed; silencing
      it does not make a bad path executable).
- [ ] Confirm `has_perm` and `.permitted()` still agree for Content.
- [ ] Confirm `filter_by_content` still matches at each dependent hop
      and for Junction-wrapped models.
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] No Trusts migrate step. Do not edit `0001_initial` or
      `0002_trustgroup`.

### 32. `Junction` is a 1.x compatibility wrapper

| | |
| --- | --- |
| Previous | `Junction.register_junction` called `Content.register_content` on the wrapped model with a Trust-origin lookup. |
| New | Same public class and auto-registration. Internally: `Context.register_direct(JunctionSubclass, scope_field='trust')` plus `Context.register_related(wrapped, through=content_fk.related_query_name())`. The wrapped model remains `Content.is_content_model`; the junction table does not become public content. |
| Replacement | Existing `class GroupJunction(Junction): content = ForeignKey(...)` is unchanged. New dependents that you own should use `Context.register_related` instead of adding a junction table. |
| Affected | Documentation and `migrates.md` only. No warning is emitted. |
| Authorization | Unchanged. No 1.x removal. |

Migration-bot checklist:

- [ ] Do not delete or rename concrete `Junction` subclasses or their
      tables in 1.x.
- [ ] Do not treat `TestGroupJunction`-style rows as `has_perm` targets
      unless you already did (they stay unregistered as public content).
- [ ] Inventory new wrap-an-existing-model cases: Junction still works;
      `Context.register_related` is preferred when you control a
      single-valued FK to a registered resource.
- [ ] Leave package version at `1.0.0.dev0`.

## Fresh database

```
python -m django migrate --settings=tests.settings
python -m django migrate --settings=tests.custom_settings
```

Trusts still applies `0001`–`0002` only. The isolated test app applies
`trusts_tests.0004_context_contract` for kernel models. That is not a
Trusts schema change.

## Upgrade of a representative legacy database

`scripts/verify-legacy-upgrade.py` is unchanged: pending
`0002_trustgroup` after recording `0001_initial`, then
`{0001_initial, 0002_trustgroup}` after migrate. No new Trusts
migration. No Junction table rewrite.

## Out of scope (unchanged)

- Removing `Junction` in 1.x
- Trustee registry (#40)
- Role / Group / Team semantics
- Trust hierarchy or recursive inheritance (#17)
- A universal concrete Context table
- A separate core distribution
- Many-valued related paths (all/any policy)

## Migration-bot summary (issue #39)

- [ ] Adopt `Context.register_direct` / `Context.register_related` for
      new resource registrations.
- [ ] Keep `Content` / `Junction` / `Content.register_content` call sites;
      they now route through the registry.
- [ ] Do not emit or expect a `Junction` `DeprecationWarning` in 1.x.
- [ ] Do not add a Trusts schema migration.
- [ ] Run `python -m tests.runtests` (includes `tests.core.test_context`).
- [ ] Run `python -m tests.runtests_custom`.
- [ ] Run `python -m django check` (default and custom settings).
- [ ] Run `python scripts/verify-legacy-upgrade.py`.
- [ ] Run the packaging / wheel-import check.
- [ ] Confirm exact one-query list/exists Context resolution and
      `has_perm` / `.permitted()` equivalence.
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] Do not close #39 from this PR.

# Issue #40: registry-driven Trustee resolution contract (1.0.0.dev0)

This record covers the first additive Trustee-extraction slice. Version
remains **1.0.0.dev0**. **No Trusts schema migration is required.** Test
fixtures add `trusts_tests` models only (`0005_trustee_contract`,
`0006_trustee_team`). This
PR does **not** close
[#40](https://github.com/django-trusts/django-trusts/issues/40); review
owns that. A separate `django-trusts-core` distribution is not created
here.

## Decision

The reusable question is: by what validated relational path does a
requester reach a trustee, and by what concrete relation does that
trustee participate in a scoped authorization decision? That contract
lives in `trusts.trustee` and must not name `User`, `Group`, `Role`,
`Team`, or `Trust`.

```python
from trusts.trustee import Trustee, TrusteeMixin

Trustee.configure(
    requester_model=Requester,
    scope_model=Scope,
    operation_model=Operation,
)
Trustee.register(
    name="direct",
    trustee_model=Requester,
    grant_model=DirectGrant,
    trustee_path="requester",
    scope_path="scope",
    operation_path="operation",
)
Trustee.register(
    name="collective",
    trustee_model=Collective,
    grant_model=CollectiveGrant,
    trustee_path="collective",
    scope_path="scope",
    operation_path="operation",
    membership_path="members",
    constraint_paths=("collective__operations",),
)
```

- **Direct / identity:** the trustee model is the configured requester.
  `membership_path` is empty.
- **Collective:** an external model (no mixin required) reaches the
  requester through a validated relational membership path. Many-valued
  membership (M2M) is allowed. Grant identity paths (`trustee_path`,
  `scope_path`, `operation_path`) stay single-valued.
- **Constraints:** grant-origin paths to the same operation model.
  They OR-compose with each other and AND-restrict a completed grant.
  They never create authorization.
- **Mixin:** `TrusteeMixin` is abstract declaration convenience and
  adds no concrete fields. It does not register an adapter.
  `__subclasses__()` is not a query-building source.

Registration is static during Django application loading. The map
freezes before the first authorization query and before
`manage.py check`. Validation uses Django `_meta` only. Duplicate,
incomplete, scalar, callable, wrong-terminal, ambiguous, many-valued
grant-identity, and late registrations fail closed
(`TrusteeRegistrationError`, `TrusteeRegistryFrozen`) and are reported
as `trusts.E007` if a stale adapter remains. Direct exists-checks and
list filters share the same compiled `Exists` predicate
(`Trustee.grant_q` / `Trustee.filter_granted` / `Trustee.row_is_granted`)
and stay one SQL query each.

django-trusts conveniences route through that map and keep their
observable 1.x behavior:

- Direct `AUTH_USER_MODEL` grants are the `direct` adapter over
  `TrustUserPermission`.
- Django `auth.Group` is the `group` adapter over
  `TrustGroupPermission` (explicit registration, no inheritance).
- Existing `Role` inherits `TrusteeMixin` with no new fields. Current
  Role behavior is the Group adapter's second constraint path
  (`trustgroup__group__roles__permissions`). It is **not** a third
  OR-composed grant branch and does not add `TrustRolePermission`.

## No change to these public call sites

- `User.has_perm` / `User.has_perms` signatures
- `ContentQuerySet.permitted(perm, user)` signature
- `Trust.objects.filter_by_user_content_perm` / `filter_by_user_perm`
- `Role` / `RolePermission` / `TrustGroup` / `TrustGroupPermission` tables
- Package version `1.0.0.dev0`
- Historical `0001_initial` / `0002_trustgroup` file contents

Authorization **behavior** is unchanged. `trust_grant_q` and
`TrustModelBackend.get_all_permissions` now compile through the frozen
Trustee adapters; the enabled 1.x set is still direct User grants OR
the Group local/global intersection (Role as ceiling only).

## Changes

### 33. `trusts.trustee.Trustee` registry (new)

| | |
| --- | --- |
| Previous | `trust_grant_q` and the backend hardcoded `TrustUserPermission` / `TrustGroup` / `Group.permissions` / `group.roles` lookups. |
| New | Abstract/model-free `Trustee.configure` / `Trustee.register`. `Trustee.adapters()` is the complete deterministic set and the complete query-building source: built-in `direct` / `group` adapters may be gated by the auth-model contract, but additional installed adapters stay in `has_perm` / `.permitted()`. `configure(scope_model=..., operation_model=...)` (or first-adapter inference) rejects mismatched terminals so OR-composed adapters cannot authorize by colliding primary keys. `Trustee.add_finalizer` runs pending integration work once before every freeze. After freeze, public `Trustee.register` is idempotent-only or rejected. `trusts.E007` re-walks the installed map. |
| Replacement | New kernel callers use `from trusts.trustee import Trustee`. Existing `has_perm` / `.permitted()` keep working. |
| Affected | New registrations; documentation distinguishes the core contract from django-trusts conveniences. |
| Authorization | Same allow/deny results for current User and Group paths. No schema change. |

Migration-bot checklist:

- [ ] Prefer `Trustee.register(...)` for new trustee types. Do not
      discover adapters with `TrusteeMixin.__subclasses__()`.
- [ ] Keep using `TrustUserPermission` and `TrustGroupPermission` for
      current User / Group grants.
- [ ] Keep `Role` as a global ceiling bundle. Do not add
      `TrustRolePermission`, `Team`, or `TrustGroupRole` in this slice.
- [ ] Do not flatten or remove `TrustGroup`.
- [ ] Membership paths must terminate at the configured requester.
- [ ] Grant identity paths must be single-valued relations.
- [ ] Constraint paths constrain completed grants; they do not authorize.
- [ ] Run `python -m django check` (`trusts.E007` is fail-closed;
      silencing it does not make a bad path executable).
- [ ] Confirm `has_perm` and `.permitted()` still agree for User and
      Group paths, including Role-as-ceiling.
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] No Trusts migrate step. Do not edit `0001_initial` or
      `0002_trustgroup`.

### 34. `Role` inherits `TrusteeMixin` (no schema change)

| | |
| --- | --- |
| Previous | `class Role(models.Model)` with `name` plus M2M `groups` / `permissions`. |
| New | `class Role(TrusteeMixin, models.Model)` with the same concrete fields. Mixin is abstract and adds no columns. |
| Replacement | Existing Role rows and `update_roles_permissions` keep working. |
| Affected | Declaration only. Role is not auto-registered as a grant adapter. |
| Authorization | Unchanged. Role remains ceiling-only. |

Migration-bot checklist:

- [ ] Do not generate or apply a Trusts migration for the mixin.
- [ ] Do not treat Role inheritance as a new authorization path.
- [ ] Leave package version at `1.0.0.dev0`.

## Fresh database

```
python -m django migrate --settings=tests.settings
python -m django migrate --settings=tests.custom_settings
```

Trusts still applies `0001`–`0002` only. The isolated test app applies
`trusts_tests.0005_trustee_contract` and `0006_trustee_team` for kernel
and extra-adapter models. That is not a Trusts schema change.

## Upgrade of a representative legacy database

`scripts/verify-legacy-upgrade.py` is unchanged: pending
`0002_trustgroup` after recording `0001_initial`, then
`{0001_initial, 0002_trustgroup}` after migrate. No new Trusts
migration. No Role or TrustGroup rewrite.

## Out of scope (unchanged)

- Adopting Grok's `TrustRolePermission` proposal from #34
- Adding a hard-coded Team model
- Removing or flattening TrustGroup
- Removing Role or RolePermission
- Changing Django `obj=None`, superuser, or third-party backend composition
- Windows ACL semantics (#17)
- A separate core distribution
- Settling Role's long-term fate (trustee vs template vs deprecated)

## Migration-bot summary (issue #40)

- [ ] Adopt `Trustee.configure` / `Trustee.register` for new trustee
      registrations.
- [ ] Keep `Role` / `TrustGroup` / `TrustUserPermission` call sites;
      they now route through the registry.
- [ ] Do not add `TrustRolePermission` or flatten TrustGroup.
- [ ] Do not add a Trusts schema migration.
- [ ] Run `python -m tests.runtests` (includes `tests.core.test_trustee`).
- [ ] Run `python -m tests.runtests_custom`.
- [ ] Run `python -m django check` (default and custom settings).
- [ ] Run `python scripts/verify-legacy-upgrade.py`.
- [ ] Run the packaging / wheel-import check.
- [ ] Confirm exact one-query list/exists Trustee resolution and
      `has_perm` / `.permitted()` equivalence for current User/Group paths.
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] Do not close #40 from this PR.

# Issue #43 Step 1: composed AuthorizationPath IR and GH proof (1.0.0.dev0)

This record covers the first additive AuthorizationPath slice. Version
remains **1.0.0.dev0**. **No Trusts schema migration is required.** Test
fixtures add a private `tests.gh_vocab` application only
(`gh_vocab.0001_initial`). This PR does **not** close
[#43](https://github.com/django-trusts/django-trusts/issues/43); review
owns that. Concrete relocation to `django-trusts-zero` is a later step.
Recursive traversal and ordered remaining-bits helpers are reserved
slots only.

## Decision

The reusable join is: given a resource model and an operation, freeze
the Context and Trustee maps and compile one authorization decision
from those frozen path records. That contract lives in `trusts.path`
and must not name `Trust`, `Content`, `Junction`, `Group`, `Role`,
`Team`, or `User`.

```python
from trusts.path import AuthorizationPath, compose, filter_granted, row_is_granted

path = compose(ResourceModel, operation, context=context, trustee=trustee)
row_is_granted(obj, requester, operation, context=context, trustee=trustee)
filter_granted(ResourceModel.objects.all(), requester, operation,
               context=context, trustee=trustee)
```

Internally that is today's

```text
Trustee.grant_q(requester, operation,
                scope_from_row=Context.scope_path(resource_model))
```

plus fail-closed terminal matching. Isolated tests construct
`ContextRegistry()` / `TrusteeRegistry()` and pass them in.
Process-wide `Context` / `Trustee` remain the default instances.

This slice is **additive/internal**. Existing Trust / Role / Group /
ceiling / backend evaluation still consumes its current path
(`trust_grant_q` / `TrustModelBackend`). Those call sites are
intentionally not rewired here.

A private GH-shaped vocabulary proves the kernel without django-trusts
nouns. Public relations used to authorize are `account.teams`,
`team.permission_bundles`, and `repository.policy`.
`organization.teams` is owner containment and is not the requester
path. Kernel APIs only: not `User.has_perm`.

## No change to these public call sites

- `User.has_perm` / `User.has_perms` signatures
- `ContentQuerySet.permitted(perm, user)` signature
- `Trust.objects.filter_by_user_content_perm` / `filter_by_user_perm`
- `from trusts.context import Context` / `from trusts.trustee import Trustee`
- `from trusts.models import Trust, Content, Junction, Role`
- `AUTHENTICATION_BACKENDS = ('trusts.backends.TrustModelBackend',)`
- `Role` / `RolePermission` / `TrustGroup` / `TrustGroupPermission` tables
- Package version `1.0.0.dev0`
- Historical `0001_initial` / `0002_trustgroup` file contents

Authorization **behavior** for current User / Group / Role-ceiling /
Content paths is **unchanged**. This slice does not rewire
`TrustModelBackend` or `ContentQuerySet.permitted`. Those surfaces stay
behavior-compatible: same signatures, same allow/deny results, same
Zero policy registration (`direct` / `group`, Role-as-ceiling).

## Changes

### 35. `trusts.path.AuthorizationPath` compose seam (new)

| | |
| --- | --- |
| Previous | The Context / Trustee join was implicit: `Trustee.grant_q(..., scope_from_row=Context.scope_path(model))` inside Zero list/`has_perm` helpers. |
| New | Named IR `AuthorizationPath` with `compose` / `row_is_granted` / `filter_granted`. Public construction is `compose` only; `AuthorizationPath(...)` is rejected. Shared terminals are scalars. Adapter-specific data is always `path.branches`: a non-empty tuple of immutable `AuthorizationBranch` records (`constraint_paths` on each branch is `tuple[str]`), the same shape for one adapter or many. Unregistered resources, empty grant sets, and mismatched scope/operation terminals fail closed (`AuthorizationPathError`). Evaluation requires requester and operation *instances* of the composed terminals; raw primary keys are rejected so Django cannot normalize a colliding PK. `RecursiveEdge` / `OrderedContribution` / resource-row `condition=` are reserved: `compose` rejects them, and an instance that carries a non-empty reserved slot cannot evaluate. |
| Replacement | New kernel callers use `from trusts.path import compose, row_is_granted, filter_granted`. Read adapter-specific fields from `path.branches[i]`, not from scalar/tuple path attributes. Existing `has_perm` / `.permitted()` keep working on the current Zero path. |
| Affected | New registrations and the private GH proof. Current Content / Trust / Group callers are unchanged. |
| Authorization | Same allow/deny for current User and Group paths. GH `Account` / `Team` graphs use kernel APIs. No schema change. |

Migration-bot checklist:

- [ ] Prefer `compose` / `row_is_granted` / `filter_granted` for new
      noun-independent callers. Pass isolated registries in tests.
- [ ] Traverse `path.branches` (always a tuple of `AuthorizationBranch`).
      Do not expect `grant_model` / `constraint_paths` on the path
      object itself.
- [ ] Pass requester and operation model instances, not raw PKs.
- [ ] Keep using `User.has_perm` / `.permitted()` for current Content.
- [ ] Do not treat `RecursiveEdge` / `OrderedContribution` /
      `condition=` as implemented. Do not construct `AuthorizationPath`
      directly.
- [ ] Do not relocate models, migrations, commands, or the backend to
      `django-trusts-zero` in this slice.
- [ ] Do not add a Trusts schema migration. Do not edit `0001_initial`
      or `0002_trustgroup`.
- [ ] Run `python -m tests.runtests` (includes `tests.core.test_path`
      and `tests.core.test_gh_vocab`).
- [ ] Run `python -m tests.runtests_custom`.
- [ ] Run `python -m django check` (default and custom settings).
- [ ] Run `python scripts/verify-legacy-upgrade.py`.
- [ ] Run the packaging / wheel-import check.
- [ ] Confirm `account.teams` membership grants and organization
      containment without membership denies.
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] Do not close #43 from this PR.

### 36. Private GH-shaped proof application (tests only)

| | |
| --- | --- |
| Previous | Isolated Context / Trustee models used kernel nouns (`TrusteeRequester`, `TrusteeScope`). Process-wide extra adapter `TrusteeTeam` still FKs `trusts.Trust`. |
| New | Private `tests.gh_vocab` models: `Account`, `Organization`, `Team`, `PermissionBundle`, `Policy`, `Repository` (plus `Operation` / `TeamPolicyGrant`). `account.teams` is the membership M2M reverse. `organization.teams` is containment only. No required public `.trusts` / `.trustees` / `.contexts` / `.roles` / `.groups` / `.member_teams`. |
| Replacement | Proof-only. Not an installable package. Terminology is GH, not the full external service name. |
| Affected | Isolated tests. Process-wide Context / Trustee maps do not register these models. |
| Authorization | Membership + grant + bundle ceiling allow. Containment without membership, wrong operation, and missing bundle ceiling deny. Exists ≡ list, one query. |

Migration-bot checklist:

- [ ] Do not import `tests.gh_vocab` from production code.
- [ ] Do not add GH models to the installable `trusts` package.
- [ ] Do not register GH adapters on the process-wide Trustee map
      (requester/scope/operation terminals would mismatch Zero).
- [ ] Leave package version at `1.0.0.dev0`.

## Fresh database

```
python -m django migrate --settings=tests.settings
python -m django migrate --settings=tests.custom_settings
```

Trusts still applies `0001`–`0002` only. The isolated test app applies
`gh_vocab.0001_initial` for GH proof models. That is not a Trusts
schema change. Custom-user settings do not install `gh_vocab`.

## Upgrade of a representative legacy database

`scripts/verify-legacy-upgrade.py` is unchanged: pending
`0002_trustgroup` after recording `0001_initial`, then
`{0001_initial, 0002_trustgroup}` after migrate. No new Trusts
migration.

## Out of scope (unchanged)

- Rewiring `TrustModelBackend` / `ContentQuerySet.permitted` onto
  compose (Step 2; recorded in the Step 2 section below)
- Relocating concrete models/migrations to `django-trusts-zero`
  (Step 3)
- Recursive hierarchy / bounded ancestor walk
- Ordered remaining-bits / Windows ACE semantics
- Compiling resource-row V1 `Expr` on the IR (`condition=` reserved)
- Implementing complete GH authorization semantics
- A separate `django-trusts-core` distribution

## Migration-bot summary (issue #43 Step 1)

- [ ] Adopt `from trusts.path import compose, row_is_granted,
      filter_granted` for new kernel callers.
- [ ] Keep current `has_perm` / `.permitted()` / backend call sites;
      they are behavior-compatible and still consume the Zero path.
- [ ] Do not relocate packages or migrations.
- [ ] Do not add a Trusts schema migration.
- [ ] Run `python -m tests.runtests` (includes `tests.core.test_path`
      and `tests.core.test_gh_vocab`).
- [ ] Run `python -m tests.runtests_custom`.
- [ ] Run `python -m django check` (default and custom settings).
- [ ] Run `python scripts/verify-legacy-upgrade.py`.
- [ ] Run the packaging / wheel-import check.
- [ ] Confirm exact one-query list/exists AuthorizationPath evaluation
      and the GH membership vs containment proof.
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] Do not close #43 from this PR.

# Issue #43 Step 2: Zero evaluation consumes AuthorizationPath (1.0.0.dev0)

This record covers routing the existing django-trusts concrete
implementation through the composed `AuthorizationPath` seam. Version
remains **1.0.0.dev0**. **No Trusts schema migration is required.** This
PR does **not** close
[#43](https://github.com/django-trusts/django-trusts/issues/43); review
owns that. Relocation to `django-trusts-zero` is a later step.
Recursive traversal and ordered remaining-bits helpers remain reserved
slots only.

## Decision

`ContentQuerySet.permitted` and object-level `TrustModelBackend`
evaluation compile through `trusts.path.compose` (Zero-enabled adapter
names) rather than a parallel `Context.scope_path` + `Trustee.grant_q`
or `Content.is_content` + `Trust.objects.filter_by_content` join.

Zero policy stays out of the kernel:

- adapter names `direct` / `group` and settings-based gating
- Django `auth.Permission` strings / `parse_perm_code` /
  `resolve_content_permission`
- `TrustModelBackend` / `_trust_perm_cache` / `User.has_perm`
- opt-in callable permission conditions
- `is_active` / anonymous short-circuit. Object-level superuser is **not**
  a global True: `TrustModelBackend.has_perm(obj)` uses the same composed
  grant as other requesters (pre-PR `get_all_permissions(obj)` did the
  same). `User.has_perm` without `obj` still follows Django's
  `PermissionsMixin` shortcut. `.permitted()` never treated superuser as
  return-all.
- public-content gate `Content.is_content` (Junction table rows still
  do not enter `User.has_perm`)

Create-under-trust (`filter_by_user_content_perm`,
`has_trust_row_perm`) still uses `Trustee.grant_q` with empty
`scope_from_row` because `Trust` as Content is registered with the
parent hop (`resource_to_scope='trust'`), not identity. Those helpers
now fail closed on raw PKs and wrong-model same-PK requesters /
operations.

## No change to these public call sites

- `User.has_perm` / `User.has_perms` signatures
- `ContentQuerySet.permitted(perm, user)` signature
- `Trust.objects.filter_by_user_content_perm` / `filter_by_user_perm` /
  `filter_by_content`
- `from trusts.context import Context` / `from trusts.trustee import Trustee`
- `from trusts.path import compose, row_is_granted, filter_granted`
- `from trusts.models import Trust, Content, Junction, Role`
- `AUTHENTICATION_BACKENDS = ('trusts.backends.TrustModelBackend',)`
- `Role` / `RolePermission` / `TrustGroup` / `TrustGroupPermission` tables
- Package version `1.0.0.dev0`
- Historical `0001_initial` / `0002_trustgroup` file contents

Authorization **behavior** for current User / Group / Role-ceiling /
condition / custom-user / inactive-user / backend-composition paths is
**intended identical**. Direct check ≡ queryset. Same-PK collisions of
the wrong model and raw primary keys now fail closed at these public
compatibility entry points instead of letting Django coerce the PK.

## Changes

### 37. Concrete evaluation consumes `compose`

| | |
| --- | --- |
| Previous (Step 1) | `ContentQuerySet.permitted` called `trust_grant_q(..., trust_fk=Context.scope_path(model))`. `TrustModelBackend.get_all_permissions` / `has_perm` materialized Trusts via `filter_by_content` then `Trustee.operation_grant_q`. |
| New | `.permitted()` uses `compose_zero_path` / `path.grant_q`. Object-level `has_perm` uses `row_is_zero_granted` / `queryset_is_zero_granted` (the same composed predicate). `get_all_permissions` enumerates operations per scope PK taken from `path.resource_to_scope` (resource-origin), still intersecting across scopes for QuerySets. `get_group_permissions` remains a Zero mapping onto the named `group` adapter. |
| Replacement | Same `has_perm` / `.permitted()` call sites. New kernel callers still use `from trusts.path import compose`. |
| Affected | Internal evaluation only. |
| Authorization | Same allow/deny for current User / Group / Role-ceiling / Content paths. Unregistered and Junction-table objects still deny on object-level `has_perm`. Active superusers without a Trust-scoped grant stay denied on object-level `TrustModelBackend.has_perm` and `.permitted()`; a granted superuser is present on both. Django `obj=None` / `User.has_perm` without an object still short-circuits active superusers. |

Migration-bot checklist:

- [ ] Keep using `User.has_perm` / `.permitted()` for current Content.
- [ ] Do not pass a raw PK or a non-requester model as the user argument
      to `.permitted()`, `TrustModelBackend.has_perm`,
      `filter_by_user_content_perm`, or `has_trust_row_perm`.
- [ ] Do not relocate models, migrations, commands, or the backend to
      `django-trusts-zero` in this slice.
- [ ] Do not add a Trusts schema migration. Do not edit `0001_initial`
      or `0002_trustgroup`.
- [ ] Run `python -m tests.runtests` (includes `tests.core.test_zero_path`).
- [ ] Run `python -m tests.runtests_custom`.
- [ ] Run `python -m django check` (default and custom settings).
- [ ] Run `python scripts/verify-legacy-upgrade.py`.
- [ ] Confirm `has_perm` and `.permitted()` still agree and stay
      fixed-query.
- [ ] Confirm an active superuser without a Trust-scoped grant is denied
      on object-level `TrustModelBackend.has_perm` and `.permitted()`, a
      granted superuser is allowed on both, and Junction / unregistered
      objects plus unknown permission codes stay denied.
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] Do not close #43 from this PR.

### 38. Deletion report (noun-dependent query branches)

Removed as genuinely redundant after the compose rewire. They were
already unused call sites or parallel joins of the same frozen adapters:

| Removed | Why redundant |
| --- | --- |
| `query.group_local_grant_exists` | Called `Trustee.get('group').exists_q` by adapter name. No remaining caller after #40; group grants OR-compose through `path.grant_q`. |
| `query.permission_granted_via_group_exists` | Called `Trustee.get('group').operation_exists_q` by adapter name. No remaining caller. Zero `get_group_permissions` still uses that adapter explicitly. |
| `query._never_exists` | Imported `TrustGroup` to return `Exists(TrustGroup.objects.none())`. Empty adapter sets use `Q(pk__in=[])`. |
| `query._scope_from_row_for_outerref` | Trust-PK outerref name munging (`trust_id` → `trust`) used only by the deleted group helpers. Compose passes `resource_to_scope` as registered. |
| `TrustModelBackendMixin._get_trusts` | Trust-origin `filter_by_content` join, parallel to Context's resource-origin hop. Replaced by `compose_zero_path` + `scope_pks_from_resource`. |
| `backends._trust_permission_grant_q` | Thin wrapper over `Trustee.operation_grant_q`; inlined on the composed scope list. |

Isolated, not deleted (still Zero policy / compatibility):

| Kept | Why |
| --- | --- |
| `query.enabled_trustee_adapter_names` | Zero gating of built-in `direct` / `group`; extra adapters stay enabled. Passed to `compose(..., names=...)`. |
| `query.trust_grant_q` | Create-under-trust / `has_trust_row_perm` (empty `scope_from_row`). Now fail-closed on requester/operation terminals. |
| `query.is_active_principal` | Django user flags; not a kernel default. |
| `Content.is_content` as `has_perm` gate | Public-content facade. Junction tables are Context-registered but must not newly authorize. |
| `Trustee.get(GROUP_TRUSTEE)` in `get_group_permissions` | Django's user/group permission split mapped onto a named Zero adapter. |
| `Content._contents` / `_conditions` / `class_prepared` | Zero convenience; not this slice. |
| V1 `Expr` compile on `.permitted()` | Still AND-ed after the composed grant `Q`. `condition=` on `compose` remains reserved. |

## Fresh database

```
python -m django migrate --settings=tests.settings
python -m django migrate --settings=tests.custom_settings
```

Trusts still applies `0001`–`0002` only.

## Upgrade of a representative legacy database

`scripts/verify-legacy-upgrade.py` is unchanged: pending
`0002_trustgroup` after recording `0001_initial`, then
`{0001_initial, 0002_trustgroup}` after migrate. No new Trusts
migration.

## Out of scope (unchanged)

- Relocating concrete models/migrations to `django-trusts-zero`
  (Step 3)
- Recursive hierarchy / bounded ancestor walk
- Ordered remaining-bits / Windows ACE semantics
- Compiling resource-row V1 `Expr` on the IR (`condition=` reserved)
- Implementing complete GH authorization semantics
- A separate `django-trusts-core` distribution
- Closing #43

## Migration-bot summary (issue #43 Step 2)

- [ ] Keep current `has_perm` / `.permitted()` / backend signatures.
- [ ] Expect same-PK / raw-PK requesters to fail closed
      (`AuthorizationPathError`) at those entry points.
- [ ] Do not relocate packages or migrations.
- [ ] Do not add a Trusts schema migration.
- [ ] Run `python -m tests.runtests` (includes `tests.core.test_zero_path`).
- [ ] Run `python -m tests.runtests_custom`.
- [ ] Run `python -m django check` (default and custom settings).
- [ ] Run `python scripts/verify-legacy-upgrade.py`.
- [ ] Confirm `has_perm` ≡ `.permitted()`, fixed-query, and current
      User/Group/Role-ceiling allow/deny.
- [ ] Confirm object-level superuser follows relational grants on both
      `TrustModelBackend.has_perm` and `.permitted()`.
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] Do not close #43 from this PR.

# Issue #43 Step 3: kernel AppConfig and in-tree `trusts.zero` (1.0.0.dev0)

This record covers the coordinated package relocation. Version remains
**1.0.0.dev0**. This package-path change is the 2.0 `INSTALLED_APPS` /
import migration; stored schema and authorization rows stay compatible.
This PR does **not** close
[#43](https://github.com/django-trusts/django-trusts/issues/43); review
owns that. Recursive/ordered helpers and a broader GH proof are out of
scope. Concrete models live only in
[`django-trusts-zero`](https://github.com/django-trusts/django-trusts-zero)
as ``trusts.zero``. This kernel package does **not** ship ``trusts/zero``.
The kernel **wheel** never included that tree.

## Decision

```text
distribution: django-trusts
import package: trusts
AppConfig: trusts.apps.KernelConfig
  name='trusts'  label='trusts_kernel'  default=False
  no models, no migrations
owns: trusts/__init__.py (pkgutil.extend_path), context, trustee,
      path, conditions, utils, kernel checks (E006 adapters, E007)

distribution: django-trusts-zero
import package: trusts.zero
depends on: django-trusts
AppConfig: trusts.zero.apps.ZeroConfig
  name='trusts.zero'  label='trusts'
  default_auto_field=AutoField
owns: models, managers, backend, admin, views, urls, decorators,
      authorization, commands, templates, settings constants,
      Zero checks (E001–E005, W001–W003),
      migrations 0001_initial / 0002_trustgroup
```

Bare `'trusts'` or `'trusts.zero'` in `INSTALLED_APPS` is invalid after
this split. Django would auto-select the kernel config (or an implicit
`label='trusts'`) and drop or collide with historical migrations.

Zero must never ship `trusts/__init__.py`. Kernel `RECORD` owns kernel
paths; Zero `RECORD` owns only `trusts/zero/**`.

## Historical migration identity

Move `0001_initial` / `0002_trustgroup` to `trusts.zero.migrations`.
Django identity stays `('trusts', '0001_initial')` /
`('trusts', '0002_trustgroup')` because Zero's `label` is `trusts`.
**Do not squash, rename, fake, or add `0003`.**

Source-only Python-path rewrite (r3):

```python
# trusts/zero/migrations/0001_initial.py
from trusts.zero import (
    ENTITY_MODEL_NAME, GROUP_MODEL_NAME, PERMISSION_MODEL_NAME,
    DEFAULT_SETTLOR, ALLOW_NULL_SETTLOR, ROOT_PK,
)
from trusts.zero.management.commands.create_trust_root import create_root_trust
from trusts.zero.models import ReadonlyFieldsMixin
# bases=(ReadonlyFieldsMixin, models.Model)
# to=, through=, apps.get_model('trusts', 'trust'), RunPython settings: unchanged

# trusts/zero/migrations/0002_trustgroup.py
from trusts.zero import GROUP_MODEL_NAME, PERMISSION_MODEL_NAME
```

Accepted deconstruction deltas (not DDL):

- `CreateModel.bases` serializes `trusts.zero.models.ReadonlyFieldsMixin`
- `RunPython` callable module is `trusts.zero.management.commands.create_trust_root`

Field `to=`, `through=`, `db_table`, `unique_together`, and
`SeparateDatabaseAndState.database_operations=[]` stay equivalent.
`sqlmigrate` snapshots live in `scripts/expected/`.

## Changes

### 38. Explicit `INSTALLED_APPS` and import paths (2.0 package path)

| | |
| --- | --- |
| Previous | `INSTALLED_APPS` includes `'trusts'`. Models: `from trusts.models import Trust, Content, Junction, Role`. Backend: `trusts.backends.TrustModelBackend`. URLs: `include('trusts.urls')`. |
| New | `INSTALLED_APPS` must list `'trusts.apps.KernelConfig'` then `'trusts.zero.apps.ZeroConfig'`. Models: `from trusts.zero.models import Trust, Content, Junction, Role`. Backend: `trusts.zero.backends.TrustModelBackend`. URLs: `include('trusts.zero.urls')`. Settings constants live on `trusts.zero`. Kernel `trusts` exports no Zero constants. |
| Replacement | Mechanical search-replace of the table below. Tables, content types, and permission natural keys are unchanged (`trusts | trust`). |
| Affected | Every project that installed django-trusts as the concrete app. |
| Authorization | Unchanged. No schema migration. |

Migration-bot checklist:

- [ ] Install `django-trusts` (kernel) and `django-trusts-zero` (concrete). Concrete sources are not in this repository.
- [ ] Confirm wheel+wheel / editable+editable / Zero uninstall isolation against the **companion checkout** (`scripts/verify-namespace-install.py`). Do not validate a synthetic Zero wheel from this tree. Editable Zero next to the kernel needs setuptools `editable_mode=compat` so kernel `trusts/__init__.py` stays the package owner.
- [ ] Replace `'trusts'` in `INSTALLED_APPS` with the two explicit class paths. Do not use bare `'trusts'` or `'trusts.zero'`.
- [ ] Replace `from trusts.models import …` with `from trusts.zero.models import …`.
- [ ] Replace `trusts.backends.TrustModelBackend` with `trusts.zero.backends.TrustModelBackend`.
- [ ] Replace `include('trusts.urls')` with `include('trusts.zero.urls')`.
- [ ] Replace `from trusts.authorization import …` / `from trusts.decorators import …` / `from trusts.admin import …` with the `trusts.zero.*` paths.
- [ ] Leave kernel imports (`trusts.context`, `trusts.trustee`, `trusts.path`, `trusts.conditions`, `django_trusts`) unchanged.
- [ ] Confirm `migrate --plan` for `app_label == 'trusts'` is empty on an already-current database.
- [ ] Confirm applied set stays `{0001_initial, 0002_trustgroup}`; row counts unchanged; content-type natural keys stay `trusts | trust` (and siblings).
- [ ] Confirm `makemigrations trusts --check` is quiet.
- [ ] Confirm `python scripts/verify-legacy-upgrade.py` still applies only pending `0002` when `0001` is already recorded.
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] Do not close #43 from this PR.

### Mechanical import / settings map

| Previous | New |
| --- | --- |
| `'trusts'` in `INSTALLED_APPS` | `'trusts.apps.KernelConfig'`, `'trusts.zero.apps.ZeroConfig'` |
| `from trusts.models import Trust` | `from trusts.zero.models import Trust` |
| `from trusts.backends import TrustModelBackend` | `from trusts.zero.backends import TrustModelBackend` |
| `from trusts.decorators import permission_required, P, K, G, O` | `from trusts.zero.decorators import …` |
| `from trusts.authorization import …` | `from trusts.zero.authorization import …` |
| `from trusts.admin import …` | `from trusts.zero.admin import …` |
| `include('trusts.urls')` | `include('trusts.zero.urls')` |
| `from trusts import ENTITY_MODEL_NAME, get_entity_model, …` | `from trusts.zero import …` |
| `from trusts.context import Context` | unchanged |
| `from trusts.trustee import Trustee` | unchanged |
| `from trusts.path import compose` | unchanged |

## Fresh database

```
python -m django migrate --settings=tests.settings
python -m django migrate --settings=tests.custom_settings
python scripts/verify-migration-split.py
```

Applies `0001_initial` then `0002_trustgroup` under label `trusts`.
Kernel `trusts_kernel` owns no migrations.

## Upgrade of a representative legacy database

`scripts/verify-legacy-upgrade.py` still:

1. Records `('trusts', '0001_initial')` as applied.
2. Expects pending `[('trusts', '0002_trustgroup', False)]`.
3. After migrate, applied set `{0001_initial, 0002_trustgroup}`.
4. Does not re-run `0001`. Association rows are reused; local grants start empty.

Already-applied 0001+0002: `migrate --plan` for `trusts` is empty.

## Out of scope (unchanged)

- Recursive hierarchy / bounded ancestor walk
- Ordered remaining-bits / Windows ACE semantics
- Compiling resource-row V1 `Expr` on the IR (`condition=` reserved)
- Implementing complete GH authorization semantics
- Pinning kernel CI to an ephemeral django-trusts-zero PR branch
- Closing #43

## Migration-bot summary (issue #43 Step 3)

- [ ] Use explicit `KernelConfig` + `ZeroConfig` in `INSTALLED_APPS`.
- [ ] Point concrete imports at `trusts.zero.*`.
- [ ] Keep kernel imports on `trusts.context` / `trustee` / `path`.
- [ ] Do not edit schema-bearing operations in `0001` / `0002`.
- [ ] Run `python -m tests.runtests` (includes `tests.core.test_kernel_split`).
- [ ] Run `python -m tests.runtests_custom`.
- [ ] Run `python -m django check` (default and custom settings).
- [ ] Run `python scripts/verify-legacy-upgrade.py`.
- [ ] Run `python scripts/verify-migration-split.py`.
- [ ] Run `python scripts/verify-namespace-install.py` (or the package CI job).
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] Do not close #43 from this PR.

# Issue #47 S1: runtime, queryset, identity, alignment (1.0.0.dev0)

This record covers the first kernel execution slice. Version remains
**1.0.0.dev0**. This PR does **not** close
[#47](https://github.com/django-trusts/django-trusts/issues/47); review
owns that. It implements accepted **framework-execution-r1+r2+r3**
kernel S1 only. It does **not** modify `django-trusts-zero`, start
gh-permissions#1, resume #17, or implement S2 backend / S3 decorators /
S4 UI.

## Decision

```text
trusts.context: register_direct / register_related / register_identity
trusts.trustee: configure(..., operation_lookup=) / register(..., alignment_paths=)
trusts.path: compose / compose_scope
trusts.runtime:
  AuthorizationDenied, AuthorizationConfigError
  is_authorized / require_authorized / filter_authorized / authorized_q
  is_scope_authorized / require_scope_authorized / filter_authorized_scope / authorized_scope_q
  (no configure_runtime, no all_authorized, no public scope_from_row)
trusts.query: AuthorizedQuerySet.authorized / AuthorizedManager
```

The queryset class name is **`AuthorizedQuerySet`** (not
`AuthorizationQuerySet`). That is the r1/r2 name: `authorized` is the
neutral verb, and Zero keeps `permitted` with its Django-permission
argument order.

Object decisions and authorized querysets compile from the same frozen
`AuthorizationPath.grant_q`. String operations compile as
`operation_path__lookup` inside that `Exists` when
`Trustee.operation_lookup` is set. Strings are prepared through that
field; an unpreparable value is an always-false predicate. There is no
preliminary `Operation.objects.get()`.

`alignment_paths` are grant-row equalities, AND-ed into that adapter's
`Exists` with `F()` and non-NULL on both sides. They are not
`constraint_paths` (those still terminate at the operation model).
NULL or mismatched identities deny at read time.

## No change to these public call sites

- `Context.register_direct` / `register_related`
- `Trustee.register` without `alignment_paths` (default `()`)
- `Trustee.configure` without `operation_lookup` (default unset)
- `AuthorizationPath.compose` / `filter_granted` / `row_is_granted`
- Zero `ContentQuerySet.permitted`, `TrustModelBackend`, decorators,
  admin, views, historical migrations, app label `trusts`

## Changes

### 39. `Context.register_identity` (new)

| | |
| --- | --- |
| Previous | Resource→scope required `register_direct` (a real field) or `register_related`. |
| New | `register_identity(model)` registers a resource that *is* its policy scope. Kind `identity`. Compiled `scope_path` is the empty string. |
| Replacement | Use identity when the row is the scope (for example a repository that is also the grant scope). Do not fake a field on `register_direct`. |
| Affected | New kernel consumers. Zero still uses `register_direct` / `register_related`. |
| Authorization | Identity `compose(Model, op)` uses grant `scope_path` → row `pk`. Same predicate as list/`exists`. |

### 40. Trustee `operation_lookup` (new, optional)

| | |
| --- | --- |
| Previous | `grant_q` required an operation-model *instance*. |
| New | `Trustee.configure(..., operation_lookup='code')` (unique scalar on `operation_model`, including non-text fields such as `id`). Strings are prepared through the lookup field (no `get()`) and compile as `{operation_path__lookup: prepared}` inside the same `Exists`. Unknown codes and values the field cannot accept (for example `operation_lookup='id'` plus `'missing'`) deny via an always-false predicate. Missing lookup + string is `AuthorizationConfigError` on direct APIs. |
| Replacement | Prefer instances, or configure a unique lookup. Zero does not have to use this (`auth.Permission.codename` is not unique alone). |
| Affected | New kernel consumers that want `'read'`-style operations. |
| Authorization | One SQL statement for supported object/list decisions. Unpreparable string data is ordinary denial, not `ValueError` / `FieldError`. No preliminary `get()`. |

### 41. Trustee `alignment_paths` (new, optional)

| | |
| --- | --- |
| Previous | Extra grant constraints had to be operation-terminal `constraint_paths` or write-time integrity. |
| New | `register(..., alignment_paths=(('team__organization', 'repository__organization'),))`. Each pair is grant-origin, single-valued, compatible FK or scalar identity. AND-ed with `F()` + `__isnull=False`. Default `()`. Copied onto `AuthorizationBranch`. `equivalent` / `revalidate` / `trusts.E007` include it. |
| Replacement | Do **not** overload `constraint_paths`. Those still walk grant → operation model. |
| Affected | Any consumer that must refuse malformed/cross-terminal grant rows at read time. |
| Authorization | Cross-org or NULL-org grant rows deny even when membership, operation, and bundle ceiling hold. Adapters still OR only as complete paths. Read-time alignment is the security boundary. |

### 42. `AuthorizationPath.compose_scope` (new)

| | |
| --- | --- |
| Previous | `compose()` always required a Context resource hop. Scope-is-row was an empty-string back-channel. |
| New | `compose_scope(scope_model, operation, ...)` when the queryset/row *is* `Trustee.scope_model()`. No Context adapter. No public `scope_from_row`. |
| Replacement | Resource listings: `compose` / `filter_authorized`. Scope listings: `compose_scope` / `filter_authorized_scope`. |
| Affected | Create-under-scope listings. Zero `trust_grant_q` can wrap `authorized_scope_q` later. |
| Authorization | Same grant `Exists` as resource-origin, including `alignment_paths`. |

### 43. `trusts.runtime` and `trusts.query` (new)

| | |
| --- | --- |
| Previous | Consumers wrote their own exists/list helpers on top of `compose`. |
| New | `is_authorized` / `require_authorized` / `filter_authorized` / `authorized_q` and scope-origin siblings. `AuthorizedQuerySet.authorized` / `AuthorizedManager`. |
| Replacement | Call these instead of copying `grant_q`. Isolated tests pass `context=` / `trustee=`. |
| Affected | New kernel consumers. Zero wrappers are a later follow-up. |
| Authorization | Explicitly unusable principal (`is_anonymous is True`, `is_authenticated is False`, or `is_active is False`, including Django `AnonymousUser`) and unknown operation *data* deny. Unusable flags are checked **before** requester-model identity so `AnonymousUser` is an ordinary denial, not `AuthorizationConfigError`. Unregistered resource, no adapters, raw PK, *usable* wrong concrete model, mixed/stale terminals, reserved slot, incomplete `operation_lookup` raise `AuthorizationConfigError`. `require_*` raises `AuthorizationDenied` only for ordinary denials. Equivalence: `is_authorized(p, op, obj)` == `exists()` of the same `Q` as `filter_authorized`. One query each. |

## Fresh database

```
python -m django migrate --settings=tests.settings
python -m tests.runtests
```

No Trusts schema migration. Test-only `trusts_tests.0007_s1_kernel` adds
isolated S1 models.

## Upgrade of a representative legacy database

Unchanged. `scripts/verify-legacy-upgrade.py` still expects
`{0001_initial, 0002_trustgroup}` on label `trusts`.

## Out of scope (unchanged)

- S2 `ObjectAuthorizationBackend` / S3 decorators / S4 admin/CBV/templates
- Generic `register_row_condition`
- `RecursiveEdge` / `OrderedContribution`
- django-trusts-zero wrappers or pin bump
- gh-permissions#1
- Closing #17 or #47

## Migration-bot summary (issue #47 S1)

- [ ] Register identity resources with `Context.register_identity`.
- [ ] Configure `Trustee.operation_lookup` if you pass operation strings.
- [ ] Declare org/identity equalities as `alignment_paths`, not `constraint_paths`.
- [ ] Use `compose_scope` / `filter_authorized_scope` when the row is the scope.
- [ ] Catch `AuthorizationConfigError` only at security boundaries.
- [ ] Attach `AuthorizedManager` (class name `AuthorizedQuerySet`) if you want `.authorized()`.
- [ ] Run `python -m tests.runtests` (includes `tests.core.test_s1_kernel`).
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] Do not close #47 from this PR.

# Issue #47 S2: object-only authorization backend (1.0.0.dev0)

This record covers the second kernel execution slice. Version remains
**1.0.0.dev0**. This PR does **not** close
[#47](https://github.com/django-trusts/django-trusts/issues/47); review
owns that. It implements accepted **framework-execution-r1+r2+r3**
kernel S2 only. It does **not** modify `django-trusts-zero`, start
gh-permissions#1, resume #17, or implement S3 decorators / S4
admin/CBVs/templates.

## Decision

```text
trusts.backends:
  ObjectAuthorizationBackend          # advertised default; BaseBackend
  ObjectAuthorizationModelBackend     # optional ModelBackend compose
```

`ObjectAuthorizationBackend` is object-only:

- `authenticate()` abstains (`None`).
- `obj is None` returns `False` (no global or model permissions).
- A supplied object routes through S1 `is_authorized` / the shared
  `grant_q` path. `perm` is an operation instance or
  `operation_lookup` string. There is no `app.action_model` parser.
- `AuthorizationConfigError` becomes denial (`False`) at this security
  boundary. Direct runtime APIs still raise.
- Ordinary denials (anonymous / inactive / unauthenticated principals,
  unknown operation data) stay denials.
- The generic backend does not assume Django User or `auth.Permission`
  models and does not grant object access because `is_superuser`.

`ObjectAuthorizationModelBackend` is a separately named convenience:
`obj is None` uses Django `ModelBackend` model permissions; object
checks stay on `ObjectAuthorizationBackend`. It is not required for GH
and is not the advertised default. Zero keeps
`trusts.zero.backends.TrustModelBackend` and its Permission / Content /
cache / `:condition` policy.

## No change to these public call sites

- S1 `trusts.runtime` / `trusts.query` / `compose` / `compose_scope`
- `Context.register_identity` / Trustee `operation_lookup` /
  `alignment_paths`
- Zero `TrustModelBackend`, `ContentQuerySet.permitted`, decorators,
  admin, views, historical migrations, app label `trusts`
- Package version `1.0.0.dev0`

## Changes

### 44. `trusts.backends.ObjectAuthorizationBackend` (new)

| | |
| --- | --- |
| Previous | Consumers wired Django `User.has_perm` themselves, or used Zero `TrustModelBackend` (Permission strings, `Content.is_content`, `obj is None` → Django model perms). |
| New | Object-only `BaseBackend`. Isolated tests pass `context=` / `trustee=` to the constructor (process-wide maps remain the no-arg default). |
| Replacement | Add `trusts.backends.ObjectAuthorizationBackend` to `AUTHENTICATION_BACKENDS` for object checks. Keep Django `ModelBackend` (or Zero) beside it for login and model permissions. |
| Affected | New kernel consumers. Zero does not subclass this in S2. |
| Authorization | Object success/denial follow S1 `is_authorized` (one SQL `Exists`). `obj is None` is `False`. Malformed configuration denies rather than raising through `has_perm`. An active superuser is not granted object access by this backend. Django `PermissionsMixin.has_perm` still short-circuits active superusers before backends run. |

### 45. `trusts.backends.ObjectAuthorizationModelBackend` (new, optional)

| | |
| --- | --- |
| Previous | No framework `ModelBackend` compose. |
| New | `ObjectAuthorizationBackend` + `ModelBackend`. `obj is None` → Django model permissions (including ModelBackend's active-superuser global grant). `obj` set → generic object path. `authenticate` / `get_user` follow `ModelBackend`. |
| Replacement | Use only when one backend should serve both Django model permissions and object checks. Not required for GH. |
| Affected | Optional convenience. |
| Authorization | Object/global dispatch is explicit. Object access is not widened by model permissions or `is_superuser`. |

## Fresh database

```
python -m django migrate --settings=tests.settings
python -m tests.runtests
```

No Trusts schema migration. S2 uses the existing isolated S1 test models.

## Upgrade of a representative legacy database

Unchanged. `scripts/verify-legacy-upgrade.py` still expects
`{0001_initial, 0002_trustgroup}` on label `trusts`.

## Out of scope (unchanged)

- S3 native decorators / `P`/`K`/`G`/`O`
- S4 admin / CBV mixins / stub templates
- Generic `register_row_condition`
- `RecursiveEdge` / `OrderedContribution`
- django-trusts-zero wrappers or pin bump
- gh-permissions#1
- Closing #17 or #47

## Migration-bot summary (issue #47 S2)

- [ ] Use `ObjectAuthorizationBackend` for object `has_perm`; do not expect global grants from it.
- [ ] Catch `AuthorizationConfigError` only at security boundaries (this backend already does).
- [ ] Do not parse `app.action_model` in the generic backend; pass an operation instance or lookup string.
- [ ] Keep Django `ModelBackend` (or Zero) if you still need login or model permissions.
- [ ] Treat `ObjectAuthorizationModelBackend` as optional compose, not the default.
- [ ] Run `python -m tests.runtests` (includes `tests.core.test_s2_backend`).
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] Do not close #47 from this PR.

# Issue #47 S3: native decorators and request-data binders (1.0.0.dev0)

This record covers the third kernel execution slice. Version remains
**1.0.0.dev0**. This PR does **not** close
[#47](https://github.com/django-trusts/django-trusts/issues/47); review
owns that. It implements accepted **framework-execution-r1+r2+r3**
kernel S3 only. It does **not** modify `django-trusts-zero`, start
S4 admin/CBVs/templates, start S5 checks cleanup, gh-permissions#1,
or resume #17.

## Decision

```text
trusts.decorators:
  require_authorized(operation, resource_model=..., resource_kwarg=...)
  request_passes_test
  P / K / G / O
```

`require_authorized` is the native HTTP security boundary:

- Operation is an operation-model instance, an `operation_lookup`
  string, or a `P` expression of those. There is no
  `app.action_model` parser and no `ContentType` inference.
- `resource_model` is required (decorator or each `P` leaf). The
  framework does not guess a model from a Django permission string.
- Resource identity is declared request keys only: `resource_kwarg`
  (URL kwarg → primary key) and inert `K` / `G` / `O` field selectors.
  Getter/resolver callbacks and other callables are configuration
  errors.
- Selectors identify *the* protected resource. A PK, unique scalar, or
  unconditional compound unique key may combine lookup + auth in one
  SQL. A non-unique selector (`title=G('title')`) is allowed only when
  exactly one row matches; two or more matches fail closed (403) and
  are never an existential grant on any authorized subset.
- Every `P` leaf's configuration is validated before any grant
  decision. A malformed leaf cannot be hidden by `|` ordering or a
  valid sibling.
- Authorization is S1 `filter_authorized` / the shared `grant_q`. The
  decorator does not call `request.user.has_perm()` and does not add a
  second policy walker. Active `is_superuser` does not bypass
  registered object policy on this path.
- Missing or unresolvable resource identity → **404**.
- Existing but unauthorized, unusable principal, or unknown operation
  data → **403**, or a login redirect when `raise_exception=False`.
- `AuthorizationConfigError` → **403** at this boundary. Direct
  runtime APIs still raise. Malformed configuration cannot produce
  access, and does not become a login redirect.

`P` boolean composition (`&` / `|`) is operation-and-selector data
over the same decorator machinery. It is **not** Zero's Django-permission
`P`. Zero's `permission_required` (Permission strings + `ContentType`)
stays in `trusts.zero.decorators` as later Zero work.

`request_passes_test` is the generic request test / login-redirect
helper. Wrapped-view metadata is preserved (`functools.wraps`).

Query contract (honest):

| Path | SQL |
| --- | ---: |
| Missing request key | 0 |
| Unusable principal (exists / missing) | 1 existence, no auth `Exists` |
| Granted unique identity (PK / unique key; lookup + auth combined) | 1 |
| Unauthorized or not-found after a unique-identity combined miss | 2 (combined miss + existence) |
| Ambiguous non-unique selector (2+ rows) | 1 (`[:2]`), fail closed 403 |
| Single non-unique match then authorize that instance | 2 |
| `P` composition | config walk is 0 SQL; then one leaf's counts per evaluated leaf |

Isolated tests pass `context=` / `trustee=` to the decorator
(process-wide maps remain the no-arg default).

## No change to these public call sites

- S1 `trusts.runtime` / `trusts.query` / `compose` / `compose_scope`
- S2 `ObjectAuthorizationBackend` / `ObjectAuthorizationModelBackend`
- Zero `trusts.zero.decorators.permission_required`, `P`, `K`, `G`, `O`
- Zero `TrustModelBackend`, `ContentQuerySet.permitted`, admin, views,
  historical migrations, app label `trusts`
- Package version `1.0.0.dev0`

## Changes

### 46. `trusts.decorators.require_authorized` (new)

| | |
| --- | --- |
| Previous | Consumers called `User.has_perm` in the view, or used Zero `permission_required` (Django permission strings, `ContentType` model inference, `has_perms`). After #43 those Zero names live at `trusts.zero.decorators`. |
| New | Native `@require_authorized('read', resource_model=Repository, resource_kwarg='pk')` plus `pk=K(...)` / `G` / `O` and optional `P` composition. Isolated registries via `context=` / `trustee=`. |
| Replacement | New kernel consumers use `trusts.decorators.require_authorized`. Zero compatibility stays `from trusts.zero.decorators import permission_required, P, K, G, O`. Do not treat the new module as a drop-in for the Zero wrapper. |
| Affected | New kernel consumers. Zero is not re-exported from `trusts.decorators`. |
| Authorization | Granted views run only after the declared keys identify exactly one row and S1 authorizes that row. A non-unique selector that matches two rows (one granted, one denied) is 403, not an existential grant. `P` OR with a malformed leaf is 403 even when the other leaf would grant. 404 vs 403 follows unique-identity existence. Superuser flags are ignored. |

### 47. `trusts.decorators.P` / `K` / `G` / `O` / `request_passes_test` (new)

| | |
| --- | --- |
| Previous | Same names existed on Zero's decorator module as Django-permission binders (`P('app.action_model', ...)`, `ContentType` lookup). |
| New | Framework `P` holds an operation and request-key selectors. `K`/`G`/`O` are inert key sources (URL kwargs / GET / POST). `request_passes_test` redirects to login when the test returns `False`. |
| Replacement | Import from `trusts.decorators` for native operation data. Keep Zero imports for Django permission strings. The two `P` types are not interchangeable. |
| Affected | New kernel view decorators. Existing Zero decorator tests still import `trusts.zero.decorators`. |
| Authorization | `P` composition does not introduce callbacks or Zero `:condition` / Permission semantics. |

## Fresh database

```
python -m django migrate --settings=tests.settings
python -m tests.runtests
```

No Trusts schema migration. S3 uses the existing isolated S1 test models.

## Upgrade of a representative legacy database

Unchanged. `scripts/verify-legacy-upgrade.py` still expects
`{0001_initial, 0002_trustgroup}` on label `trusts`.

## Out of scope (unchanged)

- S4 admin / CBV mixins / stub templates
- S5 `E008` / kernel `Content` leftover import cleanup
- Generic `register_row_condition`
- `RecursiveEdge` / `OrderedContribution`
- django-trusts-zero `permission_required` wrapper or pin bump
- gh-permissions#1
- Closing #17 or #47

## Migration-bot summary (issue #47 S3)

- [ ] Import native `@require_authorized` from `trusts.decorators`, not Zero.
- [ ] Pass an explicit `resource_model`; do not parse `app.action_model`.
- [ ] Bind identity with `resource_kwarg` or `K`/`G`/`O` only; no getter callbacks.
- [ ] Treat a non-unique selector that matches more than one row as 403, not a grant.
- [ ] Treat a malformed `P` leaf as 403 for the whole expression, including `|`.
- [ ] Expect 404 for missing/unknown resources and 403 for unauthorized ones.
- [ ] Catch `AuthorizationConfigError` only at security boundaries (this decorator already does).
- [ ] Keep `from trusts.zero.decorators import permission_required` for Django-permission compatibility; do not expect that wrapper here.
- [ ] Run `python -m tests.runtests` (includes `tests.core.test_s3_decorators`).
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] Do not close #47 from this PR.

