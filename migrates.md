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
  Django permission principal.
- Use standard `auth.Group` and `auth.Permission`. Values other than
  those models are `trusts.E004` / `trusts.E005`. django-trusts does not
  maintain a private parallel swappability contract for Group/Permission.

An experiment that treated `TRUSTS_GROUP_MODEL` /
`TRUSTS_PERMISSION_MODEL` as swappable replacements (convention-shaped
custom group/permission models, Role `AlterField` retarget, permission
row copy) is a **negative architectural result**, not supported behavior.
That work is not shipped. Deprecation/removal of the unused settings is
[#33](https://github.com/django-trusts/django-trusts/issues/33).
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
| New | Isolated suite `python -m tests.runtests_custom` migrates with custom `AUTH_USER_MODEL` / matching `TRUSTS_ENTITY_MODEL` selected before migrate. Settlor and trustee FKs target the custom user table. Group, Permission, Role, and TrustGroup stay `auth.Group` / `auth.Permission`. System checks `trusts.E003`–`E005` report a non-user entity or a non-auth group/permission model. Mismatched model instances fail closed (`ValidationError` / `AuthorizationDenied`); PKs are not taken from the wrong class. |
| Replacement | Set `AUTH_USER_MODEL` and `TRUSTS_ENTITY_MODEL` to the same custom user **before** the first migrate. Leave `TRUSTS_GROUP_MODEL` / `TRUSTS_PERMISSION_MODEL` unset. |
| Affected | Projects that set `TRUSTS_GROUP_MODEL` / `TRUSTS_PERMISSION_MODEL` to something other than `auth.Group` / `auth.Permission` now fail `manage.py check`. That combination was never a coherent Django swap. |
| Authorization | Object-level paths use `AUTH_USER_MODEL` for the principal and `auth.Group` / `auth.Permission` for group ceiling and Role. No fallback to a parallel group/permission table. |

Migration-bot checklist:

- [ ] Keep `TRUSTS_ENTITY_MODEL` equal to `AUTH_USER_MODEL`.
- [ ] Leave `TRUSTS_GROUP_MODEL` / `TRUSTS_PERMISSION_MODEL` as `auth.Group` / `auth.Permission` (or unset).
- [ ] Do not apply or expect `trusts.0003_role_configured_models`. Historical `0001_initial` is unchanged (no extra configured-app graph dependencies; Role stays `auth.*`).
- [ ] Do not pass a non-user instance into trustee APIs, or a non-`auth.Group` / non-`auth.Permission` instance into TrustGroup/Role APIs.
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
- Deprecating `TRUSTS_GROUP_MODEL` / `TRUSTS_PERMISSION_MODEL` (#33)
- Trust-scoped Role/Group assignment semantics (#34)
- Example-app UI
- Rewriting historical `0001_initial` field targets or adding a Role
  retarget migration
