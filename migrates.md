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
| New | Resolves via `get_permission_model()` / `TRUSTS_PERMISSION_MODEL`. Accepts a permission instance, codename, bare action (`read` → `read_<model>`), or dotted code. May strip a leftover `:condition` when resolving a grant/revoke target. Queryset callers must reject conditions first (`permitted` / `filter_by_user_content_perm` do). |
| Replacement | `Model.objects.get_permission('read')` or `get_permission('read_model')`. |
| Affected | `grant` / `revoke`. List APIs do not use this helper alone. Custom permission models must provide `get_by_natural_key` or `codename` + content type fields. |
| Authorization | Lookup only; does not grant. Not a list filter. |

Migration-bot checklist:

- [ ] Stop importing `auth.Permission` in project grant helpers if `TRUSTS_PERMISSION_MODEL` is set.
- [ ] Re-run permission resolution tests after swapping the permission model.

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
- `TRUSTS_GROUP_MODEL` and `TRUSTS_PERMISSION_MODEL` are respected (same settings as `0001`). Custom group models must keep Django's `auth.Group` query conventions: a `permissions` M2M to the configured permission model and a `user` related-query name for membership. Role.groups already uses `TRUSTS_GROUP_MODEL`. Swapping these settings after tables exist still requires an explicit project migration (same warning as `0001`).

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

---

# Registration primitive (issue #57)

This record covers the additive ``trusts.core`` registration surface.
Version remains **1.0.0.dev0**. It closes the #57 slice (register and
validate only). It does **not** compile queries, migrate historical
models, or change authorization results. There is **no schema or
migration change**.

## Decision

Authorization metadata for a permission-bearing relation is declared
from root-relative ``Ref`` paths on an isolated ``TrustsRegistry``
instance. The root model comes from the refs. Terminal models and field
names are inferred from Django ``_meta``. One immutable
``RegisteredRelation`` is stored per root. Duplicate (identical) and
conflicting (same root, different normalized record) registrations both
raise ``TrustsConfigurationError`` and leave the first record unchanged.

## No change to these public call sites

- `User.has_perm` / ``ContentQuerySet.permitted`` signatures
- ``Content`` / ``Junction`` registration and ``class_prepared`` dispatch
- Authentication-backend composition
- Package version `1.0.0.dev0`
- Database schema and Trusts migrations (`0001_initial`, `0002_trustgroup`)

## Changes

### 27. ``trusts.core`` registration primitive (new, additive)

| | |
| --- | --- |
| Previous | No generic relation-root registry. Historical registration state lives on ``Content`` / ``Junction``. |
| New | ``TrustsRegistry``, root-relative ``Ref``, ``register(...)``, and immutable ``RegisteredRelation`` records in ``trusts.core``. Isolated instances only; not re-exported from ``trusts``. Direct single-valued forward paths only. ``condition`` omitted/``None`` only. |
| Replacement | None for existing callers. Import ``from trusts.core import TrustsRegistry, Ref`` for new isolated declarations. |
| Affected | None of the live authorization path. Tests use ordinary Document / DocumentGrant models. |
| Authorization | Unchanged. No query compilation. No schema or migration. |

Migration-bot checklist:

- [ ] Do not apply a new Trusts migration; none was added.
- [ ] Do not import ``TrustsRegistry`` from ``trusts``; import ``trusts.core``.
- [ ] Leave historical ``Content`` / ``Junction`` registration alone.
- [ ] Leave package version at ``1.0.0.dev0``.

## Schema

No change. ``trusts.core`` performs zero SQL and adds no model.

## Out of scope (not acceptance criteria)

- Historical model registration
- String / ``__`` path desugaring
- ``condition`` representation (``Q`` / ``Expr`` / callable)
- Process-global registry or ``trusts`` package re-export

---

# Common plan and three projections (issue #60)

This record covers the additive ``trusts.core`` plan compiler.
Version remains **1.0.0.dev0**. It closes the #60 slice (one registered
relation plan, three mock projections). It does **not** migrate historical
models or change authorization results. There is **no schema or Django
migration change**.

## Decision

``TrustsRegistry`` compiles applicable ``RegisteredRelation`` records into
one ``RelationPlan``. Permission enumeration, object authorization, and
authorized-content filtering are terminal projections of that plan.
Object authorization is SQL ``EXISTS`` membership over the same relational
meaning as enumeration; it does not iterate a Python list. Multiple
applicable roots combine by SQL ``OR``. Unregistered content fails closed.

## No change to these public call sites

- `User.has_perm` / ``ContentQuerySet.permitted`` signatures
- ``Content`` / ``Junction`` registration and ``class_prepared`` dispatch
- Authentication-backend composition
- Package version `1.0.0.dev0`
- Database schema and Trusts migrations (`0001_initial`, `0002_trustgroup`)

## Changes

### 28. ``trusts.core`` common plan and three projections (new, additive)

| | |
| --- | --- |
| Previous (#57) | Registration and ``_meta`` validation only. No query compilation. |
| New | Internal ``RelationPlan`` plus development surfaces ``permissions_for``, ``has_permission``, and ``filter_authorized``. One shared ``EXISTS`` builder; projections add only the terminal or existence wrapper. Isolated instances only; not re-exported from ``trusts``. |
| Replacement | None for existing callers. Import ``from trusts.core import TrustsRegistry, Ref`` and call the projection methods on an isolated registry. |
| Affected | None of the live authorization path. Tests use ordinary Document / DocumentGrant / DocumentPermit models. |
| Authorization | Unchanged for historical Trusts. No schema or migration. |

Migration-bot checklist:

- [ ] Do not apply a new Trusts migration; none was added.
- [ ] Do not import ``TrustsRegistry`` from ``trusts``; import ``trusts.core``.
- [ ] Leave historical ``Content`` / ``Junction`` authorization alone.
- [ ] Leave package version at ``1.0.0.dev0``.

### 29. Common-plan target-field correlation and required bindings (review on #61)

The imported ``trusts.core`` development API from §28 is corrected.
Version remains **1.0.0.dev0**. There is **no schema or Django
migration change**. Historical authorization is unchanged.

| | |
| --- | --- |
| Previous (#61 / §28) | ``RelationPlan._correlated_exists()`` always used ``OuterRef('pk')``. A valid direct ``ForeignKey(..., to_field='slug')`` (or any unique non-PK target) compared the root FK column to the outer row's primary key. |
| New | Correlation reads the relation's Django target field (``ForeignKey.target_field`` / ``attname``) and builds ``OuterRef`` against that outer field. |
| Replacement | Same ``RelationPlan`` / ``plan_for`` / registry projection call sites. Register direct single-valued relations as before; non-PK ``to_field`` now enumerates and filters correctly. |
| Affected | Isolated ``trusts.core`` development callers that register a FK targeting a unique field other than ``pk``. PK-targeting FKs keep the same SQL meaning. |
| Authorization | Unchanged for historical Trusts. Corrects mock-plan enumeration/list results for non-PK targets. |

| | |
| --- | --- |
| Previous (#61 / §28) | ``_bound_root_qs()`` skipped any binding whose value was ``None``. A direct ``RelationPlan`` call with a missing principal/permission dropped that predicate and could broaden to all matching rows. |
| New | Required bindings reject ``None`` and other non-model values with ``TrustsConfigurationError``. ``_bound_root_qs()`` and the three projection methods never omit a supplied binding. Nullable grant columns do not make ``None`` a valid binding. |
| Replacement | Pass model instances for ``user``, ``content``, and ``permission`` on ``RelationPlan.permissions`` / ``has_permission`` / ``filter_content``. Registry wrappers already required instances. |
| Affected | Direct ``RelationPlan`` / ``plan_for`` projection callers. ``TrustsRegistry`` wrappers already validated instances. |
| Authorization | Fail closed. A missing binding cannot widen to all rows. |

Migration-bot checklist:

- [ ] Do not apply a new Trusts migration; none was added.
- [ ] Import ``TrustsRegistry`` / ``RelationPlan`` from ``trusts.core``, not ``trusts``.
- [ ] Pass model instances into ``RelationPlan`` projections; do not pass ``None``.
- [ ] If a registered FK uses ``to_field``, expect correlation on that unique field, not ``pk``.
- [ ] Leave historical ``Content`` / ``Junction`` authorization alone.
- [ ] Leave package version at ``1.0.0.dev0``.

## Schema

No change. The plan compiler adds no model and no migration. The §29
corrections change only ``trusts.core`` query construction and binding
validation.

## Out of scope (not acceptance criteria)

- Historical model registration or vertical migration
- String / ``__`` path desugaring
- ``condition`` representation
- Process-global registry or ``trusts`` package re-export
- Codename strings, dotted permission syntax, or heterogeneous
  permission-terminal normalization

---

# Same-root registrations and trailing-reverse content paths (issue #65)

This record covers the additive ``trusts.core`` same-root and
bounded content-path extension. Version remains **1.0.0.dev0**. It
closes the #65 slice (isolated mocks only). It does **not** migrate
historical models, start Child H, or change authorization results.
There is **no schema or Django migration change**.

## Decision

One permission-bearing root may store several normalized
``RegisteredRelation`` rows when they terminate on different content
models. A content path may be the existing direct single-valued hop or
one or more forward single-valued hops followed by exactly one final
reverse one-to-many hop. User and permission paths stay direct.
Bindings and ``EXISTS`` use the complete root-relative lookup and the
last hop's single path-info target field.

## No change to these public call sites

- `User.has_perm` / ``ContentQuerySet.permitted`` signatures
- ``Content`` / ``Junction`` registration and ``class_prepared`` dispatch
- Authentication-backend composition
- Package version `1.0.0.dev0`
- Database schema and Trusts migrations (`0001_initial`, `0002_trustgroup`)

## Changes

### 30. Same-root records and trailing-reverse content paths (new, additive)

| | |
| --- | --- |
| Previous (#57 / #60 / §29) | ``_by_root`` stored one record per root. ``get(root)`` returned that record. A second different registration for the same root was always a conflict. Content, user, and permission paths were one direct single-valued hop. ``content_field`` was the last segment on the root. ``OuterRef`` was resolved by looking up that field on the root. |
| New | ``_by_root[root]`` is an insertion-ordered list. ``records_for_root(root)`` returns that tuple and raises when absent. ``get(root)`` is removed. Exact duplicates still raise. Same root plus the same content terminal with a different registration is still a conflict. Same root plus different content terminals is allowed. Content may also be ``(forward single-valued)+`` then one final reverse one-to-many. Each hop is resolved with ``get_path_info()``: exactly one ``PathInfo`` and exactly one target field, or the path is rejected. Stored ``*_field`` is the full ``'__'.join(path)`` lookup; ``*_target`` is the last hop's target ``attname``. ``RelationPlan.content_exists`` is the one content-``EXISTS`` surface; ``filter_authorized`` consumes it. |
| Replacement | None for existing callers. Isolated ``register`` / ``plan_for`` / projection call sites stay the same. Use ``records_for_root`` instead of ``get``. Register a trailing-reverse content path when the terminal is not a field on the root. |
| Affected | Isolated ``trusts.core`` development callers. Direct one-hop registrations keep the same lookup (``document``) and #64 target-field ``OuterRef``. |
| Authorization | Unchanged for historical Trusts. No schema or migration. |

Rejected during ``register`` (zero SQL): reverse before the final hop;
reverse as the only hop; reverse one-to-one; many-to-many; generic
foreign keys; anything after the final reverse; multi-hop all-forward
content; arbitrary multi-valued chains; composite / multi-column
correlation.

Migration-bot checklist:

- [ ] Do not apply a new Trusts migration; none was added.
- [ ] Import ``TrustsRegistry`` / ``RelationPlan`` from ``trusts.core``, not ``trusts``.
- [ ] Do not call ``registry.get(root)``; use ``records_for_root(root)`` or ``plan_for``.
- [ ] Same-root second paths to one content model are conflicts, not precedence.
- [ ] Leave historical ``Content`` / ``Junction`` authorization alone.
- [ ] Leave package version at ``1.0.0.dev0``.

## Schema

No change. The same-root and trailing-reverse extension adds no model
and no migration. Query construction remains lazy.

## Out of scope (not acceptance criteria)

- Historical model registration, package-owned registry lifecycle, or
  reader migration (Child H / #62)
- Junction reverse-then-forward, group M2M, custom ``fieldlookup``
  chains, or parent hierarchy
- Process-global registry or ``trusts`` package re-export
- ``condition`` representation

---

# First historical Category reader (issue #67)

This record covers the first historical registration-only vertical slice.
Version remains **1.0.0.dev0**. It closes the #67 Child H slice: one
explicit ``TrustUserPermission → Trust ← Category`` declaration and the
trustee half of ``ContentQuerySet.permitted`` for that terminal. It does
**not** migrate backend enumeration, ``has_perm``, conditions-as-atom,
mutations, Trust-as-object, Junction, Ticket, or Group/Role. There is
**no schema or Django migration change**.

## Decision

The live ``TrustsRegistry`` is owned by ``trusts.apps.AppConfig`` and is
created in ``AppConfig.__init__`` after ``super()``. ``ready()`` does not
replace that object. Readers obtain it with
``django.apps.apps.get_app_config('trusts').registry``. Isolated core
tests continue to construct their own ``TrustsRegistry()``. There is no
core singleton and no package-root registry export.

The external test application contributes the Category declaration in
``TestsConfig.ready()``. Trusts does not import or discover
``tests.Category``. The reverse hop is taken from Django ``_meta``, not
hard-coded. Re-entry is a no-op only when the same contributor
``AppConfig`` instance has already donated this declaration to the same
registry object (instance-local sentinel, set only after ``register()``
succeeds). Unrelated Category records do not suppress the TUP
contribution. Ticket is a second independent contribution (§33).

``ContentQuerySet.permitted`` keeps the public signature and documented
results. When ``plan_for`` has records, the trustee predicate comes from
plan-level ``content_exists`` and is OR-ed with the existing group-local
grant on the original candidate queryset. The named-condition overlay
still applies after the complete trustee|group grant. The method still
returns a lazy ``.filter(...).distinct()`` queryset. Unregistered models
keep the old ``trust_grant_q`` path.

## No change to these public call sites

- `User.has_perm` / ``User.has_perms`` signatures and backend
  implementation
- ``ContentQuerySet.permitted`` signature and documented allow/deny
  results
- ``Content`` / ``Junction`` ``class_prepared`` registration
- Package version `1.0.0.dev0`
- Database schema and Trusts migrations (`0001_initial`, `0002_trustgroup`)

## Changes

### 31. Category trustee list path uses the registered plan (internal)

| | |
| --- | --- |
| Previous | ``ContentQuerySet.permitted`` always built the trustee half with ``trust_grant_q(..., trust_fk='trust')``. No package-owned registry. |
| New | ``trusts.apps.AppConfig`` owns one ``TrustsRegistry``. The test app registers ``TrustUserPermission → Trust ← Category``. For that terminal, ``.permitted`` ORs ``plan.content_exists`` with the existing group predicate on the incoming queryset. Junction and other still-unregistered models stay on ``trust_grant_q``. Trust-as-content is §32. Ticket is §33. |
| Replacement | Same ``Model.objects.permitted(perm, user)`` call. Results and laziness are unchanged. |
| Affected | Internal implementation of ``Category`` list filtering only. ``has_perm`` remains on the old backend path. |
| Authorization | Unchanged results. Group-only rows are not dropped. No schema or migration. |

Migration-bot checklist:

- [ ] Do not apply a new Trusts migration; none was added.
- [ ] Do not import a registry from ``trusts``; readers use
      ``apps.get_app_config('trusts').registry``.
- [ ] Do not expect Trusts to discover project Content models. Contribute
      registrations from the project's ``AppConfig.ready()``.
- [ ] Leave backend ``has_perm`` / ``get_all_permissions`` alone.
- [ ] Leave package version at ``1.0.0.dev0``.

### 32. Trust-as-content list path uses the registered plan (internal)

| | |
| --- | --- |
| Previous | ``Trust.objects.permitted`` used ``trust_grant_q(..., trust_fk='trust')`` because Trust had no plan records. Permission on a child Trust already resolved through its parent. |
| New | ``trusts.apps.AppConfig.ready()`` registers ``TrustUserPermission → parent Trust ← child Trust`` via Django ``_meta`` (no hard-coded reverse, no ``Content._contents``). The existing ``plan.records`` switch in ``ContentQuerySet.permitted`` lights up. Trustee is ``content_exists``; group stays OR-ed on the original candidate queryset. ``:own`` remains a condition overlay. Create-under-trust ``filter_by_user_content_perm`` stays on ``trust_grant_q`` (this slice does not register the conflicting direct Trust terminal). |
| Replacement | Same ``Trust.objects.permitted(perm, user)`` call. Results, laziness, and parent-resolution semantics are unchanged. |
| Affected | Internal implementation of ``Trust`` list filtering only. ``has_perm`` remains on the old backend path. |
| Authorization | Unchanged results. Group-only rows are not dropped. No schema or migration. |

Migration-bot checklist:

- [ ] Do not apply a new Trusts migration; none was added.
- [ ] Do not register ``content=j.trust`` beside the parent-reverse path (same-root same-terminal conflict).
- [ ] Leave ``filter_by_user_content_perm`` on ``trust_grant_q``.
- [ ] Leave backend ``has_perm`` / ``get_all_permissions`` alone.
- [ ] Leave package version at ``1.0.0.dev0``.

## Schema

No change. S1 adds no model and no Django migration. Query
construction remains lazy.

## Out of scope (not acceptance criteria)

- Backend ``get_all_permissions`` / ``has_perm`` / ``get_group_permissions``
- ``Content.is_content`` / ``_contents`` / ``register_content`` /
  ``class_prepared``
- Conditions as a registry atom; mutation helpers
- Junction, Group/Role registrations
- Generic core path semantics; Zero; GH; example #7; Windows #17
- S3–S8 of #69 (Ticket is §33)

---

# External Ticket terminal (issue #72)

This record covers the S2 external AppConfig contribution. Version
remains **1.0.0.dev0**. It closes the #72 slice: a second, independent
``TrustUserPermission → Trust ← Ticket`` declaration in
``tests.apps.TestsConfig.ready()`` so ``Ticket.objects.permitted`` uses
the common relation plan. It does **not** migrate backend enumeration,
``has_perm``, ``filter_by_user_content_perm``, conditions-as-atom,
Junction, or Group/Role. There is **no schema or Django migration
change**.

## Decision

The test application owns the Ticket declaration. Trusts does not import
or discover ``tests.Ticket``. The reverse hop is taken from Django
``_meta``, not hard-coded and not from ``Content._contents``. Ticket has
its own contributor-instance + exact-registry sentinel
(``_trusts_tup_ticket_registry_id``). Completion is not inferred from
Category's sentinel or from another record targeting Ticket. Re-entry is
a no-op only when that sentinel ``is`` the current registry; the
sentinel is set only after ``register()`` succeeds.

``ContentQuerySet.permitted`` keeps the public signature and documented
results. Ticket now has ``plan.records``, so the existing switch ORs
``content_exists`` with the group-local grant on the original candidate
queryset. ``:meta_own`` and other V1 conditions remain overlays on a
complete trustee-or-group grant and never create one. Unregistered
models keep ``trust_grant_q``. Backend ``has_perm`` stays on the old
path.

### 33. Ticket trustee list path uses the registered plan (internal)

| | |
| --- | --- |
| Previous | ``Ticket.objects.permitted`` used ``trust_grant_q(..., trust_fk='trust')`` because Ticket had no plan records. |
| New | ``TestsConfig.ready()`` registers ``TrustUserPermission → Trust ← Ticket`` via Django ``_meta`` (no hard-coded reverse, no ``Content._contents``). The existing ``plan.records`` switch in ``ContentQuerySet.permitted`` lights up. Trustee is ``content_exists``; group stays OR-ed on the original candidate queryset. ``:meta_own`` remains a condition overlay. Create-under-trust ``filter_by_user_content_perm`` stays on ``trust_grant_q``. |
| Replacement | Same ``Ticket.objects.permitted(perm, user)`` call. Results, laziness, and V1 condition semantics are unchanged. |
| Affected | Internal implementation of ``Ticket`` list filtering only. ``has_perm`` remains on the old backend path. |
| Authorization | Unchanged results. Group-only rows are not dropped. Conditions never create a grant. No schema or migration. |

Migration-bot checklist:

- [ ] Do not apply a new Trusts migration; none was added.
- [ ] Do not reuse Category's sentinel or infer Ticket completion from
      ``plan_for(Ticket).records``.
- [ ] Leave ``filter_by_user_content_perm`` on ``trust_grant_q``.
- [ ] Leave backend ``has_perm`` / ``get_all_permissions`` alone.
- [ ] Leave ``Content._conditions`` and its registration/check behavior
      alone.
- [ ] Leave package version at ``1.0.0.dev0``.

## Schema

No change. S2 adds no model and no Django migration. Query
construction remains lazy.

## Out of scope (not acceptance criteria)

- Backend ``get_all_permissions`` / ``has_perm`` / ``get_group_permissions``
- ``filter_by_user_content_perm`` migration
- ``Content.is_content`` / ``_contents`` / ``register_content`` /
  ``class_prepared``
- Conditions as a registry atom; mutation helpers
- Junction, Group/Role registrations
- Path-grammar extension; registry deletion; freeze/check
- Generic core path semantics; Zero; GH; example #7; Windows #17
- S3–S8 of #69

---

# Path-scoped registries and aggregate list authorization (issue #75 / S3a)

This record covers the S3a internal routing change. Version remains
**1.0.0.dev0**. It does **not** migrate backend ``has_perm`` /
``has_perms`` / ``get_all_permissions`` / ``get_group_permissions`` /
``_trust_perm_cache``. It does **not** change ``obj is None`` behavior.
There is **no schema or Django migration change**.

Parent design: #74 r4, accepted with the S6 correction that
``HistoricalGroupQueryCompiler`` remains through S6/S7. #69 S6 registers
Group as **protected content through Junction**. It does not register
group membership as a trustee route for Category/Ticket, so the
historical group compiler is not scheduled for deletion in S6.

## Decision

``trusts.apps.AppConfig`` owns the sole
``registries[configured_backend_path] → TrustsRegistry`` store.
Configured Trusts paths are discovered by importing
``AUTHENTICATION_BACKENDS`` classes (never ``load_backend()`` / a cached
Django backend instance). A handle binds the exact path, the exact
registry identity, and the class-owned immutable query compiler.

With one Trusts path, ``config.registry`` remains a compatibility alias
of that exact registry object. With zero or several Trusts paths, alias
access fails loud. Duplicate identical path strings de-duplicate.
Different strings that resolve to the same class are an ambiguity error.

``ContentQuerySet.permitted`` stays a thin caller: active principal and
permission resolution, then ``trusts.core.granted()`` ORs each
applicable handle compiler's **complete** predicate, then the unchanged
condition overlay. Built-in concrete routes keep historical group-only
grants. Mixin-only routes receive only their registered-plan proof. If
every route is inapplicable, the transitional ``trust_grant_q`` fallback
remains only when a configured compiler advertises
``historical_fallback``.

## No change to these public call sites

- `User.has_perm` / ``User.has_perms`` signatures and backend
  implementation (still historical; ``obj is None`` unchanged)
- ``ContentQuerySet.permitted`` signature and documented allow/deny
  results on the RST one-path install
- ``Content._conditions`` / ``register_permission_condition`` /
  callable ``has_perm``
- Package version `1.0.0.dev0`
- Database schema and Trusts migrations (`0001_initial`, `0002_trustgroup`)

## Changes

### 34. Path-scoped AppConfig registries and aggregate ``.permitted()`` (internal)

| | |
| --- | --- |
| Previous | One ``AppConfig.registry``. ``.permitted`` read that unique store and inlined ``group_local_grant_exists`` for every registered terminal. |
| New | ``AppConfig.registries[path]`` is THE store. Host contributions go through ``configured_backend(path)`` (path required when several Trusts backends are listed). Package Trust-as-content is donated to every configured ``TrustModelBackend`` or subclass; mixin-only paths receive no automatic package declaration. ``.permitted`` ORs complete compiler predicates from every applicable configured Trusts path in one lazy SQL statement. |
| Replacement | Same ``Model.objects.permitted(perm, user)`` call. With one Trusts path, ``apps.get_app_config('trusts').registry`` still ``is`` that path's registry. With several, name the exact path. |
| Affected | Internal list-authorization routing. Object ``has_perm`` / permission enumeration stay on the historical backend path. |
| Authorization | One-path Category / Ticket / Trust list results are unchanged. Two Trusts paths OR complete proofs; one route's failed ceiling cannot be completed with another route's fragment. Mixin-only paths do not inherit ``TrustGroup`` behavior. A Guardian-only object grant may make ``user.has_perm(perm, obj)`` True while ``.permitted`` excludes the row (Guardian is not a Trusts path). Missing/malformed ``query_compiler`` is ``trusts.E004`` plus runtime ``TrustsCompilerError``; silencing the check does not enable fallback or omission. |

Migration-bot checklist:

- [ ] Do not apply a new Trusts migration; none was added.
- [ ] One-path hosts: ``config.registry`` and existing S1/S2 sentinels keep
      working. No call-site change for ``.permitted``.
- [ ] Hosts that list more than one Trusts-derived backend must name the
      exact path in ``configured_backend(path)`` when contributing
      Category/Ticket-style declarations. Omission fails before writing.
- [ ] A mixin-only Trusts backend does not receive package Trust-as-content
      and does not inherit historical ``TrustGroup`` list grants.
- [ ] Do not silence ``trusts.E004`` expecting ``.permitted`` to skip a
      broken compiler.
- [ ] Leave backend ``has_perm`` / ``get_all_permissions`` /
      ``get_group_permissions`` / ``obj is None`` alone (next slice).
- [ ] Leave ``Content._conditions`` and its registration/check behavior
      alone.
- [ ] Do not delete ``HistoricalGroupQueryCompiler`` in S6.
- [ ] Leave package version at ``1.0.0.dev0``.

## Schema

No change. S3a adds no model and no Django migration. Query
construction remains lazy. Evaluated ``.permitted()`` and ``[:n]`` remain
**1 SQL**.

## Out of scope (not acceptance criteria)

- Backend ``has_perm`` / ``has_perms`` / ``get_all_permissions`` /
  ``get_group_permissions`` / ``_trust_perm_cache`` migration
- ``obj is None`` false/empty boundary (lands with backend migration)
- ``common_permissions`` collection coordinator
- S4–S8, grammar extension, Junction-as-content, registry deletion,
  callback relocation
- Schema or migration changes

---

# Backend authorization on compiler handles (issue #77 / S3b)

This record covers the S3b backend migration. Version remains
**1.0.0.dev0**. There is **no schema or Django migration change**.
``Content._conditions`` and the legacy baseline are preserved.

Parent design: #74 r4, accepted. Predecessor #75 / PR #76 merged to
``dev`` as ``d7a96e9d735eeb26d7c776981fc7e288d13e6b9a``.

## Decision

Declared Category, Ticket, and Trust terminals use the same path-scoped
handle and class-owned compiler contract as ``.permitted()``. A
disposable backend instance resolves its configured path through the
AppConfig handle and never stores declarations or routing state.

- **Instance:** that backend evaluates **its own handle only**. Django
  supplies OR/union across configured backends.
- **QuerySet:** the first configured Trusts-derived path (exact strings
  de-duplicated) is the sole collection coordinator. It aggregates every
  applicable complete proof once. Other Trusts backends return
  false/empty for the collection with **0 SQL**.
- **Undeclared** terminals, including Junction/Group in this slice, stay
  on the historical ``Content._contents`` / ``_get_trusts`` fallback.
  There is no second model→path map.
- ``HistoricalGroupQueryCompiler`` remains. S6 registers Group as
  protected content; it does not replace group-as-trustee authorization.

``_trust_perm_cache`` remains a documented user-object attribute.
Reload / ``delattr`` stay safe. Registered terminals do not read or
write Trust-pk entries; the cache is not a second authorization source.
Undeclared historical enumeration may still write Trust-pk keys.

## No change to these public call sites

- `User.has_perm` / ``User.has_perms`` signatures
- ``ContentQuerySet.permitted`` signature and documented one-path results
- ``Content._conditions`` / ``register_permission_condition`` /
  callable ``has_perm``
- Package version `1.0.0.dev0`
- Database schema and Trusts migrations (`0001_initial`, `0002_trustgroup`)

## Changes

### 35. Trusts ``obj is None`` is false/empty; ModelBackend is opt-in

| | |
| --- | --- |
| Previous | ``TrustModelBackendMixin`` called ``ModelBackend`` through ``super()`` when ``obj is None`` or the user was anonymous. A host that listed only ``trusts.backends.TrustModelBackend`` inherited global Django user/group permissions from that MRO. |
| New | A Trusts backend contributes ``False`` / empty permissions when ``obj is None``. It does not call ``ModelBackend`` permission methods through ``super()``. ``TrustModelBackend`` still subclasses ``ModelBackend`` for ``authenticate`` / ``get_user`` only. That inheritance does **not** confer global permission authority. |
| Replacement | Hosts that want ordinary global Django permissions must list ``django.contrib.auth.backends.ModelBackend`` (or another global backend) **alongside** Trusts. Django OR/union then supplies model-level ``has_perm`` / enumeration. Trusts still answers object and QuerySet calls. A model-level ``Permission`` row never becomes a Trust object grant. |
| Affected | ``has_perm`` / ``has_perms`` / ``get_all_permissions`` / ``get_group_permissions`` with ``obj is None``. Object-grant signatures are unchanged. |
| Authorization | Trusts-only installs no longer grant global Django permissions. ``ModelBackend`` + Trusts restores those globals without turning them into object grants. Superuser short-circuit remains Django ``User`` / ``PermissionsMixin``, not Trusts SQL. Anonymous and inactive principals stay denied. |

Migration-bot checklist:

- [ ] If the project listed only ``trusts.backends.TrustModelBackend`` and
      relied on inherited model-level ``has_perm()`` / ``get_all_permissions()``
      (no ``obj``), add ``django.contrib.auth.backends.ModelBackend`` (or
      another global backend) to ``AUTHENTICATION_BACKENDS``.
- [ ] Confirm ``user.has_perm('app.perm', obj)`` still uses Trusts object
      proofs and that a global ``Permission`` row does not grant that
      object.
- [ ] Confirm ``user.has_perm('app.perm')`` (no ``obj``) is now False on a
      Trusts-only backend and True again after adding ``ModelBackend``
      when the user has that global permission.
- [ ] Do not call ``super().has_perm`` / ``get_all_permissions`` /
      ``get_group_permissions`` from a Trusts mixin expecting ModelBackend
      globals.
- [ ] Reload the user, or ``delattr(user, '_trust_perm_cache')``, after
      grant changes. Registered terminals do not use Trust-pk cache
      entries as an authorization source.
- [ ] Do not apply a new Trusts migration; none was added.
- [ ] Leave ``Content._conditions`` and callable ``has_perm`` behavior
      alone.
- [ ] Do not delete ``HistoricalGroupQueryCompiler`` in S6.
- [ ] Leave package version at ``1.0.0.dev0``.

### 36. Declared-terminal backend authorization uses the compiler handle (internal)

| | |
| --- | --- |
| Previous | ``has_perm`` / ``get_all_permissions`` / ``get_group_permissions`` walked ``_get_trusts`` / ``Content._contents`` and, for ``obj is None``, ``ModelBackend.super()``. QuerySet answers were per-backend intersections that Django then OR/unioned (``(∀C A) OR (∀C B)``). |
| New | Declared Category / Ticket / Trust terminals use the path-scoped registry and the class-owned compiler. Instance calls evaluate that backend's handle only. QuerySet calls are coordinated once: SQL all-match of the aggregate complete proof, and common-permission enumeration is the intersection across every candidate of that same predicate. ``get_group_permissions`` uses group-only complete proofs; trustee grants do not leak into that surface. |
| Replacement | Same ``user.has_perm(perm, obj)`` / ``has_perms`` / ``get_*_permissions`` calls. QuerySet authorization remains a Trusts extension (all-match, not a Python per-object loop). |
| Affected | Internal backend routing for already-declared terminals. Junction/Group stay on the historical path. |
| Authorization | One-path results for Category / Ticket / Trust are unchanged. Two Trusts paths: Django OR of per-object complete proofs; QuerySet ``has_perm`` / common enumeration use the aggregate predicate so split coverage (A grants C1, B grants C2) is granted. A failed ceiling on one path cannot borrow another path's trustee/group fragment. Mixin-only compilers never inherit ``TrustGroup``. |

Migration-bot checklist:

- [ ] No call-site change for ``has_perm`` / ``has_perms`` / enumeration
      on declared terminals.
- [ ] Hosts with several Trusts-derived backends keep naming the exact
      path when contributing. QuerySet authorization is coordinated by
      the first configured Trusts path.
- [ ] Do not silence ``trusts.E004`` expecting ``has_perm`` to skip a
      broken compiler.
- [ ] Leave undeclared Junction/Group on the historical path.
- [ ] Leave ``filter_by_user_content_perm`` and ``Content._contents``
      alone (later slices).
- [ ] Leave package version at ``1.0.0.dev0``.

### 37. Historical fallback is a concrete-compiler capability (internal)

| | |
| --- | --- |
| Previous (#78) | Instance ``has_perm`` / enumeration gated non-QuerySet objects through ``Content.is_content`` before the handle. ``None`` from the aggregate always called ``_historical_*`` / ``trust_grant_q``. QuerySet plus a callable condition ran SQL, then iterated ``obj.all()`` to invoke the callback. |
| New | An instance consults the owning handle/compiler first. ``Content.is_content`` only decides whether the **concrete historical fallback** is available after that handle is inapplicable. ``historical_fallback`` is advertised on ``HistoricalGroupQueryCompiler`` / ``BackendHandle``; mixin-only compilers do not inherit ``Content._contents``, TUP, or TrustGroup. Junction/Group fallback stays on the concrete route during transition. QuerySet plus a callable raises ``PermissionConditionNotQueryable`` before candidate SQL or callback invocation. The enabled single-object callback path is unchanged. |
| Replacement | Same ``has_perm`` / ``has_perms`` / ``get_*_permissions`` / ``.permitted`` call sites. Register an ordinary (non-``Content``) model on the path-scoped registry to authorize it; do not expect ``Content._contents`` membership. |
| Affected | Internal routing for registered non-``Content`` models, mixin-only hosts, and QuerySet ``:condition`` callables. |
| Authorization | A mixin-only install with no plan cannot authorize from leftover TUP / TrustGroup rows. A concrete ``TrustModelBackend`` still authorizes undeclared Junction/Group. An inapplicable mixin route neither adds nor suppresses the concrete route's fallback. QuerySet authorization still has no Python per-object loop. |

Migration-bot checklist:

- [ ] Do not expect ``user.has_perm(perm, obj)`` to deny a registered
      ordinary model merely because it is absent from ``Content._contents``.
- [ ] A mixin-only Trusts backend still does not inherit historical
      ``TrustGroup`` / TUP fallback when no plan applies, including
      ``.permitted()``.
- [ ] Leave Junction/Group on the concrete historical route until S6.
- [ ] Do not call ``has_perm`` / ``has_perms`` with a QuerySet and a
      callable ``:condition``; catch ``PermissionConditionNotQueryable``
      or register an ``Expr``.
- [ ] Leave package version at ``1.0.0.dev0``.

### 38. `filter_by_user_content_perm` registration gate (internal)

| | |
| --- | --- |
| Previous | ``Trust.objects.filter_by_user_content_perm`` opened when ``Content.is_content_model`` found the argument in ``Content._contents``, then filtered Trust rows with ``trust_grant_q``. Junction-backed Group and any auto-registered Content subclass passed that gate even with no path-scoped declaration. |
| New | Support is ``any_plan_records(configured_handles(), content)``: any configured Trusts path with ``plan_for(content).records`` establishes that the terminal is known. The grant stays ``trust_grant_q`` on Trust rows (create-under-Trust). Unregistered models return ``none()`` without running the grant query. ``Content._contents``, ``historical_fallback``, and ``filter_authorized(Trust)`` are not consulted. |
| Replacement | Same ``filter_by_user_content_perm(user, content, perm_name, exclude_root=True)`` signature and documented Category / Ticket / Trust / ``NewTeamForm`` Trust-``change`` callers. |
| Affected | Internal registration gate only. Junction/Group stay undeclared until S6 and now fail this create-under-Trust picker closed. |
| Authorization | One-path Category / Ticket / Trust results are unchanged. A declaration on one of several Trusts paths supports the terminal but does not authorize through another path's compiler. Wrong permission, wrong Trust, inactive/anonymous, excluded root, and ``:condition`` behave as before. A proxy of a registered terminal uses the same ``concrete_model`` the plan already selects (same permission identity as the concrete class). |

This is an internal gate migration: public signature, permission identities, and create-under-Trust grant semantics are unchanged. Callers that already pass a registered Category / Ticket / Trust terminal do not change. Hosts that passed an undeclared model (including Junction/Group still listed in ``Content._contents``) now receive ``none()``.

Migration-bot checklist:

- [ ] Keep calling ``filter_by_user_content_perm(user, Model, perm)`` for
      create-target Trust pickers. Do not switch it to
      ``filter_authorized(Trust)`` or ``.permitted()`` on Trust-as-content.
- [ ] Register the content terminal on a configured Trusts path before
      expecting this picker to list Trusts. ``Content`` subclassing alone
      is no longer enough.
- [ ] Do not pass Junction/Group here until S6 declares that terminal.
- [ ] Do not pass ``:condition`` (still refused before the gate).
- [ ] Do not apply a new Trusts migration; none was added.
- [ ] Leave package version at ``1.0.0.dev0``.

## Schema

No change. This S4 slice adds no model and no Django migration.

## Out of scope (not acceptance criteria)

- S5 grammar extension, S6 Junction/Group declaration, S7
  static-registry deletion, S8 freeze/E003
- Callback relocation; condition registry
- Schema or migration changes
- Zero, GH, example #7, Windows #17

---

# Bounded Ref dependent-content grammar (issue #83)

This record covers the additive ``trusts.core`` content-path grammar
extension. Version remains **1.0.0.dev0**. It closes the #83 / #69 r2
S5 slice (isolated mocks only). It does **not** contribute
Group/Junction, delete ``Content._contents``, freeze the registry, or
change authorization results. There is **no schema or Django migration
change**.

## Decision

A content ``Ref`` path may still be the existing direct single-valued
hop. It may also be one or more forward single-valued hops, then a
reverse one-to-many **gateway**, then zero, one, or two suffix hops.
A suffix hop is a forward single-valued, reverse one-to-one, or reverse
one-to-many relation. User and permission paths stay one direct
single-valued hop. Bindings and ``EXISTS`` still use the complete
``'__'.join(path)`` lookup and the last hop's single ``PathInfo``
target field, including ``to_field``.

This is the smallest generic rule that represents Junction (forward →
reverse O2M → forward) and both documented dependent-content depths.
Core stays noun-blind: no Trust, Content, Junction, Receipt, Group, or
other historical-noun branch.

## No change to these public call sites

- `User.has_perm` / ``User.has_perms`` / ``ContentQuerySet.permitted``
  signatures
- ``Content`` / ``Junction`` registration, ``class_prepared`` dispatch,
  and ``Content._contents``
- Authentication-backend composition and undeclared-terminal fallbacks
- Package version `1.0.0.dev0`
- Database schema and Trusts migrations (`0001_initial`, `0002_trustgroup`)

## Changes

### 39. Content paths may continue past the reverse O2M gateway (new, additive)

| | |
| --- | --- |
| Previous (#65 / §30) | Content was a direct single-valued hop or ``(forward single-valued)+`` then exactly one final reverse one-to-many. Anything after that reverse was rejected, including Junction's trailing forward and both documented dependent suffix depths. |
| New | Content is that same direct hop, or ``(forward single-valued)+ reverse O2M suffix{0..2}``. The first reverse is the gateway and must be reverse O2M after at least one forward hop. Each suffix hop is forward single-valued, reverse O2O, or reverse O2M. Zero suffixes preserve every #65 trailing-reverse registration. One suffix expresses Junction and the first documented dependent level. Two suffixes express the second documented dependent level, including reverse O2M, reverse O2O, and parent-held forward encodings. |
| Replacement | None for existing callers. Isolated ``register`` / ``plan_for`` / projection call sites stay the same. Register a gateway-plus-suffix path when the terminal is one or two hops past the first reverse. |
| Affected | Isolated ``trusts.core`` development callers. Direct one-hop and trailing-reverse registrations keep the same lookup and #64 target-field ``OuterRef``. |
| Authorization | Unchanged for historical Trusts. Object authorization, aggregate QuerySet all-match, and ``common_permissions`` use the stored full lookup. Direct versus group-only contribution stays a compiler concern, not a Python per-object loop. No schema or migration. |

Rejected during ``register`` (zero SQL, no partial record): reverse
before the gateway, including a reverse-only path; reverse O2O as the
gateway; many-to-many; generic foreign keys; suffix depth greater than
two; all-forward multi-hop content; composite / multi-column targets;
implicit reverse-name guessing; arbitrary getters; executable path
components; mixed roots; and the existing #57/#65 duplicate/conflict
cases.

Migration-bot checklist:

- [ ] Do not apply a new Trusts migration; none was added.
- [ ] Import ``TrustsRegistry`` / ``RelationPlan`` from ``trusts.core``, not ``trusts``.
- [ ] Direct and trailing-reverse content paths stay valid; do not rewrite them.
- [ ] Register Junction / documented dependents only after S6 / S7. This
      slice extends the grammar; it does not contribute those terminals.
- [ ] Leave ``Content._contents``, ``register_content``, and
      ``Junction.register_junction`` in place.
- [ ] Leave undeclared-terminal incremental fallbacks in place.
- [ ] Leave package version at ``1.0.0.dev0``.

## Schema

No change. The bounded dependent-content grammar adds no model and no
migration. Query construction remains lazy.

## Out of scope (not acceptance criteria)

- S6 Group/Junction contribution or backend migration
- S7 static-registry deletion
- S8 freeze / E003
- Condition-registry work; callback relocation; #54
- Zero; GH; example #7; Windows #17

---

# Junction-backed Group terminal (issue #85 / S6)

This record covers the S6 host contribution and backend routing change.
Version remains **1.0.0.dev0**. It closes the #85 / #69 r2 S6 slice:
explicit `TrustUserPermission → Trust ← Junction → Group` on the
configured Trusts handle, and Group object authorization on that
registered plan. It does **not** delete `Content._contents`, freeze
the registry, or reinterpret Django group membership as a trustee
route for Category / Ticket / Trust. There is **no schema or Django
migration change**.

Parent design: #69 r2 (accepted), with the #74 r4 correction that
Group-as-protected-content does not replace historical group-as-trustee
authorization. Predecessor #83 / PR #84 merged to `dev` as
`0a1f7f50dd618b23ab153d475200152eb6682632`.

## Decision

The host/test application owns the Group/Junction contribution in its
`AppConfig` lifecycle. Trusts does not import or discover host Junction
or Group models. The Trust→Junction reverse accessor and the
Junction→content field come from Django `_meta` and the concrete
Junction contract (`get_content_model()`). The path is the J1 shape
admitted by S5: forward `trust`, reverse O2M gateway, forward content.

Contribution binds to one exact configured backend handle. Contributor-
instance + exact-registry sentinels use identity comparison, are set
only after `register()` succeeds, treat same-instance re-entry as a
no-op, and contribute again for a new or swapped registry. Omitted,
ambiguous, or unconfigured paths and malformed contributions fail
loudly with no partial Group record.

Group is the **protected content terminal through Junction**. Direct
trustee (`content_exists`) and retained historical TrustGroup grants
OR on the original candidate queryset under the existing Trust
ceiling. The TrustGroup EXISTS for Group candidates is derived from
the registered path / Junction `_meta`, not from `Content._contents`
and not from a Group/Junction branch in `core.py`. Mixin-only
backends do not inherit `HistoricalGroupQueryCompiler`.

After this slice, Group `has_perm` / `has_perms` /
`get_all_permissions` / `get_group_permissions` (instance and
QuerySet) use the S3 registered relation plan and coordinator. Group
no longer reaches `_get_trusts` / `filter_by_content`. Those methods
and the static content registry remain until S7. Still-undeclared
terminals keep the incremental historical fallback.

## No change to these public call sites

- `User.has_perm` / `User.has_perms` / `get_all_permissions` /
  `get_group_permissions` signatures
- `ContentQuerySet.permitted` signature and documented Category /
  Ticket / Trust results
- `filter_by_user_content_perm` signature and create-under-Trust
  grant (`trust_grant_q` on Trust rows)
- `Content._contents` / `register_content` / `is_content*` /
  `filter_by_content` / `_get_trusts` (still present)
- Package version `1.0.0.dev0`
- Database schema and Trusts migrations (`0001_initial`, `0002_trustgroup`)

## Changes

### 40. Junction-backed Group uses the registered J1 plan (internal)

| | |
| --- | --- |
| Previous | Group object authorization walked `_get_trusts` / `filter_by_content` / `Content._contents`. `filter_by_user_content_perm(user, Group, …)` failed closed because Group had no path-scoped records. |
| New | The host AppConfig registers `TUP → Trust ← Junction → Group`. Group instance and QuerySet authorization use the registered plan plus the concrete compiler's TrustGroup OR. Mixin-only compilers receive only a contributed plan (trustee), never historical TrustGroup. `obj is None` stays false/empty. Conditions remain overlays. `filter_by_user_content_perm` treats Group as a known terminal; the grant is still `trust_grant_q` on Trust rows. |
| Replacement | Same `user.has_perm('auth.change_group', group)` / QuerySet / enumeration call sites. Hosts contribute the J1 path from their own `AppConfig.ready()` through `configured_backend()`. |
| Affected | Internal routing for Group objects. Category, Ticket, and Trust stay on their existing declarations. Junction itself is not a content terminal. |
| Authorization | Direct trustee and TrustGroup grants on the Junction's Trust still allow. Wrong user, wrong permission, sibling Trust, inactive/anonymous, and `obj is None` still deny. Membership in the protected Group is not a trustee route for other content. No Python per-object loop. |

Failure behavior: omitted/ambiguous `configured_backend()` and
unconfigured paths raise `TrustsConfigurationError` before writing.
A conflicting Group registration raises and does not set the Group
sentinel (no partial Group record). Same-contributor re-entry against
the same registry object is a no-op.

Migration-bot checklist:

- [ ] Do not apply a new Trusts migration; none was added.
- [ ] Contribute Junction-backed Group from the project `AppConfig`,
      deriving the reverse accessor and content field from `_meta` /
      `get_content_model()`. Do not hard-code historical accessor names
      or read `Content._contents`.
- [ ] Name the exact Trusts path in `configured_backend(path)` when
      more than one Trusts backend is listed.
- [ ] Do not expect Trusts to import or discover host Junction/Group
      models.
- [ ] Do not treat Django group membership as a Category/Ticket/Trust
      trustee route.
- [ ] A mixin-only Trusts backend still does not inherit historical
      TrustGroup unless it uses `HistoricalGroupQueryCompiler`.
- [ ] Leave `Content._contents`, `register_content`, `is_content*`,
      `filter_by_content`, and `_get_trusts` in place until S7.
- [ ] Leave package version at `1.0.0.dev0`.

## Schema

No change. S6 adds no model and no Django migration. Query
construction remains lazy. Group grant / all-match / enumeration
projections remain **1 SQL**, independent of candidate count.

## Out of scope (not acceptance criteria)

- S7 deletion of `Content._contents`, `register_content`,
  `is_content*`, `get_content_fieldlookup`, `filter_by_content`,
  `_get_trusts`, or content signal hooks
- S8 freeze / E003
- Condition-registry work; callback relocation; group/role redesign;
  #54
- Zero; GH; example #7; Windows #17

---

# Delete the legacy static content registry (issue #87 / S7)

This record covers the S7 deletion of the static content-model map
and its remaining readers/writers. Version remains **1.0.0.dev0**.
It closes the #87 / #69 r2 S7 slice. Category, Ticket, Trust, Group,
and both documented dependent-content levels are authorized only
through explicit path-scoped contributions. The condition registry
and the concrete `HistoricalGroupQueryCompiler` remain. There is
**no schema or Django migration change**.

Parent design: #69 r2 (accepted). Predecessor #85 / PR #86 merged to
`dev` as `28c8876c436d197b365e2fc5d9029241a989cee6`.

## Decision

The process-global `Content._contents` model→fieldlookup map is gone.
Supported terminals are recognized only through exact configured
backend-handle registries. Hosts declare dependents in their own
`AppConfig.ready()` with bounded S5 `Ref` paths. Trusts does not
import, discover, or infer undeclared models.

Unknown or undeclared terminals fail closed: object `has_perm` is
false, enumeration is empty, and QuerySet authorization is
none/false. There is no renamed process-global model→path map, no
model-name branch, no implicit discovery, and no historical
`_get_trusts` / `filter_by_content` fallback.

`HistoricalGroupQueryCompiler` still ORs registered-plan trustee
proofs with historical TrustGroup grants for declared terminals.
Registering Group as protected content does not replace Django Group
membership as the historical trustee path for Category / Ticket /
Trust. Mixin-only compilers still do not inherit that TrustGroup OR.
`historical_fallback` identifies the concrete compiler; it does not
reopen a static content map.

Condition declarations remain overlays on an existing relational
grant. `Meta.permission_conditions`, Junction
`content_permission_conditions`, `Content._conditions`, getters,
iteration, system checks, Ticket `meta_own`, Trust `own`, and
current callback behavior are unchanged.

## No change to these public call sites

- `User.has_perm` / `User.has_perms` / `get_all_permissions` /
  `get_group_permissions` signatures
- `ContentQuerySet.permitted` signature and documented Category /
  Ticket / Trust results
- `filter_by_user_content_perm` / `filter_by_user_perm` signatures
  and create-under-Trust grant (`trust_grant_q` on Trust rows)
- `Content.register_permission_condition` and condition lookup APIs
- `HistoricalGroupQueryCompiler` complete / group proofs for
  declared terminals
- Package version `1.0.0.dev0`
- Database schema and Trusts migrations (`0001_initial`, `0002_trustgroup`)

## Changes

### 41. Static content map and its readers/writers are deleted

| | |
| --- | --- |
| Previous | `Content._contents` plus `register_content` / `is_content*` / `get_content_fieldlookup` auto-published every concrete Content/Junction terminal. Backend `_get_trusts` and `TrustManager.filter_by_content` resolved object→Trust through that map. Undeclared Content subclasses still authorized through the concrete `historical_fallback` route. RST Inheritance composed field lookups with `register_content`. |
| New | Those APIs and the content-map half of `class_prepared` / `Junction.register_junction` are gone. `Content.register_content` and `Junction.register_junction` walk Meta condition options only. Terminals are known only when an exact configured handle has `plan_for(model).records`. Undeclared terminals fail closed and never reach a content-map fallback. Both documented dependent levels are explicit AppConfig `Ref` contributions (`getattr(j.trust, rev).image` and `.image.image`). |
| Replacement | Host `AppConfig.ready()` → `configured_backend().registry.register(...)` with a bounded S5 `Ref`. Same `user.has_perm` / QuerySet / `.permitted` / `filter_by_user_content_perm` call sites. |
| Affected | Internal discovery and the deleted helpers. Registered Category / Ticket / Trust / Group authorization is unchanged. Manual dependents that were only in `_contents` must be declared. |
| Authorization | Declared terminals keep trustee \| TrustGroup allow/deny, mixed-scope denial, direct vs group-only split, inactive/anonymous/`obj=None` denial, and one-SQL grant / all-match / enumeration. Undeclared terminals are false / empty / none. Conditions still cannot create a grant. |

Failure behavior: omitted/ambiguous `configured_backend()` still raises
`TrustsConfigurationError` before writing. A conflicting contribution
still raises without setting that contribution's sentinel. Same-
contributor re-entry against the same registry object is a no-op.
`isolate_apps` without `trusts` still does not donate.

### 42. Removed APIs (direct migration)

| Removed | Caller migration |
| --- | --- |
| `Content._contents` | Do not read or write a process-global model→path map. Ask `configured_backend().registry.plan_for(model).records`. |
| `Content.register_content(model, fieldlookup)` | Declare the terminal in the host `AppConfig` with `Ref`. The remaining `register_content(model)` walks `Meta.permission_conditions` only. |
| `Content.is_content_model` / `Content.is_content` | `bool(handle.registry.plan_for(obj).records)` on the exact configured handle. Absence is fail-closed, not a fallback. |
| `Content.get_content_fieldlookup` | No replacement API. Dependents use `getattr(j.trust, reverse).…` from Django `_meta`. |
| `TrustManager.filter_by_content` | Not a public authorization API. Object checks use `has_perm` / the registered plan. |
| `TrustModelBackend._get_trusts` | Gone. Instance and QuerySet authorization use compiler handles. |
| Content-map half of `Junction.register_junction` / `register_content_junction` | Junction-backed terminals are host `Ref` contributions (S6). The signal still registers Junction `content_permission_conditions`. |
| Module-level `Content.register_content(Trust)` | Trust-as-content stays the package `AppConfig` contribution. Trust `:own` stays a Meta condition. |

Migration-bot checklist:

- [ ] Do not apply a new Trusts migration; none was added.
- [ ] Delete project reads/writes of `Content._contents`,
      `is_content_model`, `is_content`, `get_content_fieldlookup`,
      `filter_by_content`, and `_get_trusts`.
- [ ] Replace every `Content.register_content(model, fieldlookup)`
      content registration with an AppConfig `Ref` contribution on
      `configured_backend()`. Keep Meta `permission_conditions` as
      condition overlays.
- [ ] Declare both documented dependent levels if the project used
      ReceiptImage / ReceiptImageMeta-style fieldlookup chaining.
- [ ] Treat undeclared terminals as fail-closed. Do not expect
      `class_prepared` or Content subclassing to authorize a model.
- [ ] Do not invent a replacement model→path map, model-name branch,
      or implicit discovery helper.
- [ ] Do not treat Django group membership as a Category/Ticket/Trust
      trustee route, and do not drop `HistoricalGroupQueryCompiler`.
- [ ] Leave package version at `1.0.0.dev0`.

## Schema

No change. S7 adds no model and no Django migration. Query
construction remains lazy. Supported grant / all-match / enumeration
projections remain **1 SQL**, independent of candidate count.

## Out of scope (not acceptance criteria)

- S8 registry freeze / E003
- Condition-registry redesign; callback relocation; group/role
  redesign; #54
- Zero; GH; example #7; Windows #17

---

# Freeze live registries and report detectable missing declarations (issue #89 / S8)

This record covers the S8 freeze of AppConfig-owned path-scoped
registries and the `trusts.E003` missing-declaration check. Version
remains **1.0.0.dev0**. It closes the #89 / #69 r2 S8 slice, the final
#69 implementation slice. Standalone `TrustsRegistry()` instances stay
independent. There is **no schema or Django migration change**.

Parent design: #69 r2 (accepted). Predecessor #87 / PR #88 merged to
`dev` as `df9b51858047566574f378c3df2b648fb386fd4e`.

## Decision

Live AppConfig-owned registries freeze after Django application
population so authorization plans cannot mutate late. Freeze is
instance-owned (`TrustsRegistry.freeze()` / `.frozen`).
`register()` on that exact frozen instance raises
`TrustsConfigurationError` before validation or mutation. Existing
records, plans, compilers, and authorization reads stay usable.

A standalone `TrustsRegistry()` does not inspect Django's global
readiness and never auto-freezes. It stays writable after global
`apps.ready` unless its owner calls `freeze()`. Frozen state is not
process-global, class-global, inferred from Django's global
`apps.ready`, or shared across registry objects.

Freeze is owned by `trusts.apps.AppConfig` for the existing objects in
its path-scoped `registries` store. `ready()` does not replace those
objects. Every supported live access surface —
`configured_backend(path)`, `configured_handles()`, and the one-path
`registry` alias — returns the same stored object and freezes it on
first read when **that AppConfig's `self.apps.ready`** is true. During
`Apps.populate`, external contributors run in their own `ready()` while
that Apps instance is not yet ready, so declarations remain writable
regardless of `INSTALLED_APPS` order. After population, a newly
ensured/configured live path is frozen before exposure.

Re-entering a package or host contributor after freeze is a sentinel
no-op when that contributor already donated to the exact registry. A
genuinely new, failed, or partial late contribution raises.

`trusts.E003` reports structurally detectable missing Content/Junction
declarations from already-loaded models. It does not import host
modules, does not infer manual dependents, and issues **0 SQL**.
Undeclared manual dependents continue to fail closed at runtime with no
E003 row. Silencing E003 suppresses only the early diagnostic and never
creates authorization.

## No change to these public call sites

- `User.has_perm` / `User.has_perms` / `get_all_permissions` /
  `get_group_permissions` signatures
- `ContentQuerySet.permitted` signature and documented Category /
  Ticket / Trust results
- `filter_by_user_content_perm` / `filter_by_user_perm` signatures
  and create-under-Trust grant (`trust_grant_q` on Trust rows)
- Condition registry APIs and E001/E002/W001/E004 checks
- Package version `1.0.0.dev0`
- Database schema and Trusts migrations (`0001_initial`, `0002_trustgroup`)

## Changes

### 43. Live registries freeze after populate

| | |
| --- | --- |
| Previous | Live AppConfig-owned path-scoped registries stayed writable for the process lifetime. A late `register()` after `Apps.populate` could still mutate authorization plans. Isolated `TrustsRegistry()` instances were already independent. |
| New | `TrustsRegistry.freeze()` / `.frozen` are instance-owned. Supported live handle reads freeze the stored object once that AppConfig's `self.apps.ready` is true. The one-path `registry` setter freezes a replacement before storing it after readiness, so a caller-held reference cannot mutate late. Assignment before ready stays writable and freezes on the first supported post-populate read. `register()` on that frozen instance raises `TrustsConfigurationError` before validation or mutation and leaves records unchanged. Standalone `TrustsRegistry()` instances stay writable unless explicitly frozen. |
| Replacement | Hosts contribute from their own `AppConfig.ready()` through `configured_backend()` / `configured_handles()` / the one-path `registry` alias. Do not use `registries[path]` as a contributor route. |
| Affected | Late `register()` after populate. Existing declared terminals keep the same authorization results. |
| Authorization | Frozen plans still project. Undeclared terminals stay false / empty / none. A late write cannot add authorization after freeze. |

Failure behavior: every register attempt after freeze (valid, duplicate,
conflicting, malformed) raises with records unchanged. Same-contributor
re-entry against the exact frozen registry is a sentinel no-op. A new
or partial late contribution raises without setting that contribution's
sentinel.

### 44. `trusts.E003` detectable-domain check

| | |
| --- | --- |
| Previous | Missing Content/Junction declarations were fail-closed only at authorization time. `trusts.E003` was reserved. |
| New | A Django model system check walks `apps.get_models()` and reports each concrete, non-proxy, non-abstract `Content` subclass with no covering relation-plan record on any valid configured Trusts handle, and each concrete, non-proxy, non-abstract `Junction` subclass whose `get_content_model()` has no covering record on any valid handle. Coverage on one exact handle is enough. A malformed Junction content-model contract is a deterministic diagnostic, not a `manage.py check` crash. The check performs 0 SQL and does not call `registry.register`. |
| Replacement | Contribute an explicit AppConfig `Ref` on the intended exact backend path. Silencing `trusts.E003` hides only this diagnostic. |
| Affected | Early diagnostics for undeclared Content/Junction models. Manual dependents such as ReceiptImage / ReceiptImageMeta stay outside E003. |
| Authorization | E003 never creates a grant. Undeclared manual dependents remain false / empty / none at runtime. |

### 45. Bounded SQLite `Along` reachability

| | |
| --- | --- |
| Previous | Registered content correlation was equality at the terminal (`Exists` + `OuterRef`). There was no recursive walk, no `Along`, and no database-tagged renderer check. |
| New | Optional `Along(ref, bound)` on `TrustsRegistry.register()` stores immutable walk metadata (S/C/E edge, walk-site identity, suffix path). V1 compiles grant-anchored `GrantReach` only for `django.db.backends.sqlite3` with JSON functions and recursive CTEs: one uncorrelated `IN (WITH RECURSIVE …)` per recursive record, depth 0 included, bound `1..64`, identity-level cycle suppression, suffix `EXISTS` from stored path names. Integer, text, and UUID identities are whitelisted; mixed/unsupported identities raise before mutation. `trusts.E005` (`Tags.database`) reports each selected alias that cannot render live Along records. |
| Replacement | Hosts that need ancestor/descendant (or edge-table) reachability pass `along=Along(...)` at contribution time. Direct registrations stay equality. Unsupported vendors raise `TrustsConfigurationError` at compile; residual SQLite JSON/CTE errors stay database exceptions. |
| Affected | New Along registrations and `manage.py check --database …`. Existing non-recursive plans, SQL, and results are unchanged. |
| Authorization | A grant at a walk-site authorizes candidates whose associated walk-site identity is in the bounded reachable set `W`. Conditions still AND-narrow a complete proof and never run on intermediate walk nodes. Direct + recursive records `OR`. |

## Host AppConfig timing

Contribute during the host `AppConfig.ready()` while `Apps.populate`
has not set `ready`. After populate, the first supported live handle
read freezes the stored registry. Re-entry is safe only as a sentinel
no-op against the exact registry already donated to.

## Rollback

Remove AppConfig-owned freezing and the `trusts.E003` check only.
S1–S7 explicit registrations and static-registry deletion remain.
To drop Along, omit `along=` and ignore `trusts.E005`; non-recursive
plans stay valid.

## Migration-bot checklist

- [ ] Do not apply a new Trusts migration; none was added.
- [ ] Move host `register()` calls into `AppConfig.ready()` on the
      intended exact backend path via `configured_backend()`.
- [ ] Do not contribute through `registries[path]` after populate.
- [ ] Treat a frozen `register()` as a configuration error, not a
      partial write.
- [ ] Address `trusts.E003` by declaring the Content/Junction terminal.
      Do not expect E003 for arbitrary manual dependents.
- [ ] Silencing `trusts.E003` does not authorize the missing terminal.
- [ ] Pass `along=Along(ref, bound)` only when bounded walk-site
      reachability is intended. `bound` is `1..64`. Identity fields
      must be one V1 integer, text, or UUID family.
- [ ] Run `manage.py check --database <alias>` for every alias that
      will compile Along queries. Bare `manage.py check` does not
      execute E005 and is not an all-clear.
- [ ] Silencing `trusts.E005` does not enable a non-sqlite3 renderer.
- [ ] Do not expect PostgreSQL / MySQL / MariaDB / Oracle Along SQL.
- [ ] Leave package version at `1.0.0.dev0`.

## Schema

No change. S8 and #92 add no model and no Django migration. Query
construction remains lazy. Supported grant / all-match / enumeration
projections remain **1 SQL**, independent of candidate count. E003
issues **0 SQL**. E005 issues capability SQL only when Django passes a
non-empty `databases` list.

## Out of scope (not acceptance criteria)

- Condition-registry redesign; callback relocation; group/role
  redesign; #54
- Backend/module extraction; PostgreSQL / MySQL / MariaDB / Oracle
  recursive renderers
- Zero; GH; example #7; Windows #17

## Changes (#54 C1)

### 46. Generic public seams (#54 C1)

| | |
| --- | --- |
| Previous | Content list filtering was `ContentQuerySet.permitted(perm, user)` (Django permission codec: inactivity, string/` :condition` parse, `get_permission`). Create-under-Trust was `Trust.objects.filter_by_user_content_perm` via `trust_grant_q`. Condition overlay imported `trusts.models.Content`. Registry access used `apps.get_app_config('trusts')`. |
| New | Additive generic seams, same historical APIs unchanged: `AuthorizedQuerySet.authorized(user, permission, extra_q=None)` / `AuthorizedManager` (`trusts.query`); `filter_authorized_scopes(queryset, user, permission, *, content, handles=None)` (`trusts.core`); `ConditionLookup` + `TrustsRegistry.set_condition_lookup`; `trusts.apps.kernel_config()`. App label remains `trusts`. Models, migrations, `trust_grant_q`, and `HistoricalGroupQueryCompiler` stay. No Zero import on kernel paths. |
| Replacement | Instance-only hosts call `.authorized(user, permission_instance)` or `registry.filter_authorized`. Create-under-scope hosts that already have a permission instance call `filter_authorized_scopes`. Zero's later `.permitted` / `filter_by_user_content_perm` codecs wrap these. `kernel_config()` is the label-agnostic kernel accessor (today identical to `get_app_config('trusts')`). |
| Affected | New public names only. Existing `permitted` / `has_perm` / `filter_by_user_content_perm` call sites are unchanged. |
| Authorization | `.authorized` uses `granted(...)` on configured handles (complete proof, including the live historical TrustGroup compiler). `filter_authorized_scopes` is registered-relation prefix `EXISTS` only (no historical TrustGroup OR). Prefix correlation uses each hop's resolved target field (`get_path_info()` attname, including non-PK `to_field`), not an assumed candidate PK. Wrong permission type is `TrustsConfigurationError` with **0 SQL**. Unknown prefix / empty handles / content-terminal queryset / unbound instance-only lookup fail closed. `extra_q` never creates a grant. |

Failure behavior: string / non-instance `permission` raises before SQL.
Missing `ConditionLookup` methods raise `TrustsConfigurationError` and
leave any previous binding unchanged (no partial bind). Unregistered
condition codes stay `AttributeError`. Callables stay
`PermissionConditionNotQueryable` and are never invoked.

## No change to these public call sites

- `User.has_perm` / `User.has_perms` / `get_all_permissions` /
  `get_group_permissions` signatures
- `ContentQuerySet.permitted` signature and documented Category /
  Ticket / Trust results
- `filter_by_user_content_perm` / `filter_by_user_perm` signatures
  and create-under-Trust grant (`trust_grant_q` on Trust rows)
- Condition registry APIs (`Content.register_permission_condition`)
  and E001/E002/W001/E003/E004/E005 checks
- `trusts.apps.AppConfig` `name='trusts'` / `label='trusts'`
- Package version `1.0.0.dev0`
- Database schema and Trusts migrations (`0001_initial`, `0002_trustgroup`)

## Migration-bot checklist

- [ ] Do not apply a new Trusts migration; none was added.
- [ ] Do not change `INSTALLED_APPS` from `'trusts'` on this C1 head.
- [ ] Do not import `trusts.zero`. Zero is not a C1 dependency.
- [ ] Instance-only list filtering: `AuthorizedManager` /
      `.authorized(user, permission_instance)`. Do not attach
      `.permitted` or `.get_permission` to that manager.
- [ ] Django-permission codec callers keep `Content.objects.permitted(perm, user)`
      and `Model.objects.get_permission(...)`.
- [ ] Create-under-Trust stays `Trust.objects.filter_by_user_content_perm`
      on this head. `filter_authorized_scopes` is the generic prefix
      projection for hosts that already hold a permission instance.
- [ ] Bind `ConditionLookup` only from a later Zero `AppConfig.ready()`.
      Unbound C1 overlay keeps the historical `Content` condition store.
- [ ] Prefer `kernel_config()` for new kernel-store access. Existing
      `get_app_config('trusts')` still works while the label is `trusts`.
- [ ] Leave `trust_grant_q` / `HistoricalGroupQueryCompiler` in place.
- [ ] Leave package version at `1.0.0.dev0`.

## Schema

No change. C1 adds no model and no Django migration. Query construction
remains lazy. Fail-closed construction (wrong type / unknown prefix /
empty handles / unbound no-op) issues **0 SQL**. Compiled
`.authorized` / `filter_authorized_scopes` evaluations stay **1 SQL**.

## Out of scope (not acceptance criteria)

- App-label change (`trusts_core`); model or migration move; PEP 562
  `trusts.models` shim
- Deleting `trust_grant_q` / `HistoricalGroupQueryCompiler`
- G1, Windows #17
- Zero `.permitted` / `ContentManager` codec; GH adoption; docs
  restructuring beyond these APIs; examples; admin work

## Changes (#96 C2)

### 47. Kernel app identity extraction (#96 C2)

Paired with approved django-trusts-zero Z1 at
`41d07f40e676f75389b91219106440932d402b53`. Do not merge C2 or Z1
alone. Merge order is C2 then Z1 when both are green.

| | |
| --- | --- |
| Previous (C1) | Kernel `AppConfig` `name='trusts'` `label='trusts'`. Concrete models in `trusts.models`. Historical migrations `trusts.0001_initial` / `trusts.0002_trustgroup` shipped by the kernel. Registry lookups via `apps.get_app_config('trusts')` (same object as `kernel_config()`). Package Trust-as-content donated from `AppConfig.ready()`. |
| New (C2) | Kernel `name='trusts'` `label='trusts_core'`. `trusts.models` is a PEP 562 shim (no `Model` subclasses; no Zero import during `import_models`). `__getattr__` loads Zero only for the explicit compatibility-name set; `dir()` / `hasattr()` / unknown names do not import Zero. Historical models, tables, content types, permissions, serialized identities, and loader keys `trusts.0001_initial` / `trusts.0002_trustgroup` are owned by Zero (`ZeroConfig.name='trusts.zero'` `label='trusts'`). `pkgutil.extend_path` on `trusts/__init__.py` so the Zero dist can own `trusts.zero`. Registry, checks, and backends find the kernel by class identity (`kernel_config()`). Package Trust-as-content donation left `AppConfig.ready()`; Zero registers TUP+TGP. |
| Replacement | 0.x hosts: `INSTALLED_APPS = ['trusts', 'trusts.zero.apps.ZeroConfig']`. Kernel-store access: `kernel_config()` / `kernel_config(apps_registry)`. Canonical models: `trusts.zero.models`. Legacy `from trusts.models import Trust` works **only when Zero is installed**. |
| Affected | Hosts that listed only `'trusts'` for 0.x schema. Hosts that used `get_app_config('trusts').registry` / `.configured_backend()`. GH-only hosts that imported `trusts.models` model names. |
| Authorization | No schema or data migration. Grant tables, content-type natural keys, and permission identities are unchanged when Zero is installed. |

Failure behavior: kernel-only populate has no `label='trusts'` and no
`Trust` model. `import trusts.models` succeeds and does not import
`trusts.zero`. `from trusts.models import Trust` raises `ImportError`
naming `django-trusts-zero`. Installing C1 + Z1 remains
`ImproperlyConfigured` (duplicate label `trusts`) and is unsupported.

## No change to these public call sites

- `User.has_perm` / `User.has_perms` / `get_all_permissions` /
  `get_group_permissions` signatures
- `ContentQuerySet.permitted` signature (Zero) and documented Category /
  Ticket / Trust results when Zero is installed
- `filter_by_user_content_perm` / `filter_by_user_perm` signatures
- Backend path `trusts.backends.TrustModelBackend`
- Check IDs `trusts.E001`–`E005` / `W001`
- Package version `1.0.0.dev0`
- Database schema and Trusts migration **names** (`0001_initial`,
  `0002_trustgroup`) when Zero is installed

## Migration-bot checklist

- [ ] Do not apply a new Trusts schema or data migration; none is authorized.
- [ ] For 0.x hosts, add `'trusts.zero.apps.ZeroConfig'` next to `'trusts'`.
      `'trusts'` alone is kernel-only (`trusts_core`, no schema).
- [ ] Do not install bare `'trusts.zero'`.
- [ ] Replace `get_app_config('trusts').registry` /
      `.configured_backend()` with `kernel_config()`.
      `get_app_config('trusts')` is Zero after this cutover.
- [ ] Prefer `from trusts.zero.models import Trust` (canonical). Legacy
      `from trusts.models import Trust` still works if Zero is installed.
- [ ] GH-only hosts must not import `trusts.models` model names.
- [ ] Confirm `makemigrations trusts --check` is quiet and an
      already-current database has an empty Trusts plan (Zero owns the
      loader keys).
- [ ] Leave `trust_grant_q` / `HistoricalGroupQueryCompiler` in the kernel.
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] Do not merge this C2 head without the paired Z1 head
      `41d07f40e676f75389b91219106440932d402b53`. Merge C2 then Z1.

## Schema

No change. C2 deletes kernel copies of the historical files; Zero ships
the same operations under the same loader keys. Already-applied 1.x
`django_migrations` rows keep matching. Query construction remains lazy.

## Out of scope (not acceptance criteria)

- G1 / GH adoption
- Windows #17
- Examples
- Docs restructuring beyond this cutover
- Admin extraction
- Deleting `trust_grant_q` / `HistoricalGroupQueryCompiler`

# Issue #98: closed predicates and terminal membership paths (1.0.0.dev0)

## Decision

Public C2 `TrustsRegistry.register` now accepts the closed predicate
nodes required by the accepted GH team mapping, and a requester path
may end in exactly one membership hop. Core owns validation,
correlation, compilation, object / queryset / enumeration agreement,
and fail-closed behavior. Hosts own ordinary models and the
registration spelling. This does not reopen a general rule language.

## No change to these public call sites

- `User.has_perm` / `User.has_perms` / `get_all_permissions` /
  `get_group_permissions` signatures
- `ContentQuerySet.permitted` / `filter_by_user_content_perm`
- Historical `Expr` / `:condition` / `ConditionLookup` codec
- Existing one-hop user / permission registrations without `condition`
- `Along` reachability, app label `trusts_core`, package version
  `1.0.0.dev0`
- Database schema and Trusts migration names

## Changes

### 48. Closed predicates and terminal membership (#98)

| | |
| --- | --- |
| Previous | `condition=` other than `None` raised `TrustsConfigurationError` (`condition is not supported`). User and permission refs were one direct single-valued hop. M2M and reverse O2M requester paths were rejected. `All` / `Equal` / `permission_in` were absent from `trusts.core`. |
| New | `from trusts.core import All, Equal, Ref, permission_in`. `All(*predicates)`, `Equal(left, right)`, and `permission_in(*refs)` are immutable closed nodes. Registration-time `_meta` validation is zero SQL. A user path may be one forward single-valued hop, or `(forward single)*` then exactly one terminal M2M membership hop (`t.team.members`). Reverse O2M requester paths stay rejected. Predicates compile as an AND overlay on the same permission-bearing root row (membership, bundle ceiling, organization alignment). Multiple complete registered roots still OR-compose. |
| Replacement | Team-style hosts register the accepted spelling on public C2. Do not add a consumer-local `Q`, lookup-string, tuple, or callable dialect. Direct three-FK registrations stay valid without `condition`. |
| Affected | New public names and the requester-path grammar. Existing no-condition registrations, SQL, and results are unchanged. |
| Authorization | A team grant allows only when the requester is a terminal member, the grant row exists, `permission_in` holds for that row's permission, and `Equal` paths align, all on the same root row. Removing any one of those facts denies only that branch. Cross-organization team grants deny. Direct and team roots OR; revoking one valid root preserves the other. Object, queryset/manager, and enumeration agree. Query construction is lazy; supported decisions/listings stay **1 SQL** before pagination. |

Failure behavior: invalid predicate arity or types, mixed-root refs,
incompatible `Equal` terminals or resolved comparison fields (distinct
`to_field` / PK identities on the same model), `permission_in` paths
that do not end on the registered permission model, extra or
intermediate multi-valued walks, untyped `condition` values,
unregistered / stale / unsupported declarations fail closed. Untyped
`condition=` still reports that `condition` is not supported.
Registration and system checks issue **0 SQL**.

## Old vs new behavior

| Situation | Old (C2 `db5a41ed`) | New (#98) |
| --- | --- | --- |
| `from trusts.core import All, Equal, permission_in` | Names absent | Exported closed nodes |
| `user=t.team.members` | Rejected (M2M) | Terminal membership hop |
| `condition=All(...)` | Rejected | AND overlay on the same root row |
| `condition=object()` | Rejected (`not supported`) | Unchanged rejection |
| Direct `user=d.account` with `condition=None` | Registered | Unchanged |
| Content-path M2M / extra multi-valued walks | Rejected | Still rejected |
| Two complete roots on one content terminal | OR | Unchanged OR; predicates stay AND inside one root |

## Schema

No change. #98 adds no model and no Django migration. Existing schema
and migration identities stay. Query construction remains lazy.

## Out of scope (not acceptance criteria)

- General callable, `Q`, lookup-string, tuple, or unrestricted
  expression dialect
- Arbitrary-depth or repeated multi-valued traversal
- Zero model/schema changes
- GH consumer changes beyond the paired acceptance spelling
- Windows #17, examples, broad docs restructuring, admin

## Migration-bot checklist

- [ ] Do not apply a new Trusts schema or data migration; none was added.
- [ ] Import `All`, `Equal`, and `permission_in` from `trusts.core` only
      when a closed predicate overlay is intended.
- [ ] Keep direct three-FK registrations unchanged; omit `condition` or
      pass `None`.
- [ ] Requester membership is exactly one terminal M2M after zero or
      more forward singles. Reverse O2M requester paths stay rejected.
      Do not walk extra collections.
- [ ] `permission_in` refs must terminate on the registered permission
      model. `Equal` sides must be forward singles to the same model
      and the same resolved comparison field.
- [ ] Do not pass `Q`, callables, lookup strings, or tuples as
      `condition`. Untyped values still fail closed.
- [ ] Treat `All` / `Equal` / `permission_in` as AND on one root row.
      Independent roots still OR.
- [ ] Paginate only after `.authorized(...)` / `filter_authorized`.
- [ ] Leave package version at `1.0.0.dev0`.
- [ ] Leave C2 app-label / package boundaries and the Zero
      compatibility baseline unchanged.






