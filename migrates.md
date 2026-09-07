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
| New | `Content.objects.permitted(perm, user)` — SQL filter of trustee **or** `Group.permissions` **or** role grants on `content.trust`. Empty for inactive/anonymous. Paginate the QuerySet. Superuser short-circuit is **not** duplicated (Django `ModelBackend`). |
| Replacement | `Model.objects.permitted('read', user)` or `permitted('app.read_model', user)`. Example list helpers can call this instead of a project-local JOIN. |
| Affected | New callers; Content subclasses inherit `ContentManager`. `Trust.objects` is a `TrustManager` that also inherits `permitted`. |
| Authorization | List results match `has_perm` on the supported relational paths. Read-only principals are listed only for perms they actually hold. |

Migration-bot checklist:

- [ ] Replace Python `[obj for obj in qs if user.has_perm(perm, obj)]` list filters with `.permitted(perm, user)` before pagination.
- [ ] Do not treat `permitted` as a superuser "return all" API.
- [ ] Confirm inactive users get an empty queryset.

### 7. `Content.objects.get_permission(perm)` (new)

| | |
| --- | --- |
| Previous | #9 hardcoded `from django.contrib.auth.models import Permission`. |
| New | Resolves via `get_permission_model()` / `TRUSTS_PERMISSION_MODEL`. Accepts a permission instance, codename, bare action (`read` → `read_<model>`), or dotted code. Strips `:own`. |
| Replacement | `Model.objects.get_permission('read')` or `get_permission('read_model')`. |
| Affected | `grant` / `revoke` / `permitted` / `filter_by_user_content_perm`. Custom permission models must provide `get_by_natural_key` or `codename` + content type fields. |
| Authorization | Lookup only; does not grant. |

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
| New | **Additional** method. Create-under-trust: Trusts where `user` holds `perm_name` for `content` on **that Trust row** via trustee / group.permissions / role. No parent lookup. No settlor shortcut. `fieldlookup` unused (no existing content required). Inactive → empty. `exclude_root` defaults True. `filter_by_user_perm` and `TrustTest.test_filter_by_user_perm` are unchanged. |
| Replacement | `Trust.objects.filter_by_user_content_perm(user, Project, 'add_project')` for create-target trust pickers. Keep `filter_by_user_perm` for "trusts this user is attached to". |
| Affected | Example `ProjectForm` trust queryset (historical #1). |
| Authorization | Settlor-only is **not** implied. Create forms must not list every settlor trust. |

Migration-bot checklist:

- [ ] Do not rename or remove `filter_by_user_perm`.
- [ ] Update any #9-era `filter_by_user_content_perm(self.user)` (old signature) to the four-argument form.
- [ ] Confirm settlors without an `add_*` grant are omitted.
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
| New | `options.DEFAULT_NAMES` includes `auto_modeladmin`. `AppConfig.ready` registers concrete `Content` / `Junction` subclasses with `auto_modeladmin = True`. Default is False. Already-registered models are skipped. Proxy and abstract subclasses do not re-register content fieldlookups (a proxy Junction must not overwrite the concrete junction's Group lookup). |
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

## Migration-bot summary (issue #8)

- [ ] Adopt `permitted` / `grant` / `revoke` / `filter_by_user_content_perm` instead of #9 copies.
- [ ] Keep `filter_by_user_perm` and `test_filter_by_user_perm`.
- [ ] Wrap mutations with `trusts.authorization` (`change`, scoped IDs).
- [ ] Do not write `Group.permissions` from a project form.
- [ ] Do not add `TrustGroup` or edit `0001_initial`.
- [ ] Set `auto_modeladmin = True` only where you want automatic admin.
- [ ] Leave package version at `1.0.0.dev0`.

