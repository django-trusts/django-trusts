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

## #8 recovery API additions (1.0.0.dev0)

These are new helpers recovered from historical PR #9 / example PR #1.
They do **not** rename or remove `filter_by_user_perm`. `0001_initial` is
unchanged. No `TrustGroup` through table. Package version stays `1.0.0.dev0`.

### 6. `ContentQuerySet.permitted(perm, user)`

| | |
| --- | --- |
| Previous | No list-filter API. Callers iterated objects or used `has_perm` per row. Historical #9 `permitted` omitted role grants and used `Group.permissions` only. |
| New | `Content` subclasses inherit `objects.permitted(perm, user)`. SQL JOIN on trustee, trust-attached `Group.permissions`, and role grants — the same paths as `TrustModelBackend.get_all_permissions`. Paginate **after** this filter. |
| Replacement | `Model.objects.permitted('read_thing', user)` or `qs.permitted(...)`. |
| Affected | List views that need Trusts-aware membership. `:own` predicates are **not** in SQL (still Python-side on `has_perm`). Superuser short-circuit is Django `has_perm` only; `permitted` is grant-backed. |
| Authorization | Anonymous and `is_active=False` return an empty queryset (parity with Django `has_perm`). |

Migration-bot checklist:

- [ ] Find Python loops that call `has_perm` per row to build a list page.
- [ ] Replace with `qs.permitted(codename, user)` before slicing / paginating.
- [ ] Confirm inactive users are excluded from both the list and `has_perm`.
- [ ] Confirm role-granted rows appear (not only `TrustUserPermission` / `Group.permissions`).

### 7. `Trust.objects.filter_by_user_content_perm(user, content, perm_name, exclude_root=True)`

| | |
| --- | --- |
| Previous | Only `filter_by_user_perm(user, **kwargs)` (any trustee row or group membership; no permission name). Historical #9 rename queried parent `trust__*` relations, ignored `fieldlookup`, and treated settlor as a grant. The renamed test was not collected. |
| New | Additional manager method. Returns trusts where `user` holds `perm_name` for Content subclass `content` via the same grant paths as `permitted` / `has_perm`. Settlor identity is **not** a shortcut. Root is excluded by default. |
| Replacement | Keep `filter_by_user_perm` for the old “any attachment” query. Use `filter_by_user_content_perm` for create-under-trust (trust dropdown). |
| Affected | Project/content create forms that need trusts the user may attach new rows to. |
| Authorization | Inactive / anonymous → empty. Does not grant create rights by being settlor alone. |

Migration-bot checklist:

- [ ] Do not replace existing `filter_by_user_perm` callers unless they meant a named permission.
- [ ] Create-form trust querysets should call `filter_by_user_content_perm(user, Model, 'add_model')`.
- [ ] Verify a settlor with no trustee/role/group grant is omitted.
- [ ] Keep `test_filter_by_user_perm` collected; add/keep `test_filter_by_user_content_perm_*`.

### 8. `Content.get_permission` / `Content.grant`

| | |
| --- | --- |
| Previous | No public helpers. Historical #9 hardcoded `django.contrib.auth.models.Permission`. |
| New | `Model.objects.get_permission(perm)` uses `get_permission_model()` (`TRUSTS_PERMISSION_MODEL`). `content.grant(perm, user)` creates a `TrustUserPermission` on `content.trust`. |
| Replacement | New API. `perm` is a codename or `app_label.codename` (`:condition` stripped). |
| Affected | Apps that issued trustee rows by hand. Custom permission models now resolve correctly. |
| Authorization | Grant writes an explicit trustee row; it does not use `Group.permissions`. |

Migration-bot checklist:

- [ ] Replace hardcoded `Permission.objects.get_by_natural_key` on Content managers with `get_permission` if the project uses `TRUSTS_PERMISSION_MODEL`.
- [ ] Prefer `content.grant(codename, user)` over assembling `TrustUserPermission` by hand.

### 9. `auto_modeladmin` Meta flag

| | |
| --- | --- |
| Previous | Only core models registered in `trusts.admin`. #8 milestone 2 was unspecified in #9. |
| New | Concrete `Content` / `Junction` subclasses with `class Meta: auto_modeladmin = True` are registered in `AppConfig.ready` when `django.contrib.admin` is installed. |
| Replacement | Opt-in. Existing explicit `admin.site.register` is left alone (`AlreadyRegistered` avoided). |
| Affected | Project models that set the flag. `auto_modeladmin` is added to Django `options.DEFAULT_NAMES`. |
| Authorization | Admin registration only; object-level grants are unchanged. |

Migration-bot checklist:

- [ ] Set `auto_modeladmin = True` on concrete Content/Junction models that should appear in admin.
- [ ] Do not set it on abstract bases.
- [ ] Confirm admin is in `INSTALLED_APPS`.

### 10. Team views (`trusts.views.newteam` / `team`)

| | |
| --- | --- |
| Previous | Historical #9: any group member could add members. No Trusts manage check. |
| New | `newteam` creates a Django Group and enrolls the creator (membership ≠ manage). `team` GET requires membership (or manage). POST add-member requires a **trustee** `change_trust` grant on a trust that includes the group. Does not write `Group.permissions`. |
| Replacement | Same URL ideas (`/teams/new/`, `/teams/<pk>/`); authorization is stricter. |
| Affected | Callers that assumed membership was enough to add people. Wire URLs explicitly. |
| Authorization | Reader/member POST is 403 with no membership change. POST to a group the user cannot manage is 403. |

Migration-bot checklist:

- [ ] Include `trusts.views` URLs only if the project wants built-in team pages.
- [ ] Do not treat group membership as permission-administration.
- [ ] Do not set `Group.permissions` from a project settings form (global, not per-trust). Use `Trust.groups` + `Role` / trustee rows.

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
