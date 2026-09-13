# #181 spike: `has_perm` raise on QuerySet — STOP inventory

Baseline: Core `dev` `73519bc6e67cf0e5759ebb5d3c816d39fb84d859`.
Zero pair pin: `2e3cccedb92b4cf85e9d6a3cd2d51821aad1d716` (CI `COMPANION_ZERO_SHA`).
Disposition: Thomas (chat 2026-09-13) prefer raise when `obj` is a QuerySet.
Result: **STOP**. No production raise landed. Blast radius **exceeds 3**.

## Hypothesis

QS acceptance is an internal mixin unification leftover from #77, **and** it
is now a Zero/legacy contract plus a production decorator implementation
detail. Both halves are true.

- Taught 1.x APIs (`README.md`, `docs/source/index.rst`, `migrates.md` item 7)
  show singular `user.has_perm(perm, object)` and list inquiry on
  `.authorized`. No advertised consumer recipe passes a QuerySet into
  `has_perm`.
- Production `TrustModelBackendMixin.has_perm` in `trusts/backends.py`
  still treats QuerySet as a first-class `all_match` collection check.
  That path is the #77/#178 coordinator unification, not a separate
  content mixin.
- Zero `tests/legacy/` still proves object/QuerySet `has_perm` parity as
  a public contract. Pair CI runs that suite (`scripts/run-z1-pair-tests.py`).
- Legacy `permission_required` resolves fieldlookups to
  `Model.objects.filter(**lookups)` and passes that QuerySet to
  `user.has_perms`. Zero `test_permission_required` asserts the second
  argument is a QuerySet (`.count()` / `.first()`).

## Where QS is accepted today

`trusts/backends.py` `TrustModelBackendMixin` (only production `has_perm`):

- `has_perm`: if `isinstance(obj, QuerySet)` and this backend is the
  first configured Trusts path, call `_collection_has_perm` →
  `all_match`. Non-coordinator QuerySet returns `False`.
- `_condition_overlay`: QuerySet compiles the named filter to `extra_q`
  SQL AND overlay.
- `permission_condition_met`: iterates QuerySet rows in Python when
  there is no compiled `extra_q`.
- `_bound_condition_lookup`: QuerySet uses `handles[0].registry`
  (the #181 Host+Document named-filter mismatch that parked PR #183).
- `get_all_permissions` / `get_group_permissions`: same QuerySet
  coordinator split via `_collection_permissions` → `common_permissions`.
  **Left alone** in this spike.

`authorization_required` does **not** call `user.has_perm`. It filters
`model._default_manager.filter(pk=pk)` with `granted()`. That path stays
green if `has_perm` raises.

Zero production (`trusts/zero/authorization.py`) calls `has_perm` with
instances only.

## Core tests that call `has_perm(..., qs)`

All in `tests/core/test_issue178.py` (`PAIR_KERNEL_SUITE` includes this
module). No other Core kernel module passes a QuerySet into `has_perm`.

| Method | Calls |
| --- | --- |
| `test_queryset_common_projection_is_one_sql_and_count_independent` | `document_backend.has_perm(..., many/mixed)`; `host.has_perm(..., many)` (false/non-coordinator); `alice.has_perm(PERM, many/mixed)` |
| `test_noncoordinator_and_duplicate_path_stay_empty_or_one_sql` | `mixin.has_perm(..., qs)` false; `host.has_perm(..., qs)` false |
| `test_defensive_inputs_are_false_empty_with_zero_sql` | inactive/anon `document_backend.has_perm(..., qs)` — these return False on principal checks **before** the QuerySet branch |

Same file also uses `get_all_permissions(qs)` / `get_group_permissions(qs)`
heavily. Those would stay if only `has_perm` raised, leaving an asymmetric
public API.

List proofs that already use `.authorized` (no rewrite needed for raise):
`tests/core/test_issue115.py` `test_object_has_perm_and_authorized_queryset`,
`tests/core/test_issue77.py` `test_registered_ordinary_instance_queryset_and_authorized`,
`tests/core/test_issue132.py`.

## Zero pair breakages (why this exceeds 3)

A Core-only raise would fail `pair-iia` (`run-z1-pair-tests.py` → Zero
complete suite). User scope: if Zero must change, STOP.

### Historical mixin (pre-#77 product contract)

`tests/legacy/test_historical.py`

- `test_has_perm_queryset` — `user.has_perm(perm, qs)` true for two
  granted rows
- `test_mixed_trust_queryset` — `user.has_perm(perm, Model.objects.all())`
  false
- `test_organization_isolation_denies_cross_trust_access` — mixed QS
  `has_perm` false
- `test_permission_required` / `test_permission_required_P` — assert
  `has_perms` second arg is a QuerySet (`obj.count()`, `obj.first()`)

### #77 mixin unification (object + QuerySet parity)

`tests/legacy/test_issue77.py`

- `test_category_trustee_and_group_object_and_queryset`
- `test_ticket_and_trust_object_queryset_parity`
- `test_named_condition_constrains_and_does_not_create` (`qs_keep` /
  `qs_drop`, including `perm:name` on a QuerySet)
- `test_inactive_and_anonymous_denied` (inactive + QS)
- `test_permission_identity_and_group_enumeration` (`get_*_permissions(qs)`)
- `test_query_bounds_one_path` (1-SQL `backend.has_perm(..., qs)` and
  `has_perms(..., qs)`)
- `test_split_coverage_object_queryset_and_permitted` (distributive-law
  aggregate QS `has_perm` true)
- `test_failed_ceiling_cannot_borrow_other_path_fragment`
- `test_concrete_group_grant_not_inherited_by_mixin`
- `test_coordinator_one_sql_noncoordinator_zero`
- `test_reversed_backend_order`
- `test_duplicate_exact_path_strings_dedupe`
- `test_junction_group_uses_registered_plan`
- `test_registered_ordinary_instance_queryset_enum_and_permitted`
- `test_concrete_no_plan_fails_closed_for_undeclared_content`
- `test_inapplicable_mixin_neither_adds_nor_reopens_deleted_fallback`
- `test_concrete_authorizes_declared_junction_group`
- `test_mixin_does_not_add_or_suppress_junction_plan`

### #85 Group

`tests/legacy/test_issue85.py`

- `test_instance_and_queryset_has_perm_has_perms` (`has_perm` /
  `has_perms` on `qs` and `mixed`)
- later coordinator / concrete `has_perm(..., qs)` and
  `get_*_permissions(qs)` assertions (~586, 639, 725)

### #87 dependents

`tests/legacy/test_issue87.py`

- `test_category_ticket_trust_group_allow_deny_unchanged` (`has_perm` on
  `qs`)
- `test_image_object_queryset_enum_direct_and_group` / meta equivalent
  (`granted_qs` / `mixed_qs` / `image_qs` / `meta_qs`)
- orphan QuerySet deny

Rough count: **40+** `has_perm(..., qs)` assertions across **4 Zero
legacy modules**, plus decorator contract tests that require the QS
object itself.

## Production call site (Core)

`trusts/decorators.py` `_get_permissible_items` →
`ctype.model_class().objects.filter(**fieldlookups)` →
`request.user.has_perms(perms, items)`.

Documented README / RST `@permission_required(..., fieldlookups_kwargs={'pk': 'pk'})`
would raise once mixin `has_perm` raises, unless the decorator is changed
to pass a model instance (or to use `.authorized`). Changing it to an
instance would keep the Core README path green and break Zero
`test_permission_required`, which asserts QuerySet API on the `has_perms`
argument.

`authorization_required` is independent and would stay green.

## `get_all_permissions` / `get_group_permissions` with QS

Not changed. Complication even if left alone:

- Same mixin, same coordinator rule, same `common_permissions` SQL.
- Core #178 and Zero #77/#85/#87 treat QS enumeration as the sibling of
  QS `has_perm`.
- Raising only in `has_perm` creates an asymmetric public surface:
  `user.has_perm(perm, qs)` errors, `user.get_all_permissions(qs)` still
  answers the all-candidates question.
- Redesigning enumeration as part of this PR is explicitly a STOP
  condition.

`all_match` / `common_permissions` / `.authorized` / `.permitted` remain
the list-shaped primitives and do not need to change for a `has_perm`
raise.

## Size

| Work | Size |
| --- | --- |
| Core `has_perm` TypeError + rewrite `test_issue178` QS `has_perm` lines + add raise proof | 2–3 by itself |
| Keep `permission_required` green (decorator + Zero `test_permission_required`) | + production + Zero pin |
| Zero legacy parity rewrite (4 modules, 40+ assertions, including `:name` on QS) | deep Zero parity |
| Decide `get_*_permissions(qs)` (leave asymmetric vs raise/redesign) | sibling API / possible `migrates.md` |
| **This spike** | **exceeds 3** |

Whole-ticket note (provisional, for Chat): a later raise still looks like
a focused Core change **after** Zero is re-issued to drop QS `has_perm`
parity and the decorator either stops passing a QuerySet or is documented
as the one remaining collection caller. That sequencing is not this PR.

## Residual risk if someone lands Core-only raise anyway

Pair CI red. Documented `permission_required` 500s/TypeError on every
fieldlookup view. Asymmetric `get_*_permissions(qs)`. PR #183 stays
parked and becomes moot for `has_perm(..., qs)` named-filter overlay.

## CI

Not run. No production change.
