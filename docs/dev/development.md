# Development

Historical development record. Last source update: 2026-10-14. Reorganized
2026-10-16; this revision has not been reviewed by a human for current accuracy.

For application setup, use the [usage guide](../source/index.rst).
The [legacy baseline](legacy-baseline.md) owns preserved 0.x evidence.

## Change sizing and surface discovery

Design tasks must estimate the complete implementation and review surface before
implementation is authorized. Use the Fibonacci scale
`1, 2, 3, 5, 8, 13, 21, 34, 55, 89, 144`. This is a comparative
risk/complexity size, not an hour estimate or a count of changed lines.

Every design review must surface sizing near the top in three layers:

- the entire controlling ticket, with a realistic range covering all known and
  not-yet-designed stages;
- completed points from accepted subtasks; and
- the current proposed subtask, with one size or a bounded range.

Do not hide unplanned stages inside a precise-looking total. Mark them
`unknown`, give a reasoned comparison where possible, and widen the whole-task
range accordingly. For example:

```text
#247 — v3.7 automatic relationship extraction
Whole ticket: 34–144
Completed: 5 (S1 accepted)
Current: S2 — size 8
S3–S7 — unknown; command, validation, stability, migration,
and consumer surfaces remain unbounded
```

Completed points are the sum of the final reviewed sizes of accepted subtasks.
If a subtask was re-sized during implementation, count its final size and show
the change. If historical work was never sized, label it `unscored` or
`retrospective estimate`; do not invent precision.

The whole-task range is a planning envelope, not a mechanical sum of subtask
points. It should include integration, discoveries between stages, review
rounds, cross-repository sequencing, and final acceptance proof. Completed
points show progress but must not be subtracted mechanically from that range to
claim a precise remaining size while stages remain unknown.

The calibration anchor for a **3** is
[django-trusts #129 / PR #140](https://github.com/django-trusts/django-trusts/pull/140):
a bounded one-repository cleanup with no intended API change that nevertheless
required migration wording, package and companion-wheel proof, preservation of
historical evidence, a focused review correction, and the full django-trusts matrix.
[PR #124](https://github.com/django-trusts/django-trusts/pull/124), a
one-file Read the Docs configuration using an already-proven build, is a useful
**1** reference.

Estimate the surface that must be understood and proved, including:

- public API and migration consequences;
- grant-producing semantics and fail-closed behavior;
- object, queryset, enumeration, and decorator projections;
- relationship identity, many-to-many, recursion, and database dialects;
- registry lifecycle, startup, and registration-time database access;
- affected consumer repositories and exact-version staging;
- documentation, packaging, CI, deployment, and rollback proof; and
- uncertainty about existing behavior or historical compatibility.

A design handoff must state the subtask size, whole-ticket range, comparison
task used as its anchor, surface drivers, proposed proof, and the known/unknown
status of later stages. A size is not a promise that discovery will stop. If
implementation or review exposes a material surface that the estimate omitted,
stop expanding the patch, report the discovery, and re-size both the current
subtask and the whole-ticket range before continuing.

A task estimated at **13 or larger** is not implementation-ready. Split it at
clean dependency or release boundaries and size the resulting tasks
independently. A task that grows to 13 during implementation follows the same
rule.

## Docs-first development

Docs-first development is the default, not a hard rule. Use another approach
for a tiny or sweeping change, an exploratory task, or when this workflow does
not reasonably fit the problem.

For a user-visible feature, first test feasibility: walk every affected path,
identify likely pitfalls, and draft the smallest user-doc change. Refine a
representative snippet until the behavior is clear, then open a docs PR as the
proposed contract. Keep it draft; user docs normally merge with or after the
implementation so `dev` does not promise behavior it does not provide.

The implementor reviews that contract before coding, surfaces contradictions
or missing cases, and implements against it. Code review checks both
correctness and adherence to the docs, including the reasoning behind
documented choices and the boundaries the docs intentionally leave
unspecified. Implementation PRs normally do not edit user docs. When implementation exposes a mismatch, the implementor
posts an evidence-backed doc-change request. The doc writer decides whether it
is a valid contract change, a documentation defect, or an implementation
misunderstanding, and updates the docs when warranted. If implementation leads
to a significant contract change, the docs PR should generally remain unmerged
until the project owner has had a chance to review the revised contract. Keep
implementation notes and proof in PR comments or development docs, not
permanent user docs.

## Writing docs

Keep four user documents: the [usage guide](../source/index.rst) for the
minimal happy path, [security audit](../../SECURITY_AUDIT.md) for policy
boundaries, [migrations](../../migrates.md) for required upgrade actions,
and [What's New](../whats-new.md) for one- or two-line announcements with links.
Each fact has one home. Elsewhere, use at most one sentence and a link when
needed for the flow. Keep development records under `docs/dev/`, dated and
marked with their human-review status. Do not add documents unless requested.


- Write in plain English, the way Django's docs read.
- Use the terms Django's docs already use: user, active user, superuser,
  authentication backend, permission, object permissions, `has_perm()`.
- Describe what the code does instead of inventing labels. No "mode",
  "principal", "contributor", "invariant" or "outer rules".
- Prefer examples to abstract rules.
- User docs read as already shipped. No version disclaimers.
- Don't imply hooks or flags that code outside Trusts must support.
- Don't present pseudo-code as a real function.
- If a reader has to read a sentence twice, rewrite it.

## Test

```
python -m pip install -e ".[test]"
python -m tests.runtests
python -m django check --settings=tests.settings
```

`scripts/verify-legacy-upgrade.py` and `scripts/legacy/trusts_0001_sqlite.sql`
remain in this tree as historical already-applied-`0001` evidence. The
runner is currently broken (imports inert `trusts.models`, lists
`'trusts'` in `INSTALLED_APPS`) and is **not** in CI. It is not a live
operator path. Live `create_trust_root`,
`grandfather_trust_group_permissions`, and `update_roles_permissions`
commands require `trusts.zero.apps.ZeroConfig`. Zero's
fresh-install / migration-identity / grandfather tests are complementary;
they are not an already-applied-`0001` → `0002` → grandfather replay.
Only that Zero replay should authorize deleting this django-trusts evidence.

CI is GitHub Actions (`.github/workflows/ci.yml`): kernel-only
authorization tests, a fresh migrate, `manage.py check`, pair proofs
against the supported Zero companion, a non-blocking companion follow
job described below, and a `package` job that builds
an sdist/wheel, checks that the long description comes from the user
`README.md` (not this file), verifies BeeDesk 2015-2026 / BSD-2-Clause
`LICENSE` metadata, and imports the wheel from a temporary directory so
the source tree cannot satisfy the import. Do not treat a removed Travis check
as a stand-in green status.

## Companions on the Core commit under test

The exact Zero pair job is unchanged. It still installs one pinned Zero
commit and runs the pair proofs.

A second job runs the Zero test suite and the GH Permissions test suite
against the Core commit the workflow is testing. It does not edit either
companion's pin. The job is `continue-on-error`, so a failure shows on
the workflow and the other jobs still count. It does not post a pull
request comment.

For every pull request and every push, each companion is chosen the
same way:

1. The branch with the same name as the Core branch under test. On a
   pull request that name is the head branch. On a push it is the
   branch that was pushed.
2. `dev`, when the companion has no branch of that name.
3. The companion's stable branch, when it also has no `dev`.

The stable branch is that repository's GitHub default branch. The job
reads it with `git ls-remote --symref` from `HEAD`. The workflow does
not list `main` or `master`. Core's default branch is `master`. CI
relies on each repository's GitHub default branch being its stable
branch (`master` or `main`). An admin must not set that default to
`dev`. If a repository renames its stable branch, point the GitHub
default at the new name.

Core leads. Core's `dev` and Core's `master` are tested against the
companion `dev` branch. Core changes land in Core first, and a companion
pins that commit afterwards, so the companion stable branch does not yet
have the pieces those Core changes need. A companion has no branch
named `master`, so a Core `master` run misses the same-name step and
uses companion `dev`. It uses the stable branch only when `dev` is
missing too. A same-name branch wins when the companion has one,
including a pull request branch that exists on both repositories.

The job checks out Core and the companion. It installs the companion's
requirements, then installs this Core checkout with
`pip install --no-deps --force-reinstall` so the requirements pin stays
as written and the installed Core library is the commit under test. It
logs that Core commit, the companion ref, and the companion commit. It
sets `TRUSTS_FOLLOW_CORE=1` and runs the companion test suite.

Zero's test runner puts the Core checkout on the Python path and drops
any other directory that contains the `trusts` package. Installing Core
into the environment's package directory would drop Django as well,
because that package lives in the same directory. For Zero, the job
points the runner at the Core checkout it just installed and leaves
Django on a separate path. GH Permissions imports the reinstalled Core
library from the environment.

For GH Permissions the job also writes the SQLite policy lockfile. The
companion's test settings use SQLite, and the command is
`manage.py trusts_policy_sql --lock`. If that command fails, the job
fails. The file is uploaded as the artifact
`gh-permissions-sqlite-policy-lock` and kept for 7 days.
