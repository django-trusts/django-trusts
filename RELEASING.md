# Releasing django-trusts

This is the standing maintainer runbook for django-trusts release
candidates, later RC increments, and the final release. It transcribes
the decisions in [#224](https://github.com/django-trusts/django-trusts/issues/224)
and the completed 1.0.0rc1 process recorded on closed
[#149](https://github.com/django-trusts/django-trusts/issues/149).

“Core” in this document is the internal name for the published
django-trusts package train. Only django-trusts follows that version
and tag. Companions keep independent cycles.

Do not invent new check matrices, scripts, packaging gates, or CI
workflows for a release. Use the existing committed CI and ordinary
consumer checks already in each repository.

## Standing boundaries

- **Only django-trusts follows the Core version/tag and is published by
  this train.**
- django-trusts-zero (Zero) keeps an independent 0.x line. RC1 used
  `0.12.0.dev0`. Do not publish Zero merely because django-trusts
  releases.
- Zero Example, Windows ACL, GH Permissions, and OrderedFold keep
  independent version and release cycles.
- A `compatible-with-django-trusts-v<VERSION>` tag is a source snapshot
  of a tested pairing. It is not a companion package release.
- Examples are examples. OrderedFold is provisional. Both get their
  ordinary existing CI only — no new wheel, lock, or publication gates.
- Default branches are contribution baselines. Do not rename
  `main`/`master` solely for consistency.
- Between RCs, reuse already-accepted evidence for unchanged
  companions. Rerun django-trusts CI and the django-trusts + Zero pair
  on the new candidate. Rerun a consumer only when the delta can affect
  it, or when its ordinary CI is part of a default-branch merge.
- A Zero development tag (for example RC1’s separately authorized
  `v0.12.0.dev0`) is **not** a mandatory recurring step of this train.

## Ownership

| Role | Responsibility |
| --- | --- |
| Preparer | Freeze exact candidate heads, apply coupled django-trusts version metadata, run existing CI, and return exact SHAs for review. |
| Release operator | Review and merge promotions into each existing default branch, create annotated tags, and prepare the GitHub Release notes. |
| Thomas | Authorizes the final PyPI publish of django-trusts. No other package is published on this train unless separately authorized. |

The preparer does not merge promotions, push release tags, or upload to
PyPI unless that exact step is reassigned. Draft baton PR
[#220](https://github.com/django-trusts/django-trusts/pull/220) is a
coordination lane only and stays do-not-merge.

## Active repositories and default branches

| Repository | Default branch | Role in this train |
| --- | --- | --- |
| [django-trusts](https://github.com/django-trusts/django-trusts) | `master` | Published package. Tag `v<VERSION>`. |
| [django-trusts-zero](https://github.com/django-trusts/django-trusts-zero) | `main` | Required compatibility pair. Compatibility tag only. |
| [django-trusts-zero-example](https://github.com/django-trusts/django-trusts-zero-example) | `master` | Example. Ordinary CI. Compatibility tag only. |
| [django-trusts-windows-acl](https://github.com/django-trusts/django-trusts-windows-acl) | `main` | Consumer. Ordinary CI when the delta can affect it. Compatibility tag only. |
| [django-trusts-gh-permissions](https://github.com/django-trusts/django-trusts-gh-permissions) | `main` | Consumer. Ordinary CI when the delta can affect it. Compatibility tag only. |
| [django-trusts-ordered-fold](https://github.com/django-trusts/django-trusts-ordered-fold) | `main` | Provisional extension. Ordinary CI only. Compatibility tag only. |

Promote accepted revisions into those existing defaults. Do not create
new release branches in every repository merely for consistency.

## Version metadata (django-trusts + coupled assertions)

`pyproject.toml` is the authoritative django-trusts package version.
A release revision updates that version and the **coupled assertions**
that already exist in this tree. Do not add a new version source or
`__version__`.

Coupled locations proven on RC1 (`1.0.0.dev3` → `1.0.0rc1`):

| Location | Role |
| --- | --- |
| `pyproject.toml` | Authoritative package version |
| `docs/source/conf.py` | Sphinx `version` / `release` |
| `docs/development-version.md` | Development-line record |
| `docs/support-matrix.md` | Support-claim version wording |
| `.github/workflows/ci.yml` `COMPANION_ZERO_SHA` | Exact Zero candidate for the pair job |
| `scripts/verify-package-metadata.py` | `EXPECTED_VERSION` and sdist/wheel name prefix |
| `scripts/verify-wheel-install.py` | Installed-wheel version assertion |
| `scripts/verify-pair-zero.py` | Pair-proof version wording |
| `scripts/verify-companion-wheels.py` | Companion-wheel version wording |
| `scripts/management_archive.py` | Sdist member-prefix comment |
| Kernel tests that pin the package version string | Existing assertions only |

Independently intended companion version changes (for example Zero
`0.12.0.dev0`) are companion-owned work. They are not part of the
django-trusts version bump unless separately authorized.

`setup.py` stays a thin wrapper and does not duplicate the version
field. `trusts/__init__.py` has no `__version__`.

## Procedure

Record every exact commit, tag, artifact, and announcement link in the
release execution issue (RC1 used #149; later increments use their own
tracker). #224 remains the standing procedure.

### 1. Freeze the candidate

Record the exact django-trusts and Zero candidate commits, plus the
exact companion heads that will be promoted. Start later RCs from the
previous release tag and review the delta. Do not reopen historical
architecture reviews or one-off proofs unless that surface changed.

A failed **relevant** existing check blocks the release. Absence of a
newly imagined check does not.

### 2. Set and verify version metadata

Apply the new django-trusts version and the coupled assertions listed
above. Review release notes, migration-boundary wording
(`migrates.md`), dependency metadata, and
[docs/support-matrix.md](docs/support-matrix.md).

Companion repositories receive version changes only when those changes
are independently intended.

### 3. Run existing CI on the release revision

Run django-trusts’s committed CI once on the exact release revision
(`.github/workflows/ci.yml`):

- kernel-only authorization tests on Python 3.12, 3.13, and 3.14;
- documentation (`sphinx-build -nW`, also the `package` job);
- package, sdist, and wheel (`python -m build`, `twine check`);
- clean installed-wheel / import / metadata checks;
- the existing django-trusts + Zero compatibility pair against the
  exact Zero candidate pin.

Run ordinary current compatibility checks for GH Permissions and
Windows ACL when the django-trusts delta can affect them.

Run each example or provisional repository’s ordinary existing checks.
Do not invent new wheel matrices, locks, scripts, or byte-identical
environment proofs merely for the django-trusts release.

### 4. Promote accepted revisions to default branches

After proof is accepted, merge the accepted state of every active
repository into its existing default branch so users can reproduce it
and open bug-fix PRs from the correct base:

- django-trusts → `master`
- Zero → `main`
- Zero Example → `master`
- Windows ACL → `main`
- GH Permissions → `main`
- OrderedFold → `main`

Confirm each resulting default-branch commit and its ordinary required
checks. The preparer returns those exact heads; the release operator
reviews and merges.

### 5. Create exact annotated tags

Create annotated tags only. Do not force-update. Do not treat a tag as
a package release.

- django-trusts: `v<VERSION>` on the verified default-branch commit.
  RC1 used message `django-trusts 1.0.0rc1`.
- Each tested companion default-branch commit:
  `compatible-with-django-trusts-v<VERSION>`. Use an annotated message
  that names the django-trusts tag (and, when useful, the Core commit).
  RC1 used `Compatibility snapshot tested against django-trusts v1.0.0rc1.`

An unchanged companion may receive the next compatibility tag on the
same commit after the new django-trusts candidate is confirmed
compatible.

### 6. Create the GitHub pre-release

Create the GitHub Release from the django-trusts tag. RC1 marked
`v1.0.0rc1` as a **pre-release**. A later final `1.0.0` uses the same
tag/Release path and is marked a full release when Thomas authorizes
that step.

Do not create GitHub Releases for companion compatibility tags.

### 7. Publish django-trusts only to PyPI

Publish **only** the django-trusts sdist and wheel. Do not upload Zero
or any companion unless a separate companion release was independently
authorized.

**Current path (RC1):** manual upload with `twine` and a PyPI project
API token. Typical shape after the `package` job (or an equivalent
local `python -m build` + `twine check`) has produced `dist/`:

```text
python -m twine upload dist/django_trusts-<VERSION>.tar.gz \
    dist/django_trusts-<VERSION>-py3-none-any.whl
```

Thomas authorizes that upload. Store the token outside the repository.
Do not commit credentials or add a publish workflow in this runbook.

**Optional future improvement:** GitHub Actions Trusted Publishing to
PyPI. That is not the current path. Do not add workflow or CI files
for it as part of following this runbook.

### 8. Verify sdist, wheel, and SHA-256 hashes

After upload, confirm the PyPI files match the built artifacts:

- package name `django-trusts` and the intended version;
- both sdist and wheel present;
- SHA-256 of each file;
- metadata still reports the declared Python, Django, and license
  (RC1: Python `>=3.12`, Django 6.1 classifier, BSD-2-Clause).

RC1 hashes are a **worked example**, not forever-required constants.
Record the new hashes in the execution issue for each release.

| Artifact | SHA-256 (1.0.0rc1 only) |
| --- | --- |
| `django_trusts-1.0.0rc1.tar.gz` | `f66f80882a2912901ba997ff1e996a9de1e70a2d832735e77120d93f2664f7a3` |
| `django_trusts-1.0.0rc1-py3-none-any.whl` | `e65468b27840e2c21dd426b8a1be654b4cafd22ea1690cf1ad295aed6a2e5ae3` |

### 9. Announce and record durable artifact links

Announce the exact django-trusts / Zero pairing, supported
Python / Django / databases, authorization and security boundary,
known limitations, and any API-review request.

Record durable links in the execution issue, at least:

- PyPI project/version page;
- GitHub Release / tag;
- documentation build;
- forum (or equivalent) announcement.

## Reuse between RCs

For `rc1 → rc2` and later increments:

1. Start from the previous release tag and review the delta.
2. Keep accepted evidence for unchanged code and unaffected consumers.
3. Rerun django-trusts’s committed release CI and the django-trusts +
   Zero pair on the new exact candidate.
4. Rerun a consumer only when the delta can affect it, or when its
   ordinary CI is part of the default-branch merge.
5. Add the new compatibility tag after the new pairing is confirmed.
   It may point to the same companion commit as the prior tag.
6. Publish only django-trusts unless a companion release was
   independently authorized.

## RC1 worked example

Verified on 2026-09-15. These SHAs and hashes are historical proof,
not values to copy into later releases.

| Repository | Default ref | Exact target | Tag |
| --- | --- | --- | --- |
| django-trusts | `master` | `67312bc8b774e2e48c241b8f25bfc5d4c04894ba` | `v1.0.0rc1` |
| django-trusts-zero | `main` | `3184479ade417c57307c3e18b6c0289347a05687` | `compatible-with-django-trusts-v1.0.0rc1` |
| django-trusts-zero-example | `master` | `230aa4ba7ad996bd8d5b24bab60bd5cc17be44a1` | `compatible-with-django-trusts-v1.0.0rc1` |
| django-trusts-windows-acl | `main` | `804e1ea54361a02860f8aa67b5788771969690b9` | `compatible-with-django-trusts-v1.0.0rc1` |
| django-trusts-gh-permissions | `main` | `44f2c1eb96c726e5da6cc581a6fdeb4d50a7af86` | `compatible-with-django-trusts-v1.0.0rc1` |
| django-trusts-ordered-fold | `main` | `89808c314aff8447030d8664fbd542160f0383ab` | `compatible-with-django-trusts-v1.0.0rc1` |

Durable RC1 links:

- PyPI: https://pypi.org/project/django-trusts/1.0.0rc1/
- GitHub pre-release: https://github.com/django-trusts/django-trusts/releases/tag/v1.0.0rc1
- Docs: https://django-trusts.readthedocs.io/en/master/
- Forum: https://forum.djangoproject.com/t/django-trusts-1-0-0rc1-declarative-object-level-permissions/45996

Separately authorized on RC1, **not** a recurring django-trusts
release step:

- Zero `v0.12.0.dev0` → `74fc24e66884ac24f46864385c1babe78409ed7a`
- Zero Example `compatible-with-django-trusts-zero-v0.12.0.dev0` →
  `230aa4ba7ad996bd8d5b24bab60bd5cc17be44a1`

Those two refs are development-snapshot markers. They did not publish
Zero and do not authorize a Zero GitHub Release or PyPI upload.

## Non-goals

- Coordinated package versions or publication across repositories.
- New release branches in every repository.
- Exhaustive artifact proofs for examples.
- Promoting provisional extensions to stable packages.
- Reopening deferred post-1.0 work such as #147.
- Adding Trusted Publishing workflows or any other CI/workflow change
  merely to follow this runbook.

## Related

- Standing procedure: https://github.com/django-trusts/django-trusts/issues/224
- RC1 execution tracker (closed): https://github.com/django-trusts/django-trusts/issues/149
- Baton lane (do-not-merge): https://github.com/django-trusts/django-trusts/pull/220
