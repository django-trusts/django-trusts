# Legacy baseline (pre-modernization)

This document records the django-trusts source as it existed on the default
branch before any modernization. It is a historical snapshot, not a supported
install or test matrix.

**This preservation work makes no API, method, runtime, packaging, or
authorization behavior changes.** `setup.py` still declares version `0.10.3`.
`requirements.txt` is unchanged. No `migrates.md` update is required because
no API or method changed.

Recorded on 2026-09-06 from
[`django-trusts/django-trusts`](https://github.com/django-trusts/django-trusts)
`origin/master`. Machine-readable values live in
[`docs/legacy/baseline.json`](legacy/baseline.json).

## Preserved commit

| Field | Value |
| --- | --- |
| Default branch | `master` |
| Full SHA | `20ef23946d4fcfd9463fcf5953bb9414b8f0521b` |
| Tree SHA | `2a0613d074456c44d07006f7d3692b42e3011ff0` |
| Date | 2016-04-30T07:17:02Z |
| Subject | Merge pull request #10 from beedesk/DOC-Updated-Code-Formatting |
| URL | https://github.com/django-trusts/django-trusts/commit/20ef23946d4fcfd9463fcf5953bb9414b8f0521b |

That commit is the exact `master` tip as of this record. It is the source that
the legacy tag and archive must point at.

## Last published version vs unreleased commits

The last published package version is **0.10.3**.

| Channel | Identifier | Commit |
| --- | --- | --- |
| Git tag | `v0.10.3` | `6222652de6f85e7870e878fb131a93cb39e0ccf7` |
| PyPI | [django-trusts 0.10.3](https://pypi.org/project/django-trusts/0.10.3/) | uploaded 2016-04-30T07:26:47Z |
| Package metadata at that tag | `setup.py` `version='0.10.3'` | same as `master` |

`v0.10.3` is an ancestor of `master`. Two later commits exist on `master` and
were **never tagged or published**:

| SHA | Date | Subject |
| --- | --- | --- |
| `91ae1ba3e899f241730b46cae5dd687db4244571` | 2016-04-30 | Updated code formatting. |
| `20ef23946d4fcfd9463fcf5953bb9414b8f0521b` | 2016-04-30 | Merge pull request #10 from beedesk/DOC-Updated-Code-Formatting |

Those two commits do not change the declared package version. They are
documentation/formatting only. The preserved baseline is still the later
`master` tip, so the complete unreleased default-branch history is kept.

`setup.py` at both `v0.10.3` and `20ef239` reports `version='0.10.3'`. Do not
treat current `master` as a published release.

## Existing release tags

All of the following are **lightweight** tags (they point at commits, not
annotated tag objects). **Do not move or replace them.**

This repository had **no GitHub Releases** when this baseline was recorded
(2026-09-06). Tags exist only as git refs.

| Tag | Commit | Commit date (author) |
| --- | --- | --- |
| `v0.0.2` | `44bfddaf1fe2606ee3590855fc6d74fe48c0d606` | 2015-12-31 |
| `v0.0.3` | `76a3f3fe5ac7e913e2731e1b26cf68e3cc48ba63` | 2016-01-03 |
| `v0.0.4` | `f41486b4a13455744e280cf8e075542308bc2d5f` | 2016-01-08 |
| `v0.0.5` | `a4ad33e6f8c21f1edb8c698033b196befdbdba53` | 2016-01-19 |
| `v0.6.0` | `b9337e63f258c070a70c2dda4501ba912af9ff8c` | 2016-01-22 |
| `v0.9.0` | `5dc12acf461706836a1b5265f7df85e4aae06714` | 2016-01-29 |
| `v0.9.1` | `6360e19630b2a3bbb7c5d93a7513a6f9eb8fdf20` | 2016-01-29 |
| `v0.9.2` | `192de70278b0cf0f01ab623ade6f40b9507f571c` | 2016-01-29 |
| `v0.9.4` | `1671a294d1c70a4c0da9aed6a1f468e7354016de` | 2016-01-29 |
| `v0.9.5` | `88d47f47a589bb7d15d06860cb70e91925d59883` | 2016-01-30 |
| `v0.9.6` | `d1689f68bd87500ef107cc87e2129154293c7626` | 2016-01-30 |
| `v0.10.0` | `0397ff92264af4060813771c3c5f17fcd3c027a9` | 2016-02-03 |
| `v0.10.1` | `bb466b30403032d076ccb37dcfd56460113cc6e6` | 2016-02-04 |
| `v0.10.2` | `7305f617bb5c154f12a03c24423477737fb4b7e9` | 2016-02-15 |
| `v0.10.3` | `6222652de6f85e7870e878fb131a93cb39e0ccf7` | 2016-04-30 |

Notes:

- There is **no** `v0.9.3` git tag. PyPI still has a
  [0.9.3 sdist](https://pypi.org/project/django-trusts/0.9.3/) uploaded
  2016-01-30.
- Current PyPI hosts `0.9.3`, `0.9.4`, `0.9.5`, `0.9.6`, and `0.10.0` through
  `0.10.3` only. Earlier git tags (`v0.0.2`–`v0.9.2`) are not present as
  current PyPI releases.
- A non-default branch `DJANGO-TRUSTS-8-Edit-Perm-Pages` also exists on this
  repository. It is **not** part of the default-branch baseline.

## Chosen legacy tag

| Field | Value |
| --- | --- |
| Name | `legacy-pre-modernization` |
| Target | `20ef23946d4fcfd9463fcf5953bb9414b8f0521b` |
| Why this name | It is not a version tag, so it cannot be confused with `v0.10.3` or a future major version. |

Create this as a **new annotated tag**. Do not retarget `v0.10.3` or any other
existing release tag.

```bash
git fetch origin
git tag -a legacy-pre-modernization 20ef23946d4fcfd9463fcf5953bb9414b8f0521b \
  -m "Legacy django-trusts baseline immediately before modernization.

Points at origin/master as recorded on 2026-09-06:
20ef23946d4fcfd9463fcf5953bb9414b8f0521b

This is not a PyPI release. Last published version remains 0.10.3
(tag v0.10.3 / 6222652de6f85e7870e878fb131a93cb39e0ccf7).
Two unreleased formatting commits follow that tag."
git push origin refs/tags/legacy-pre-modernization
```

Verify after the push:

```bash
test "$(git rev-parse legacy-pre-modernization^{commit})" = 20ef23946d4fcfd9463fcf5953bb9414b8f0521b
```

Until that tag exists on `origin`, treat this item as incomplete. Creating the
tag is a repository write that may require maintainer permissions.

## Source archive

A deterministic source archive of the preserved commit is stored in this
repository:

| Field | Value |
| --- | --- |
| Path | [`docs/legacy/django-trusts-legacy-pre-modernization.tar.gz`](legacy/django-trusts-legacy-pre-modernization.tar.gz) |
| SHA-256 | `ae79e1f0e45c957b33a9acabeb7389aa75dcea714f1621eed6c714d3ef71e084` |
| Size | 26404 bytes |
| Originating commit | `20ef23946d4fcfd9463fcf5953bb9414b8f0521b` |
| Prefix | `django-trusts-20ef23946d4fcfd9463fcf5953bb9414b8f0521b/` |
| Checksums file | [`docs/legacy/SHA256SUMS`](legacy/SHA256SUMS) |
| Contents list | [`docs/legacy/MANIFEST`](legacy/MANIFEST) |

How it was created:

```bash
COMMIT=20ef23946d4fcfd9463fcf5953bb9414b8f0521b
git archive --format=tar --prefix="django-trusts-${COMMIT}/" "$COMMIT" \
  | gzip -n > docs/legacy/django-trusts-legacy-pre-modernization.tar.gz
```

`gzip -n` omits the gzip timestamp so the SHA-256 is repeatable.

### Durable locations

1. **In-repository path (available when this documentation is merged):**
   `docs/legacy/django-trusts-legacy-pre-modernization.tar.gz`
2. **Intended GitHub Release asset (maintainer action; incomplete until done):**
   create a GitHub Release on tag `legacy-pre-modernization` and upload the
   same file. After upload, the durable URL should be:
   `https://github.com/django-trusts/django-trusts/releases/download/legacy-pre-modernization/django-trusts-legacy-pre-modernization.tar.gz`
3. **Git object (always):** commit `20ef23946d4fcfd9463fcf5953bb9414b8f0521b`

GitHub's automatic `archive/` tarballs for a commit or tag are convenient but
are **not** the recorded artifact. Their prefix and gzip metadata can differ,
so their SHA-256 will not match the value above.

Suggested release commands after the tag exists:

```bash
gh release create legacy-pre-modernization \
  --title "Legacy baseline (pre-modernization)" \
  --notes "Source snapshot of commit 20ef23946d4fcfd9463fcf5953bb9414b8f0521b, the master tip before modernization. Not a PyPI release. SHA-256: ae79e1f0e45c957b33a9acabeb7389aa75dcea714f1621eed6c714d3ef71e084" \
  docs/legacy/django-trusts-legacy-pre-modernization.tar.gz \
  docs/legacy/SHA256SUMS
```

## How to retrieve the legacy source

Any of the following reconstructs the preserved tree. They do not claim that
the historical Python or Django stack still installs or that tests still pass.

Checkout the recorded commit:

```bash
git clone https://github.com/django-trusts/django-trusts.git
cd django-trusts
git checkout 20ef23946d4fcfd9463fcf5953bb9414b8f0521b
```

After the legacy tag is pushed:

```bash
git fetch origin tag legacy-pre-modernization
git checkout legacy-pre-modernization
```

Extract the preserved archive from a clone that contains this documentation:

```bash
mkdir /tmp/django-trusts-legacy
tar -xzf docs/legacy/django-trusts-legacy-pre-modernization.tar.gz -C /tmp/django-trusts-legacy
```

Confirm the checksum:

```bash
cd docs/legacy
sha256sum -c SHA256SUMS
```

Or run the helper from the repository root:

```bash
./scripts/verify-legacy-baseline.sh
```

## Historical Python and Django requirements

These are the requirements declared by the preserved commit. They are
**historical**. This document does not claim they still resolve, install, or
pass tests on current operating systems, index servers, or toolchains.

From [`requirements.txt`](https://github.com/django-trusts/django-trusts/blob/20ef23946d4fcfd9463fcf5953bb9414b8f0521b/requirements.txt)
at `20ef239`:

```
Django>=1.8,<1.9
docutils>=0.12
funcsigs>=0.4
mock>=1.3.0
pbr>=1.8.1
six>=1.10.0
wheel>=0.24.0
```

From [`setup.py`](https://github.com/django-trusts/django-trusts/blob/20ef23946d4fcfd9463fcf5953bb9414b8f0521b/setup.py)
classifiers at `20ef239`:

- `Programming Language :: Python :: 2`
- `Framework :: Django :: 1.8`

From [`.travis.yml`](https://github.com/django-trusts/django-trusts/blob/20ef23946d4fcfd9463fcf5953bb9414b8f0521b/.travis.yml)
at `20ef239`:

- CI Python: `2.7`
- Install: `pip install -r requirements.txt`
- Tests: `coverage run --source=trusts setup.py test`

There is no `python_requires` field. The code uses Python 2 idioms
(`unicode_literals`, `django.utils.six`, `ugettext_lazy`).

The 2016 README test instructions were:

```
pip install virtualenv
virtualenv venv/
source venv/bin/activate
python setup.py test
```

Those commands are quoted for history only.

## Examples-repository baseline

| Field | Value |
| --- | --- |
| Repository | [django-trusts/django-trusts-example](https://github.com/django-trusts/django-trusts-example) |
| Default branch | `master` |
| Commit | `0b22f2e4768a3c4ed02dd048627d0d596c7b7eb0` |
| Date | 2016-03-07T00:31:38Z |
| Subject | Updated project name. |
| URL | https://github.com/django-trusts/django-trusts-example/commit/0b22f2e4768a3c4ed02dd048627d0d596c7b7eb0 |
| Tags | none |

Retrieve it:

```bash
git clone https://github.com/django-trusts/django-trusts-example.git
cd django-trusts-example
git checkout 0b22f2e4768a3c4ed02dd048627d0d596c7b7eb0
```

Historical example requirements at that commit (again, not a current install
claim) pin `Django==1.9.4` and do not list `django-trusts`. That default-branch
tree is a 2016 starter project. It is recorded here because it is the examples
repository's default-branch tip corresponding to this preservation date.

A later unmerged examples branch `DJANGO-TRUSTS-8-Edit-Perm-Pages`
(`54e83b76fee2e6e950cec94366adec038ebc1260`, 2016-10-12) exists. It is **not**
the default-branch baseline.

## Verification

From a clone that contains the preserved commit (any branch):

```bash
./scripts/verify-legacy-baseline.sh
```

The script checks:

1. The recorded commit and tree SHA exist and match.
2. Recreating `git archive | gzip -n` yields the recorded SHA-256.
3. The stored archive matches `SHA256SUMS` and `MANIFEST`.
4. Archive paths correspond to `git ls-tree` of the recorded commit.
5. If `legacy-pre-modernization` exists locally or on `origin`, it points at
   `20ef23946d4fcfd9463fcf5953bb9414b8f0521b`. If the tag is absent, the
   script reports that as an incomplete maintainer step rather than a content
   mismatch.

Verification performed while writing this document (2026-09-06):

- `git rev-parse origin/master` = `20ef23946d4fcfd9463fcf5953bb9414b8f0521b`
- `git rev-parse 20ef239^{tree}` = `2a0613d074456c44d07006f7d3692b42e3011ff0`
- Recreated archive SHA-256 matched
  `ae79e1f0e45c957b33a9acabeb7389aa75dcea714f1621eed6c714d3ef71e084`
- Archive file list matched `git ls-tree -r --name-only` of the recorded
  commit (plus the directory prefix entries that `git archive` adds)

## Maintainer follow-up (not done by this documentation PR)

Leave these incomplete until a maintainer with tag and release permission
performs them:

1. Create and push annotated tag `legacy-pre-modernization` at
   `20ef23946d4fcfd9463fcf5953bb9414b8f0521b` using the commands above.
2. Confirm `git rev-parse legacy-pre-modernization^{commit}` equals that SHA
   and that no existing `v*` tag moved.
3. Create a GitHub Release for that tag and upload
   `docs/legacy/django-trusts-legacy-pre-modernization.tar.gz` plus
   `docs/legacy/SHA256SUMS`.
4. Re-run `./scripts/verify-legacy-baseline.sh`.
5. Optionally record the resulting release asset URL in
   [`docs/legacy/baseline.json`](legacy/baseline.json).
