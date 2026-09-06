#!/usr/bin/env bash
# Recreate and verify the recorded pre-modernization source archive.
# This script does not install the historical Python/Django stack.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASELINE_JSON="$ROOT/docs/legacy/baseline.json"
LEGACY_DIR="$ROOT/docs/legacy"
ARCHIVE_NAME="django-trusts-legacy-pre-modernization.tar.gz"
STORED_ARCHIVE="$LEGACY_DIR/$ARCHIVE_NAME"
SHA256SUMS="$LEGACY_DIR/SHA256SUMS"
MANIFEST="$LEGACY_DIR/MANIFEST"

if [[ ! -f "$BASELINE_JSON" ]]; then
  echo "error: missing $BASELINE_JSON" >&2
  exit 1
fi

python_read() {
  python3 - "$BASELINE_JSON" "$1" <<'PY'
import json, sys
data = json.load(open(sys.argv[1]))
path = sys.argv[2].split(".")
cur = data
for key in path:
    cur = cur[key]
if not isinstance(cur, str):
    cur = str(cur)
print(cur)
PY
}

COMMIT="$(python_read preserved_commit)"
TREE="$(python_read preserved_tree)"
TAG="$(python_read legacy_tag)"
EXPECTED_SHA256="$(python_read archive.sha256)"
PREFIX="$(python_read archive.prefix)"

fail=0
note() { printf '%s\n' "$*"; }
ok() { printf 'ok: %s\n' "$*"; }
warn() { printf 'incomplete: %s\n' "$*"; }
err() { printf 'error: %s\n' "$*" >&2; fail=1; }

sha256_of() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

note "Recorded commit: $COMMIT"
note "Recorded tree:   $TREE"
note "Legacy tag:      $TAG"
note

if ! git cat-file -e "${COMMIT}^{commit}" 2>/dev/null; then
  err "recorded commit $COMMIT is not present in this clone"
  exit 1
fi
ok "recorded commit exists"

actual_commit="$(git rev-parse "${COMMIT}^{commit}")"
if [[ "$actual_commit" != "$COMMIT" ]]; then
  err "commit resolved to $actual_commit, expected $COMMIT"
else
  ok "commit SHA matches"
fi

actual_tree="$(git rev-parse "${COMMIT}^{tree}")"
if [[ "$actual_tree" != "$TREE" ]]; then
  err "tree is $actual_tree, expected $TREE"
else
  ok "tree SHA matches"
fi

if [[ ! -f "$STORED_ARCHIVE" ]]; then
  err "stored archive missing: $STORED_ARCHIVE"
  exit 1
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf "$tmpdir"' EXIT

recreated="$tmpdir/$ARCHIVE_NAME"
git archive --format=tar --prefix="$PREFIX" "$COMMIT" | gzip -n > "$recreated"

recreated_sha="$(sha256_of "$recreated")"
stored_sha="$(sha256_of "$STORED_ARCHIVE")"

if [[ "$recreated_sha" != "$EXPECTED_SHA256" ]]; then
  err "recreated archive SHA-256 is $recreated_sha, expected $EXPECTED_SHA256"
else
  ok "recreated archive SHA-256 matches recorded value"
fi

if [[ "$stored_sha" != "$EXPECTED_SHA256" ]]; then
  err "stored archive SHA-256 is $stored_sha, expected $EXPECTED_SHA256"
else
  ok "stored archive SHA-256 matches recorded value"
fi

if [[ "$stored_sha" != "$recreated_sha" ]]; then
  err "stored archive does not match a fresh git archive | gzip -n"
else
  ok "stored archive matches freshly created archive"
fi

if command -v sha256sum >/dev/null 2>&1; then
  if ! (cd "$LEGACY_DIR" && sha256sum -c SHA256SUMS); then
    err "SHA256SUMS check failed"
  else
    ok "SHA256SUMS check passed"
  fi
else
  listed="$(awk '{print $1}' "$SHA256SUMS")"
  if [[ "$listed" != "$EXPECTED_SHA256" ]]; then
    err "SHA256SUMS does not list $EXPECTED_SHA256"
  else
    ok "SHA256SUMS lists the recorded digest"
  fi
fi

actual_manifest="$tmpdir/MANIFEST"
tar -tzf "$STORED_ARCHIVE" | LC_ALL=C sort > "$actual_manifest"
expected_manifest="$tmpdir/expected-MANIFEST"
LC_ALL=C sort "$MANIFEST" > "$expected_manifest"
if ! cmp -s "$expected_manifest" "$actual_manifest"; then
  err "archive contents do not match docs/legacy/MANIFEST"
  diff -u "$expected_manifest" "$actual_manifest" || true
else
  ok "archive contents match docs/legacy/MANIFEST"
fi

# Directory prefixes added by git archive are not in ls-tree. Compare files only.
archive_files="$tmpdir/archive-files"
git_files="$tmpdir/git-files"
tar -tzf "$STORED_ARCHIVE" \
  | sed "s#^${PREFIX}##" \
  | grep -v '/$' \
  | grep -v '^$' \
  | LC_ALL=C sort > "$archive_files"
git ls-tree -r --name-only "$COMMIT" | LC_ALL=C sort > "$git_files"
if ! cmp -s "$git_files" "$archive_files"; then
  err "archive file list does not match git ls-tree of $COMMIT"
  diff -u "$git_files" "$archive_files" || true
else
  ok "archive files match git ls-tree of the recorded commit"
fi

resolve_tag() {
  local ref="$1"
  local sha=""
  if sha="$(git rev-parse --verify --quiet "${ref}^{commit}" 2>/dev/null)"; then
    printf '%s\n' "$sha"
  fi
}

tag_commit="$(resolve_tag "refs/tags/${TAG}")"
if [[ -z "$tag_commit" ]]; then
  tag_commit="$(resolve_tag "$TAG")"
fi
if [[ -z "$tag_commit" ]]; then
  tag_commit="$(resolve_tag "refs/remotes/origin/${TAG}")"
fi
if [[ -z "$tag_commit" ]]; then
  warn "tag $TAG is not present locally or on origin"
  warn "create it with: git tag -a $TAG $COMMIT && git push origin refs/tags/$TAG"
else
  if [[ "$tag_commit" != "$COMMIT" ]]; then
    err "tag $TAG points at $tag_commit, expected $COMMIT"
  else
    ok "tag $TAG points at the recorded commit"
  fi
fi

if [[ "$fail" -ne 0 ]]; then
  echo
  echo "legacy baseline verification failed"
  exit 1
fi

echo
echo "legacy baseline verification passed"
echo "tag push / GitHub release remain maintainer steps if the tag check is incomplete"
