#!/usr/bin/env bash
# Recreate and verify the recorded pre-modernization source archive.
# This script does not install the historical Python/Django stack.
#
# Exit codes:
#   0  complete success (archive, commit, tree, and local tag all match)
#   1  verification failed (mismatch or missing required content)
#   2  incomplete (local tag not checked, or --partial mode)
#
# A complete pass requires the local tag refs/tags/<legacy_tag>. This script
# does not query the server. Fetch the existing tag if it is missing locally:
#   git fetch origin tag legacy-pre-modernization
# Do not create a new tag merely because it is absent from this clone.

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/verify-legacy-baseline.sh [--partial]

Verify the recorded pre-modernization source archive against the preserved
commit. A complete successful run requires the local tag named in
docs/legacy/baseline.json (legacy-pre-modernization) to point at the
recorded commit.

  --partial   Check the archive, commit, and tree only. Skip the tag
              requirement. Even when those checks pass, the result is
              incomplete (exit 2).

If the tag is missing locally, fetch the existing tag; do not create one:

  git fetch origin tag legacy-pre-modernization
EOF
}

PARTIAL=0
for arg in "$@"; do
  case "$arg" in
    --partial) PARTIAL=1 ;;
    -h|--help) usage; exit 0 ;;
    *)
      printf 'error: unknown argument: %s\n' "$arg" >&2
      usage >&2
      exit 1
      ;;
  esac
done

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
incomplete=0
note() { printf '%s\n' "$*"; }
ok() { printf 'ok: %s\n' "$*"; }
warn() { printf 'incomplete: %s\n' "$*"; incomplete=1; }
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
if [[ "$PARTIAL" -eq 1 ]]; then
  note "Mode:            --partial (tag check skipped; result cannot be complete)"
fi
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

# Only a local tag ref can complete verification. Remote-tracking names such
# as refs/remotes/origin/<tag> are local leftovers and are not queried.
if [[ "$PARTIAL" -eq 1 ]]; then
  warn "tag $TAG was not checked (--partial)"
  warn "re-run without --partial after: git fetch origin tag $TAG"
else
  tag_commit=""
  if tag_commit="$(git rev-parse --verify --quiet "refs/tags/${TAG}^{commit}" 2>/dev/null)"; then
    if [[ "$tag_commit" != "$COMMIT" ]]; then
      err "local tag $TAG points at $tag_commit, expected $COMMIT"
    else
      ok "local tag $TAG points at the recorded commit"
    fi
  else
    warn "local tag $TAG is not present (refs/tags/$TAG)"
    warn "this is not a complete verification; fetch the existing tag:"
    warn "  git fetch origin tag $TAG"
    warn "do not create a new tag because it is missing from this clone"
  fi
fi

echo
if [[ "$fail" -ne 0 ]]; then
  echo "legacy baseline verification failed"
  exit 1
fi
if [[ "$incomplete" -ne 0 ]]; then
  echo "legacy baseline verification incomplete"
  echo "archive/commit checks may have passed, but the local tag was not verified"
  exit 2
fi

echo "legacy baseline verification passed"
