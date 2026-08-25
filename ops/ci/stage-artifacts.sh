#!/usr/bin/env bash
# Copy one validated lane's closed diagnostic inventory into an isolated upload
# directory. Uploading the directory preserves observations/ and reports/ even
# for lanes that have only one file; uploading that file directly would not.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

lane="${1:-}"
expected_commit="${2:-}"
case "$lane" in source-scan|fast|lint|contract|security|docs|history|links|advisory|coverage|platform) ;; *)
  printf '[ci] CI_STAGE_LANE_INVALID: %s\n' "$lane" >&2
  exit 2
esac

bash ops/ci/artifact-check.sh "$lane" "$expected_commit"
stage_parent="$REPO_ROOT/target/ci-upload"
stage_root="$stage_parent/$lane"
[[ ! -L "$REPO_ROOT/target" && ! -L "$stage_parent" && ! -L "$stage_root" ]] || {
  printf '[ci] CI_STAGE_ROOT_INVALID: %s\n' "$stage_root" >&2
  exit 1
}
mkdir -p -- "$stage_parent"
chmod 700 -- "$stage_parent"
rm -rf -- "$stage_root"
mkdir -m 700 -- "$stage_root/observations"

copy_path() {
  local source="$1" relative destination
  [[ "$source" == .ci-artifacts/* && "$source" != *'/../'* && "$source" != *'//'*
    && -f "$source" && ! -L "$source" ]] || {
    printf '[ci] CI_STAGE_SOURCE_INVALID: %s\n' "$source" >&2
    return 1
  }
  relative="${source#.ci-artifacts/}"
  destination="$stage_root/$relative"
  mkdir -p -- "${destination%/*}"
  chmod 700 -- "${destination%/*}"
  cp -- "$source" "$destination"
  chmod 600 -- "$destination"
}

observation=".ci-artifacts/observations/$lane.json"
copy_path "$observation"
while IFS= read -r artifact; do
  [[ -n "$artifact" ]] || continue
  copy_path "$artifact"
done < <(jq -r '.artifact_hashes[].path' "$observation")

bash ops/ci/artifact-check.sh "$lane" "$expected_commit" "$stage_root" atomic
log "staged exact $lane diagnostics under target/ci-upload/$lane"
