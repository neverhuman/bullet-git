#!/usr/bin/env bash
# Validate one atomic lane's exact-subject observation and hashed diagnostics.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
lane="${1:-}"
expected_commit="${2:-}"
artifact_root="${3:-.ci-artifacts}"
mode="${4:-atomic}"
case "$lane" in
  source-scan|fast|lint|contract|security|docs|history|links|advisory|coverage|platform) ;;
  *) echo "usage: $0 <lane> <commit> [artifact-root [atomic|merged]]" >&2; exit 2 ;;
esac
case "$lane" in
  source-scan) lane_script="ops/ci/source-scan.sh" ;;
  fast) lane_script="ops/ci/fast.sh" ;;
  lint) lane_script="ops/ci/lint.sh" ;;
  contract) lane_script="ops/ci/contract.sh" ;;
  security) lane_script="ops/ci/security.sh" ;;
  docs) lane_script="ops/ci/docs.sh" ;;
  history) lane_script="ops/ci/history.sh" ;;
  links) lane_script="ops/ci/external-links.sh" ;;
  advisory) lane_script="ops/ci/advisory.sh" ;;
  coverage) lane_script="ops/ci/coverage.sh" ;;
  platform) lane_script="ops/ci/platform-refusal.sh" ;;
esac
expected_doctor_command="bash scripts/ci-doctor.sh $lane"
expected_lane_command="bash $lane_script"
[[ "$mode" == atomic || "$mode" == merged ]] || { echo "usage: $0 <lane> <commit> [artifact-root [atomic|merged]]" >&2; exit 2; }
[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] || { printf '[ci] CI_COMMIT_INVALID: %s\n' "$expected_commit" >&2; exit 1; }
expected_tree="$(git rev-parse --verify "$expected_commit^{tree}" 2>/dev/null)" || {
  printf '[ci] CI_COMMIT_UNKNOWN: %s\n' "$expected_commit" >&2
  exit 1
}
[[ -d "$artifact_root" && ! -L "$artifact_root" ]] || { printf '[ci] CI_ARTIFACT_ROOT_INVALID: %s\n' "$artifact_root" >&2; exit 1; }
observation="$artifact_root/observations/$lane.json"
[[ -f "$observation" ]] || { printf '[ci] CI_OBSERVATION_MISSING: %s\n' "$observation" >&2; exit 1; }
[[ ! -L "$observation" ]] || { printf '[ci] CI_OBSERVATION_INVALID: %s\n' "$observation" >&2; exit 1; }
jq -e --arg lane "$lane" --arg commit "$expected_commit" --arg tree "$expected_tree" \
  --arg doctor "$expected_doctor_command" --arg command "$expected_lane_command" '
  .schema_version == "bullet.ci-observation.v1" and .repository == "bullet-git" and
  .commit_oid == $commit and .tree_oid == $tree and .clean == true and
  .commands == [$doctor,$command] and
  (.tool_versions | type == "object") and
  .outcomes == [{"lane":$lane,"status":"PASS","exit_code":0}] and
  (.artifact_hashes | type == "array") and
  ([.artifact_hashes[].path] | unique | length) == (.artifact_hashes | length) and
  all(.artifact_hashes[];
    (.path | test("^\\.ci-artifacts/[A-Za-z0-9._/-]+$") and
      (contains("/../") | not) and (endswith("/..") | not) and (contains("//") | not)) and
    (.sha256 | test("^[0-9a-f]{64}$"))) and
  .signed == false and .evidence_class == "DIAGNOSTIC_ONLY" and
  (keys | sort) == (["artifact_hashes","clean","commands","commit_oid","evidence_class",
    "outcomes","repository","schema_version","signed","tool_versions","tree_oid"] | sort)
' "$observation" >/dev/null || { echo "[ci] CI_OBSERVATION_INVALID" >&2; exit 1; }
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
while IFS=$'\t' read -r path expected; do
  [[ -n "$path" ]] || continue
  relative="${path#.ci-artifacts/}"
  artifact="$artifact_root/$relative"
  [[ -f "$artifact" && ! -L "$artifact" ]] || { printf '[ci] CI_ARTIFACT_INVALID: %s\n' "$path" >&2; exit 1; }
  cursor="$artifact_root"
  IFS=/ read -r -a components <<<"$relative"
  for component in "${components[@]}"; do
    cursor="$cursor/$component"
    [[ ! -L "$cursor" ]] || { printf '[ci] CI_ARTIFACT_INVALID: %s\n' "$path" >&2; exit 1; }
  done
  [[ "$(sha256_file "$artifact")" == "$expected" ]] || { printf '[ci] ARTIFACT_HASH_MISMATCH: %s\n' "$path" >&2; exit 1; }
done < <(jq -r '.artifact_hashes[] | [.path, .sha256] | @tsv' "$observation")

expected_hash_paths='[]'
case "$lane" in
  fast|contract) expected_hash_paths="[\".ci-artifacts/reports/$lane.junit.xml\"]" ;;
  coverage) expected_hash_paths='[".ci-artifacts/reports/coverage.lcov"]' ;;
esac
jq -e --argjson expected "$expected_hash_paths" \
  '([.artifact_hashes[].path] | sort) == ($expected | sort)' "$observation" >/dev/null \
  || { echo '[ci] CI_ARTIFACT_INVENTORY_INVALID' >&2; exit 1; }

if [[ "$lane" == fast || "$lane" == contract ]]; then
  report="$artifact_root/reports/$lane.junit.xml"
  lines=()
  while IFS= read -r line || [[ -n "$line" ]]; do
    lines[${#lines[@]}]="$line"
  done <"$report"
  [[ "${#lines[@]}" -eq 4 && "${lines[0]}" == '<?xml version="1.0" encoding="UTF-8"?>' &&
    "${lines[1]}" =~ ^\<testsuites\ tests=\"[0-9]+\"\ failures=\"[0-9]+\"\ errors=\"[0-9]+\"\ skipped=\"[0-9]+\"\>$ &&
    "${lines[2]}" =~ ^\ \ \<testsuite\ name=\"bullet-git-$lane\"\ tests=\"[0-9]+\"\ failures=\"[0-9]+\"\ errors=\"[0-9]+\"\ skipped=\"[0-9]+\"/\>$ &&
    "${lines[3]}" == '</testsuites>' ]] || {
    printf '[ci] SANITIZED_JUNIT_INVALID: %s\n' "$report" >&2
    exit 1
  }
  root_counts="${lines[1]#<testsuites }"
  suite_counts="${lines[2]#*\" }"
  [[ "${root_counts%>}" == "${suite_counts%/>}" ]] || {
    printf '[ci] SANITIZED_JUNIT_COUNTER_MISMATCH: %s\n' "$report" >&2
    exit 1
  }
fi

if [[ "$mode" == atomic ]]; then
  expected_files=("observations/$lane.json")
  case "$lane" in
    fast|contract) expected_files+=("reports/$lane.junit.xml") ;;
    coverage) expected_files+=("reports/coverage.lcov") ;;
  esac
  actual_files=()
  while IFS= read -r file; do
    actual_files[${#actual_files[@]}]="$file"
  done < <(
    find "$artifact_root" -mindepth 1 \( -type f -o -type l \) -print \
      | sed "s#^$artifact_root/##" | LC_ALL=C sort
  )
  [[ "${actual_files[*]}" == "${expected_files[*]}" ]] || {
    printf '[ci] CI_ARTIFACT_TREE_INVALID: expected=[%s] actual=[%s]\n' \
      "${expected_files[*]}" "${actual_files[*]}" >&2
    exit 1
  }
fi
log "artifact allowlist and hashes passed for $lane"
