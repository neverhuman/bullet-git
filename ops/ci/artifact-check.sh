#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
lane="${1:-}"
[[ -n "$lane" ]] || { echo "usage: $0 <lane>" >&2; exit 2; }
observation=".ci-artifacts/observations/$lane.json"
[[ -f "$observation" ]] || { printf '[ci] CI_OBSERVATION_MISSING: %s\n' "$observation" >&2; exit 1; }
jq -e --arg lane "$lane" '
  .schema_version == "bullet.ci-observation.v1" and .repository == "bullet-git" and
  (.commit_oid | test("^[0-9a-f]{40}$")) and (.tree_oid | test("^[0-9a-f]{40}$")) and
  ((.clean | type) == "boolean") and (.commands | type == "array" and length > 0) and
  ((.tool_versions | type) == "object") and (.outcomes | length == 1) and
  (.outcomes[0].lane == $lane) and
  (.outcomes[0].status == "PASS" or .outcomes[0].status == "FAIL") and
  ((.outcomes[0].exit_code | type) == "number") and ((.artifact_hashes | type) == "array") and
  .signed == false and .evidence_class == "DIAGNOSTIC_ONLY" and (has("timestamp") | not)
' "$observation" >/dev/null || { echo "[ci] CI_OBSERVATION_INVALID" >&2; exit 1; }
sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}';
  else shasum -a 256 "$1" | awk '{print $1}'; fi
}
while IFS=$'\t' read -r path expected; do
  [[ -n "$path" ]] || continue
  [[ "$path" != /* && "$path" != *'..'* && "$expected" =~ ^[0-9a-f]{64}$ ]] || {
    printf '[ci] UNSAFE_ARTIFACT_REFERENCE: %s\n' "$path" >&2; exit 1;
  }
  [[ -f "$path" ]] || { printf '[ci] ARTIFACT_MISSING: %s\n' "$path" >&2; exit 1; }
  [[ "$(sha256_file "$path")" == "$expected" ]] || { printf '[ci] ARTIFACT_HASH_MISMATCH: %s\n' "$path" >&2; exit 1; }
done < <(jq -r '.artifact_hashes[] | [.path, .sha256] | @tsv' "$observation")
case "$lane" in
  fast|contract)
    report=".ci-artifacts/reports/$lane.junit.xml"
    if [[ ! -s "$report" ]] || ! grep -Eq '<testsuites|<testsuite' "$report"; then
      printf '[ci] SANITIZED_JUNIT_MISSING: %s\n' "$report" >&2; exit 1;
    fi
    ;;
  coverage) [[ -s .ci-artifacts/reports/coverage.lcov ]] || { echo "[ci] COVERAGE_REPORT_MISSING" >&2; exit 1; } ;;
esac
while IFS= read -r file; do
  [[ -n "$file" ]] || continue
  name="$(basename "$file" | tr '[:upper:]' '[:lower:]')"
  case "$name" in *bootstrap*|*credential*|*raw.log*|*secret*|*token*)
    printf '[ci] FORBIDDEN_ARTIFACT_NAME: %s\n' "$file" >&2; exit 1;; esac
  size="$(wc -c <"$file")"
  (( size <= 26214400 )) || { printf '[ci] ARTIFACT_TOO_LARGE: %s (%s bytes)\n' "$file" "$size" >&2; exit 1; }
done < <(find .ci-artifacts -type f -print | LC_ALL=C sort)
log "artifact allowlist and hashes passed for $lane"
