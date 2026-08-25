#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
required=.github/workflows/ci.yml
scheduled=.github/workflows/scheduled.yml
[[ -f "$required" && -f "$scheduled" ]] || { echo "[ci] WORKFLOW_MISSING" >&2; exit 1; }
for workflow in "$required" "$scheduled"; do
  grep -Eq 'runs-on: (ubuntu-24.04|macos-15|windows-2025)' "$workflow"
  if grep -Eq 'ubuntu-latest|pull_request_target|continue-on-error|secrets\.|permissions:.*write|uses:.*cache|rust-cache' "$workflow"; then
    printf '[ci] FORBIDDEN_WORKFLOW_CONTROL: %s\n' "$workflow" >&2
    exit 1
  fi
  if grep -Eq '^[[:space:]]+paths(-ignore)?:' "$workflow"; then
    printf '[ci] PATH_FILTERED_REQUIRED_WORKFLOW: %s\n' "$workflow" >&2
    exit 1
  fi
  while IFS= read -r use; do
    [[ "$use" =~ @[0-9a-f]{40}([[:space:]]*#.*)?$ ]] || { printf '[ci] ACTION_NOT_PINNED_TO_SHA: %s: %s\n' "$workflow" "$use" >&2; exit 1; }
  done < <(grep -E '^[[:space:]]+- uses:' "$workflow")
  checkout_count="$(grep -c 'uses: actions/checkout@' "$workflow")"
  credential_count="$(grep -c 'persist-credentials: false' "$workflow")"
  [[ "$checkout_count" -eq "$credential_count" ]] || { printf '[ci] CHECKOUT_CREDENTIAL_POLICY_DRIFT: %s\n' "$workflow" >&2; exit 1; }
done
grep -q '^name: CI$' "$required"
grep -q '^  merge_group:$' "$required"
expected_cancel="cancel-in-progress: \${{ github.event_name == 'pull_request' }}"
grep -Fq "$expected_cancel" "$required"
grep -q '^    name: required$' "$required"
expected_always="if: \${{ always() }}"
grep -Fq "$expected_always" "$required"
grep -Eq 'uses: actions/download-artifact@[0-9a-f]{40}' "$required"
expected_commit_binding="EXPECTED_COMMIT: \${{ github.sha }}"
expected_artifact_pattern="pattern: bullet-git-*-\${{ github.run_id }}-\${{ github.run_attempt }}"
grep -Fq "$expected_commit_binding" "$required"
grep -Fq "$expected_artifact_pattern" "$required"
[[ "$(grep -c 'name: bullet-git-.*github.run_id.*github.run_attempt' "$required")" -eq 6 ]] || {
  echo '[ci] RUN_BOUND_ARTIFACT_NAME_DRIFT' >&2
  exit 1
}
if grep -q 'needs\..*outputs\.observation' "$required"; then
  echo '[ci] UNVERIFIED_OUTPUT_AGGREGATION' >&2
  exit 1
fi
grep -q 'toolchain: 1.97.1' "$required"
[[ "$(grep -c 'run: bash ops/ci/install-gitleaks.sh' "$required")" -eq 2 ]] || {
  echo '[ci] REQUIRED_GITLEAKS_INSTALLATION_DRIFT' >&2
  exit 1
}
grep -q 'name: macOS compile and typed refusal' "$scheduled"
grep -q 'runs-on: macos-15' "$scheduled"
grep -q 'name: Windows compile and typed refusal' "$scheduled"
grep -q 'runs-on: windows-2025' "$scheduled"
grep -q 'fetch-depth: 0' "$scheduled"
source_scan_line="$(grep -n -m1 '^[[:space:]]*bash scripts/ci-local.sh source-scan$' Justfile | cut -d: -f1)"
rustup_line="$(grep -n -m1 '^[[:space:]]*rustup component add rustfmt clippy$' Justfile | cut -d: -f1)"
cargo_fetch_line="$(grep -n -m1 '^[[:space:]]*cargo fetch --locked$' Justfile | cut -d: -f1)"
if (( source_scan_line >= rustup_line || source_scan_line >= cargo_fetch_line )); then
  echo '[ci] SETUP_SOURCE_SCAN_ORDER_DRIFT' >&2
  exit 1
fi
log "workflow policy: triggers, pins, exact-run artifacts, expected commit, and aggregator are exact"
