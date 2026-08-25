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
log "workflow policy: triggers, permissions, pins, runners, cancellation, and aggregator are exact"
