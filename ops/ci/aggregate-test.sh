#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
green=(success present success present success present success present success present success present)
bash ops/ci/aggregate.sh "${green[@]}" >/dev/null
expect_failure() {
  local reason="$1" output status
  shift
  set +e
  output="$(bash ops/ci/aggregate.sh "$@" 2>&1)"
  status=$?
  set -e
  [[ "$status" -eq 1 && "$output" == *"$reason"* ]] || {
    printf '[ci] aggregator did not refuse with %s (status=%s, output=%s)\n' "$reason" "$status" "$output" >&2
    exit 1
  }
}
for bad in failure skipped cancelled ''; do
  candidate=("${green[@]}")
  candidate[2]="$bad"
  expect_failure CI_JOB_NOT_SUCCESSFUL "${candidate[@]}"
done
candidate=("${green[@]}")
candidate[3]=''
expect_failure CI_OBSERVATION_MISSING "${candidate[@]}"
expect_failure CI_JOB_MISSING "${green[@]:0:10}"
log "aggregator rejects failed, skipped, cancelled, missing jobs and observations"
