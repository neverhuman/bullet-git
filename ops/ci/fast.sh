#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "fast lane: type and journal component partition"
# Canonical deterministic command shape executed by run_partition:
# cargo nextest run --locked --workspace --profile fast
status=0
run_partition fast fast "$FAST_FILTER" "$FAST_EXPECTED_TESTS" || status=$?
if [[ -s .ci-artifacts/reports/fast.junit.xml ]]; then
  bash ops/ci/sanitize-junit.sh fast
fi
[[ "$status" -eq 0 ]] || exit "$status"
log "fast lane passed"
