#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
mkdir -p .ci-artifacts/reports
rm -f -- .ci-artifacts/reports/coverage.lcov
log "scheduled workspace coverage diagnostic"
cargo llvm-cov nextest --locked --workspace --lcov --output-path .ci-artifacts/reports/coverage.lcov
[[ -s .ci-artifacts/reports/coverage.lcov ]] || { echo "[ci] COVERAGE_REPORT_MISSING" >&2; exit 1; }
bash ops/ci/assert-coverage.sh
log "scheduled coverage diagnostic passed"
