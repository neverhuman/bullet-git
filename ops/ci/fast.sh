#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "fast lane: type and journal component partition"
# Canonical deterministic command shape executed by run_partition:
# cargo nextest run --locked --workspace --profile fast
run_partition fast fast "$FAST_FILTER" "$FAST_EXPECTED_TESTS"
log "fast lane passed"
