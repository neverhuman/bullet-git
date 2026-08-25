#!/usr/bin/env bash
# Contract lane: all workspace and daemon tests, including real local Git and
# the spawned daemon round trip. Local subprocesses only; no forge network.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "contract lane: workspace capability API and daemon process partition"
run_partition contract contract "$CONTRACT_FILTER" "$CONTRACT_EXPECTED_TESTS"
log "contract lane passed"
