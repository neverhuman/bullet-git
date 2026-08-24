#!/usr/bin/env bash
# Contract lane: the full workspace suite under the nextest contract profile, including the
# real-Git integration suites and the daemon round trip. In-process only; no jeryu-gitd network.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "contract lane: in-memory capability API"
run_tests contract
log "contract lane passed"
