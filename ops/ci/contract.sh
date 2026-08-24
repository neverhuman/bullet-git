#!/usr/bin/env bash
# Mock-only contract lane. MemoryRepository only; no jeryu-gitd network.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "contract lane: in-memory capability API"
run_tests contract
log "contract lane passed"
