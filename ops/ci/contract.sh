#!/usr/bin/env bash
# Contract lane: the full workspace suite under the nextest contract profile, including the
# real-Git integration suites and the spawned daemon round trip. Local processes only; no network.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "contract lane: local capability API and daemon process"
run_tests contract
log "contract lane passed"
