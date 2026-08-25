#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "pre-push quality gate: deterministic fast lane"
exec bash ops/ci/fast.sh
