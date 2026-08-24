#!/usr/bin/env bash
# Live jeryu-gitd oracle. Skip when the feature or pin is missing.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "nightly lane"
if [[ -z "${BULLET_LIVE_GITD:-}" ]]; then
  log "BULLET_LIVE_GITD unset; skip live gitd"
  exit 0
fi
log "live gitd requested; adapter not implemented yet"
exit 0
