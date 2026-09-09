#!/usr/bin/env bash
# Explicit local jeryu-gitd oracle entrypoint; no hosted schedule is registered yet.
# Unset BULLET_LIVE_GITD returns 78 to distinguish unregistered from success.
# Set: no oracle adapter is registered yet, so the request fails closed instead of
# reporting a green lane that ran nothing.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "nightly lane"
if [[ -z "${BULLET_LIVE_GITD:-}" ]]; then
  log "BULLET_LIVE_GITD unset; no live gitd lane registered"
  exit 78
fi
echo "[ci] BULLET_LIVE_GITD requested but no live jeryu-gitd oracle lane is registered" >&2
exit 1
