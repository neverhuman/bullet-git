#!/usr/bin/env bash
# Live jeryu-gitd oracle lane. Unset BULLET_LIVE_GITD: neutral, nothing registered.
# Set: no oracle adapter is registered yet, so the request fails closed instead of
# reporting a green lane that ran nothing.
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "nightly lane"
if [[ -z "${BULLET_LIVE_GITD:-}" ]]; then
  log "BULLET_LIVE_GITD unset; no live gitd lane registered"
  exit 0
fi
echo "[ci] BULLET_LIVE_GITD requested but no live jeryu-gitd oracle lane is registered" >&2
exit 1
