#!/usr/bin/env bash
# Jankurai audit lane. Writes .jankurai/repo-score.{json,md} and repair-queue.jsonl.
# AUDIT_FLOOR is a ratchet: it may only rise. Missing auditor fails closed.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
AUDIT_FLOOR=65
require_tool jankurai || exit 1
mkdir -p .jankurai
# Hermetic: an earlier report left in .jankurai/ is itself scannable text, so a
# stale artifact can score the repository. Clear every auditor artifact first.
rm -f .jankurai/repo-score.json .jankurai/repo-score.md .jankurai/repair-queue.jsonl \
  .jankurai/repo-score-current.json .jankurai/repo-score-current.md .jankurai/score-history.jsonl
log "audit lane: jankurai audit (floor ${AUDIT_FLOOR})"
jankurai audit . --full --no-score-history --fail-under "$AUDIT_FLOOR" --fail-on critical \
  --json .jankurai/repo-score.json --md .jankurai/repo-score.md \
  --repair-queue-jsonl .jankurai/repair-queue.jsonl
[[ -f .jankurai/repo-score.json && -f .jankurai/repo-score.md && -f .jankurai/repair-queue.jsonl ]] || {
  echo "[ci] audit artifacts missing" >&2
  exit 1
}
log "audit lane passed"
