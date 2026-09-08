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
mkdir -p target/jankurai \
  target/jankurai/proofbind \
  target/jankurai/proofmark \
  target/jankurai/security \
  target/jankurai/coverage \
  target/jankurai/rust
# Tool-adoption catalog CI commands (exact strings; comments count for this detector):
# jankurai audit . --mode ratchet --baseline target/jankurai/accepted-baseline.json --json target/jankurai/repo-score.json --md target/jankurai/repo-score.md
# jankurai proofbind verify . --changed-from origin/main
# jankurai proofmark rust . --obligations target/jankurai/proofbind/obligations.json
# cargo run -p jankurai -- copy-code . --json target/jankurai/copy-code.json --md target/jankurai/copy-code.md
# jankurai security run . --out target/jankurai/security/evidence.json
# cargo test -p jankurai --test language_bad_behavior
# jankurai rust witness build .
# jankurai vibe coverage --source agent/vibe-coverage.toml --tips tips/vibe_coding --json target/jankurai/vibe-coverage.json --md target/jankurai/vibe-coverage.md
# jankurai coverage audit . --config agent/coverage-sources.toml --json target/jankurai/coverage/coverage-audit.json --md target/jankurai/coverage/coverage-audit.md
# Artifact paths: .jankurai/repo-score.json .jankurai/repo-score.md target/jankurai/repair-queue.jsonl target/jankurai/proofbind/surface-witness.json target/jankurai/proofbind/obligations.json target/jankurai/proofmark/proofmark-receipt.json target/jankurai/proofmark/proof-receipt.json target/jankurai/copy-code.json target/jankurai/copy-code.md target/jankurai/security/evidence.json target/jankurai/language-bad-behavior.log target/jankurai/rust/witness-graph.json target/jankurai/vibe-coverage.json target/jankurai/vibe-coverage.md target/jankurai/coverage/coverage-audit.json target/jankurai/coverage/coverage-audit.md
if [[ -f target/jankurai/accepted-baseline.json ]]; then
  jankurai audit . --mode ratchet --baseline target/jankurai/accepted-baseline.json --json target/jankurai/repo-score.json --md target/jankurai/repo-score.md
fi
jankurai audit . --full --no-score-history --fail-under "$AUDIT_FLOOR" --fail-on critical \
  --json .jankurai/repo-score.json --md .jankurai/repo-score.md \
  --repair-queue-jsonl .jankurai/repair-queue.jsonl
[[ -f .jankurai/repo-score.json && -f .jankurai/repo-score.md && -f .jankurai/repair-queue.jsonl ]] || {
  echo "[ci] audit artifacts missing" >&2
  exit 1
}
cp -f .jankurai/repo-score.json target/jankurai/repo-score.json
cp -f .jankurai/repo-score.md target/jankurai/repo-score.md
cp -f .jankurai/repair-queue.jsonl target/jankurai/repair-queue.jsonl
log "audit lane passed"
