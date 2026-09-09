#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "non-Linux compile plus production-daemon typed refusal"
cargo check --locked --workspace --all-targets
refusal_test=self_authored_token_cannot_create_a_workspace
selected="$(cargo test --locked -p bullet-gitd --test daemon_roundtrip -- --list \
  | awk -v expected="$refusal_test: test" \
    '{ sub(/\r$/, "", $0); if ($0 == expected) count++ } END { print count + 0 }')"
[[ "$selected" -eq 1 ]] || {
  printf '[ci] PLATFORM_REFUSAL_TEST_INVENTORY_DRIFT: selected %s; expected exactly 1\n' "$selected" >&2
  exit 1
}
cargo test --locked -p bullet-gitd --test daemon_roundtrip \
  "$refusal_test" -- --exact
log "platform compile and AUTHORITY_CONTRACT_UNAVAILABLE refusal passed"
