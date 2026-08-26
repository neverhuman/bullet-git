#!/usr/bin/env bash
# Contract-lane helper: replay checked-in patch and .git/config corpora against
# their exact admission/refusal outcomes. This is not a cargo-fuzz receipt.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
require_tool cargo || exit 1
require_tool git || exit 1
log "fuzz lane: replay checked-in corpora"
export CARGO_TARGET_DIR="$REPO_ROOT/target/fuzz-replay"
cargo test --locked --offline \
  --manifest-path crates/bullet-git-workspace/fuzz/Cargo.toml --bin replay --quiet
cargo run --locked --offline \
  --manifest-path crates/bullet-git-workspace/fuzz/Cargo.toml \
  --bin replay --quiet
log "fuzz lane passed"
