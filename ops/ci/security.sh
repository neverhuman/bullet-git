#!/usr/bin/env bash
# Supply-chain lane. Current-tree secret admission runs before every dependency
# installation in required/hosted orchestration; this lane proves the scanner
# can still find a synthetic secret and runs every cargo-deny policy.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "security lane: secret canary plus cargo-deny policies"
require_tool gitleaks || exit 1
require_tool cargo-deny || exit 1
require_tool git || exit 1
[[ -f deny.toml ]] || { echo "[ci] deny.toml missing: no committed supply-chain policy" >&2; exit 1; }
bash ops/ci/secret-canary.sh
bash ops/ci/advisory-db.sh
cargo deny --locked check licenses advisories bans sources
cargo deny --manifest-path crates/bullet-git-workspace/fuzz/Cargo.toml --locked \
  check --config deny.toml licenses advisories bans sources
log "security lane passed"
