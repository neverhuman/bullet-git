#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "scheduled advisory diagnostic"
bash ops/ci/advisory-db.sh
cargo deny --locked check advisories
log "scheduled advisory diagnostic passed"
