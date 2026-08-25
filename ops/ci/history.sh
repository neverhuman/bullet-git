#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
require_tool gitleaks || exit 1
commit_count="$(git rev-list --count HEAD)"
[[ "$commit_count" =~ ^[1-9][0-9]*$ ]] || { echo "[ci] HISTORY_INVENTORY_EMPTY" >&2; exit 1; }
log "full-history secret scan: $commit_count commits"
gitleaks git --redact=100 --no-banner --no-color .
log "full-history secret scan passed"
