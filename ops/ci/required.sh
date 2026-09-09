#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "required gate: source admission, then five atomic lanes exactly once"
bash ops/ci/source-scan.sh
bash ops/ci/fast.sh
bash ops/ci/lint.sh
bash ops/ci/contract.sh
bash ops/ci/security.sh
bash ops/ci/docs.sh
log "required gate passed"
