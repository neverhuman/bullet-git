#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
require_tool gitleaks || exit 1
log "source admission: current tree and lockfiles before dependency installation"
gitleaks dir --redact=100 --no-banner --no-color .
log "source admission passed"
