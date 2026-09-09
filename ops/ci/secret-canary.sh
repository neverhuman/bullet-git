#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
require_tool gitleaks || exit 1
canary_tmp="$(mktemp -d)"
cleanup() { rm -rf -- "$canary_tmp"; }
trap cleanup EXIT
printf 'token = glpat-%s%s\n' '0123456789' 'abcdefghij' >"$canary_tmp/canary.txt"
set +e
gitleaks dir --redact=100 --no-banner --no-color "$canary_tmp" >"$canary_tmp/result" 2>&1
status=$?
set -e
[[ "$status" -eq 1 ]] || {
  printf '[ci] SECRET_CANARY_NOT_DETECTED: gitleaks exited %s\n' "$status" >&2
  exit 1
}
grep -q 'leaks found: 1' "$canary_tmp/result" || {
  echo "[ci] SECRET_CANARY_RESULT_UNRECOGNIZED: scanner did not report one finding" >&2
  exit 1
}
log "synthetic secret canary detected and redacted"
