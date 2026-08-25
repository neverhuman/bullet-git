#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

run_observed() {
  local lane="$1"
  local script="$2"
  local status
  set +e
  bash scripts/ci-doctor.sh "$lane" && bash "$script"
  status=$?
  set -e
  bash scripts/ci-observation.sh "$lane" "$status" \
    "bash scripts/ci-doctor.sh $lane" "bash $script"
  return "$status"
}

lane="${1:-required}"
case "$lane" in
  source-scan) run_observed source-scan ops/ci/source-scan.sh ;;
  fast) run_observed fast ops/ci/fast.sh ;;
  lint) run_observed lint ops/ci/lint.sh ;;
  contract) run_observed contract ops/ci/contract.sh ;;
  security) run_observed security ops/ci/security.sh ;;
  docs) run_observed docs ops/ci/docs.sh ;;
  required) run_observed required ops/ci/required.sh ;;
  audit) run_observed audit ops/ci/audit.sh ;;
  nightly) run_observed nightly ops/ci/nightly.sh ;;
  history) run_observed history ops/ci/history.sh ;;
  links) run_observed links ops/ci/external-links.sh ;;
  advisory) run_observed advisory ops/ci/advisory.sh ;;
  coverage) run_observed coverage ops/ci/coverage.sh ;;
  platform) run_observed platform ops/ci/platform-refusal.sh ;;
  toolchain-msrv) run_observed toolchain-msrv ops/ci/toolchain-msrv.sh ;;
  gates|all) run_observed required ops/ci/required.sh ;;
  *)
    echo "usage: $0 {source-scan|fast|lint|contract|security|docs|required|audit|nightly|history|links|advisory|coverage|platform|toolchain-msrv|all}" >&2
    exit 2
    ;;
esac
