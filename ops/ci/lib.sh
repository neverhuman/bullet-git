#!/usr/bin/env bash
set -euo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export REPO_ROOT
export GIT_TERMINAL_PROMPT=0
FAST_FILTER='package(bullet-git-types) | package(bullet-git-journal)'
CONTRACT_FILTER='package(bullet-git-workspace) | package(bullet-gitd)'
FAST_EXPECTED_TESTS=62
CONTRACT_EXPECTED_TESTS=160
TOTAL_EXPECTED_TESTS=222
export FAST_FILTER CONTRACT_FILTER FAST_EXPECTED_TESTS CONTRACT_EXPECTED_TESTS TOTAL_EXPECTED_TESTS

log() { printf '[ci] %s\n' "$*"; }
require_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    printf '[ci] missing required tool: %s\n' "$1" >&2
    return 1
  fi
}
run_partition() {
  local lane="$1" profile="$2" filter="$3" expected="$4" listing count status source_report report
  require_tool cargo-nextest || return 1
  require_tool cp || return 1
  require_tool jq || return 1
  source_report="target/nextest/$profile/junit.xml"
  report=".ci-artifacts/reports/$lane.junit.xml"
  mkdir -p .ci-artifacts/reports
  rm -f -- "$source_report" "$report"
  listing="$(cargo nextest list --locked --workspace --profile "$profile" \
    -E "$filter" --message-format json)"
  count="$(jq -r '."test-count"' <<<"$listing")"
  [[ "$count" =~ ^[0-9]+$ && "$count" -gt 0 ]] || {
    printf '[ci] ZERO_TEST_PARTITION: %s selected %s cases\n' "$lane" "$count" >&2
    return 1
  }
  [[ "$count" -eq "$expected" ]] || {
    printf '[ci] TEST_PARTITION_DRIFT: %s selected %s cases; expected %s\n' "$lane" "$count" "$expected" >&2
    return 1
  }
  log "$lane partition: $count cases"
  set +e
  cargo nextest run --locked --workspace --profile "$profile" -E "$filter"
  status=$?
  set -e
  if [[ -s "$source_report" ]]; then
    cp "$source_report" "$report"
  fi
  [[ -s "$report" ]] || {
    printf '[ci] JUNIT_REPORT_MISSING: %s\n' "$source_report" >&2
    return 1
  }
  return "$status"
}
