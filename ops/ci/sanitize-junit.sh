#!/usr/bin/env bash
# Replace nextest's raw JUnit with a deterministic counter-only summary. Raw
# test names, stdout/stderr, timestamps, durations, UUIDs, and host paths are
# deliberately excluded from the publishable artifact.
set -euo pipefail
lane="${1:-}"
case "$lane" in fast|contract) ;; *) echo "usage: $0 {fast|contract} [report]" >&2; exit 2;; esac
report="${2:-.ci-artifacts/reports/$lane.junit.xml}"
[[ -f "$report" && ! -L "$report" ]] || { printf '[ci] JUNIT_SOURCE_INVALID: %s\n' "$report" >&2; exit 1; }

xml_integer_attribute() {
  local line="$1" attribute="$2" matches count value
  matches="$(grep -oE "[[:space:]]${attribute}=\"[0-9]+\"" <<<"$line" || true)"
  count="$(grep -c . <<<"$matches")"
  [[ "$count" -eq 1 ]] || {
    printf '[ci] JUNIT_SOURCE_INVALID: expected one %s attribute\n' "$attribute" >&2
    return 1
  }
  value="${matches#*=\"}"
  printf '%s\n' "${value%\"}"
}

mapfile -t roots < <(grep '^<testsuites ' "$report" || true)
[[ "${#roots[@]}" -eq 1 ]] || { echo '[ci] JUNIT_SOURCE_INVALID: expected one testsuites root' >&2; exit 1; }
tests="$(xml_integer_attribute "${roots[0]}" tests)"
failures="$(xml_integer_attribute "${roots[0]}" failures)"
errors="$(xml_integer_attribute "${roots[0]}" errors)"
mapfile -t suites < <(grep '^[[:space:]]*<testsuite ' "$report" || true)
[[ "${#suites[@]}" -gt 0 ]] || { echo '[ci] JUNIT_SOURCE_INVALID: no testsuite counters' >&2; exit 1; }
sum_tests=0
sum_failures=0
sum_errors=0
skipped=0
for suite in "${suites[@]}"; do
  sum_tests=$(( sum_tests + $(xml_integer_attribute "$suite" tests) ))
  sum_failures=$(( sum_failures + $(xml_integer_attribute "$suite" failures) ))
  sum_errors=$(( sum_errors + $(xml_integer_attribute "$suite" errors) ))
  skipped=$(( skipped + $(xml_integer_attribute "$suite" disabled) ))
done
[[ "$sum_tests" -eq "$tests" && "$sum_failures" -eq "$failures" && "$sum_errors" -eq "$errors" ]] || {
  echo '[ci] JUNIT_SOURCE_INVALID: root and suite counters differ' >&2
  exit 1
}

temporary="$(mktemp "${report}.tmp.XXXXXX")"
cleanup() { rm -f -- "$temporary"; }
trap cleanup EXIT
printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' \
  "<testsuites tests=\"$tests\" failures=\"$failures\" errors=\"$errors\" skipped=\"$skipped\">" \
  "  <testsuite name=\"bullet-git-$lane\" tests=\"$tests\" failures=\"$failures\" errors=\"$errors\" skipped=\"$skipped\"/>" \
  '</testsuites>' >"$temporary"
mv -- "$temporary" "$report"
trap - EXIT
