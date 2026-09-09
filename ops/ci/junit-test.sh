#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT
canary="$(printf '%s%s' 'AKIAIOSF' 'ODNN7EXAMPLE')"

write_raw() {
  cat >"$test_root/raw.xml" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="nextest-run" tests="3" failures="1" errors="0" uuid="volatile" timestamp="volatile">
  <testsuite name="one" tests="2" disabled="1" errors="0" failures="1">
    <testcase name="secret-test"><system-out>$canary</system-out></testcase>
  </testsuite>
  <testsuite name="two" tests="1" disabled="0" errors="0" failures="0"/>
</testsuites>
EOF
}

expect_failure() {
  local reason="$1" output status
  set +e
  output="$(bash ops/ci/sanitize-junit.sh fast "$test_root/raw.xml" 2>&1)"
  status=$?
  set -e
  [[ "$status" -eq 1 && "$output" == *"$reason"* ]] || {
    printf '[ci] JUnit sanitizer did not refuse %s (status=%s output=%s)\n' "$reason" "$status" "$output" >&2
    exit 1
  }
}

write_raw
bash ops/ci/sanitize-junit.sh fast "$test_root/raw.xml"
grep -Fq '<testsuites tests="3" failures="1" errors="0" skipped="1">' "$test_root/raw.xml"
if grep -Eq "$canary|system-out|system-err|timestamp=|uuid=|classname=|testcase" "$test_root/raw.xml"; then
  echo '[ci] JUNIT_SANITIZER_LEAK: output or volatile metadata survived' >&2
  exit 1
fi
write_raw; sed -i 's/tests="3"/tests="3" tests="3"/' "$test_root/raw.xml"
expect_failure JUNIT_SOURCE_INVALID
write_raw; sed -i 's/ disabled="1"//' "$test_root/raw.xml"
expect_failure JUNIT_SOURCE_INVALID
write_raw; sed -i 's/tests="3"/tests="4"/' "$test_root/raw.xml"
expect_failure JUNIT_SOURCE_INVALID
write_raw; mv "$test_root/raw.xml" "$test_root/target.xml"; ln -s "$test_root/target.xml" "$test_root/raw.xml"
expect_failure JUNIT_SOURCE_INVALID
set +e
invalid_output="$(bash ops/ci/sanitize-junit.sh invalid "$test_root/raw.xml" 2>&1)"
invalid_status=$?
set -e
[[ "$invalid_status" -eq 2 && "$invalid_output" == *usage:* ]] || {
  echo '[ci] JUNIT_SANITIZER_LANE_GUARD_FAILED' >&2
  exit 1
}
log "counter-only JUnit sanitizer and hostile refusal matrix passed"
