#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT
commit="$(git rev-parse HEAD)"
tree="$(git rev-parse 'HEAD^{tree}')"

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

make_fixture() {
  rm -rf -- "$test_root"
  mkdir -p "$test_root/observations" "$test_root/reports"
  printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' \
    '<testsuites tests="2" failures="0" errors="0" skipped="0">' \
    '  <testsuite name="bullet-git-fast" tests="2" failures="0" errors="0" skipped="0"/>' \
    '</testsuites>' >"$test_root/reports/fast.junit.xml"
  digest="$(hash_file "$test_root/reports/fast.junit.xml")"
  jq -n --arg commit "$commit" --arg tree "$tree" --arg digest "$digest" '
    {schema_version:"bullet.ci-observation.v1",repository:"bullet-git",commit_oid:$commit,
     tree_oid:$tree,clean:true,
     commands:["doctor","lane"],tool_versions:{},
     outcomes:[{lane:"fast",status:"PASS",exit_code:0}],
     artifact_hashes:[{path:".ci-artifacts/reports/fast.junit.xml",sha256:$digest}],
     signed:false,evidence_class:"DIAGNOSTIC_ONLY"}' >"$test_root/observations/fast.json"
}

expect_failure() {
  local reason="$1" output status
  set +e
  output="$(bash ops/ci/artifact-check.sh fast "$commit" "$test_root" 2>&1)"
  status=$?
  set -e
  [[ "$status" -eq 1 && "$output" == *"$reason"* ]] || {
    printf '[ci] artifact checker did not refuse %s (status=%s output=%s)\n' "$reason" "$status" "$output" >&2
    exit 1
  }
}

make_fixture
bash ops/ci/artifact-check.sh fast "$commit" "$test_root" >/dev/null
make_fixture; jq '.clean=false' "$test_root/observations/fast.json" >"$test_root/x"; mv "$test_root/x" "$test_root/observations/fast.json"
expect_failure CI_OBSERVATION_INVALID
make_fixture; jq '.outcomes[0].exit_code=7' "$test_root/observations/fast.json" >"$test_root/x"; mv "$test_root/x" "$test_root/observations/fast.json"
expect_failure CI_OBSERVATION_INVALID
make_fixture; printf 'tamper\n' >>"$test_root/reports/fast.junit.xml"
expect_failure ARTIFACT_HASH_MISMATCH
make_fixture; printf '<system-out>secret</system-out>\n' >>"$test_root/reports/fast.junit.xml"; digest="$(hash_file "$test_root/reports/fast.junit.xml")"; jq --arg digest "$digest" '.artifact_hashes[0].sha256=$digest' "$test_root/observations/fast.json" >"$test_root/x"; mv "$test_root/x" "$test_root/observations/fast.json"
expect_failure SANITIZED_JUNIT_INVALID
make_fixture; printf 'extra\n' >"$test_root/raw.log"
expect_failure CI_ARTIFACT_TREE_INVALID
make_fixture; rm "$test_root/reports/fast.junit.xml"; ln -s /dev/null "$test_root/reports/fast.junit.xml"
expect_failure CI_ARTIFACT_INVALID
log "artifact checker exact-subject, hash, tree, and sanitizer guards passed"
