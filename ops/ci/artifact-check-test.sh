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

if grep -Eq '(^|[[:space:]])(mapfile|readarray)([[:space:]]|$)' ops/ci/artifact-check.sh; then
  echo '[ci] ARTIFACT_CHECK_BASH3_INCOMPATIBLE' >&2
  exit 1
fi

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
     commands:["bash scripts/ci-doctor.sh fast","bash ops/ci/fast.sh"],tool_versions:{},
     outcomes:[{lane:"fast",status:"PASS",exit_code:0}],
     artifact_hashes:[{path:".ci-artifacts/reports/fast.junit.xml",sha256:$digest}],
     signed:false,evidence_class:"DIAGNOSTIC_ONLY"}' >"$test_root/observations/fast.json"
}

scheduled_lane_script() {
  case "$1" in
    history) printf '%s\n' ops/ci/history.sh ;;
    links) printf '%s\n' ops/ci/external-links.sh ;;
    advisory) printf '%s\n' ops/ci/advisory.sh ;;
    coverage) printf '%s\n' ops/ci/coverage.sh ;;
    platform) printf '%s\n' ops/ci/platform-refusal.sh ;;
  esac
}

make_scheduled_fixture() {
  local lane="$1" script artifacts='[]' digest
  rm -rf -- "$test_root"
  mkdir -p "$test_root/observations" "$test_root/reports"
  script="$(scheduled_lane_script "$lane")"
  if [[ "$lane" == coverage ]]; then
    printf '%s\n' 'TN:' 'SF:crates/bullet-git-types/src/lib.rs' 'DA:1,1' 'end_of_record' \
      >"$test_root/reports/coverage.lcov"
    digest="$(hash_file "$test_root/reports/coverage.lcov")"
    artifacts="$(jq -cn --arg digest "$digest" \
      '[{path:".ci-artifacts/reports/coverage.lcov",sha256:$digest}]')"
  fi
  jq -n --arg lane "$lane" --arg commit "$commit" --arg tree "$tree" \
    --arg doctor "bash scripts/ci-doctor.sh $lane" --arg command "bash $script" \
    --argjson artifacts "$artifacts" '
    {schema_version:"bullet.ci-observation.v1",repository:"bullet-git",commit_oid:$commit,
     tree_oid:$tree,clean:true,commands:[$doctor,$command],tool_versions:{},
     outcomes:[{lane:$lane,status:"PASS",exit_code:0}],artifact_hashes:$artifacts,
     signed:false,evidence_class:"DIAGNOSTIC_ONLY"}' >"$test_root/observations/$lane.json"
}

expect_failure() {
  local reason="$1" lane="${2:-fast}" output status
  set +e
  output="$(bash ops/ci/artifact-check.sh "$lane" "$commit" "$test_root" 2>&1)"
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
make_fixture; jq '.commands=["true","true"]' "$test_root/observations/fast.json" >"$test_root/x"; mv "$test_root/x" "$test_root/observations/fast.json"
expect_failure CI_OBSERVATION_INVALID
make_fixture; jq '.commands |= reverse' "$test_root/observations/fast.json" >"$test_root/x"; mv "$test_root/x" "$test_root/observations/fast.json"
expect_failure CI_OBSERVATION_INVALID
make_fixture; jq '.commands += ["true"]' "$test_root/observations/fast.json" >"$test_root/x"; mv "$test_root/x" "$test_root/observations/fast.json"
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
for lane in history links advisory coverage platform; do
  make_scheduled_fixture "$lane"
  bash ops/ci/artifact-check.sh "$lane" "$commit" "$test_root" >/dev/null
done
make_scheduled_fixture coverage
jq '.artifact_hashes=[]' "$test_root/observations/coverage.json" >"$test_root/x"
mv "$test_root/x" "$test_root/observations/coverage.json"
expect_failure CI_ARTIFACT_INVENTORY_INVALID coverage
log "artifact checker exact-subject, hash, tree, and sanitizer guards passed"
