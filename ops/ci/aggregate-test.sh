#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
test_root="$(mktemp -d)"
cleanup() { rm -rf -- "$test_root"; }
trap cleanup EXIT
expected_commit="$(git rev-parse HEAD)"
expected_tree="$(git rev-parse 'HEAD^{tree}')"
lanes=(source-scan fast lint contract security docs)
green=(success success success success success success)

lane_script() {
  case "$1" in
    source-scan) printf '%s\n' ops/ci/source-scan.sh ;;
    fast) printf '%s\n' ops/ci/fast.sh ;;
    lint) printf '%s\n' ops/ci/lint.sh ;;
    contract) printf '%s\n' ops/ci/contract.sh ;;
    security) printf '%s\n' ops/ci/security.sh ;;
    docs) printf '%s\n' ops/ci/docs.sh ;;
  esac
}

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

make_fixtures() {
  local lane relative path digest artifacts doctor_command lane_command
  rm -rf -- "$test_root"
  mkdir -p "$test_root/observations" "$test_root/reports"
  printf '%s\n' '<?xml version="1.0" encoding="UTF-8"?>' \
    '<testsuites tests="1" failures="0" errors="0" skipped="0">' \
    '  <testsuite name="bullet-git-fast" tests="1" failures="0" errors="0" skipped="0"/>' \
    '</testsuites>' >"$test_root/reports/fast.junit.xml"
  sed 's/bullet-git-fast/bullet-git-contract/' "$test_root/reports/fast.junit.xml" \
    >"$test_root/reports/contract.junit.xml"
  for lane in "${lanes[@]}"; do
    artifacts='[]'
    case "$lane" in
      fast|contract)
        relative=".ci-artifacts/reports/$lane.junit.xml"
        path="$test_root/${relative#.ci-artifacts/}"
        digest="$(hash_file "$path")"
        artifacts="$(jq -cn --arg path "$relative" --arg sha256 "$digest" \
          '[{path:$path,sha256:$sha256}]')"
        ;;
    esac
    doctor_command="bash scripts/ci-doctor.sh $lane"
    lane_command="bash $(lane_script "$lane")"
    jq -n --arg lane "$lane" --arg commit "$expected_commit" --arg tree "$expected_tree" \
      --arg doctor "$doctor_command" --arg command "$lane_command" --argjson artifacts "$artifacts" '
      {schema_version:"bullet.ci-observation.v1",repository:"bullet-git",commit_oid:$commit,
       tree_oid:$tree,clean:true,
       commands:[$doctor,$command],tool_versions:{},
       outcomes:[{lane:$lane,status:"PASS",exit_code:0}],artifact_hashes:$artifacts,
       signed:false,evidence_class:"DIAGNOSTIC_ONLY"}' >"$test_root/observations/$lane.json"
  done
}

expect_failure() {
  local reason="$1" output status
  shift
  set +e
  output="$(bash ops/ci/aggregate.sh "$@" 2>&1)"
  status=$?
  set -e
  [[ "$status" -eq 1 && "$output" == *"$reason"* ]] || {
    printf '[ci] aggregator did not refuse with %s (status=%s, output=%s)\n' "$reason" "$status" "$output" >&2
    exit 1
  }
}

make_fixtures
bash ops/ci/aggregate.sh "$test_root" "$expected_commit" "${green[@]}" >/dev/null
for bad in failure skipped cancelled ''; do
  candidate=("${green[@]}")
  candidate[1]="$bad"
  expect_failure CI_JOB_NOT_SUCCESSFUL "$test_root" "$expected_commit" "${candidate[@]}"
done
expect_failure CI_JOB_MISSING "$test_root" "$expected_commit" "${green[@]:0:5}"

make_fixtures; rm "$test_root/observations/lint.json"
expect_failure CI_OBSERVATION_MISSING "$test_root" "$expected_commit" "${green[@]}"
make_fixtures; jq '.repository="other"' "$test_root/observations/docs.json" >"$test_root/x"; mv "$test_root/x" "$test_root/observations/docs.json"
expect_failure CI_OBSERVATION_INVALID "$test_root" "$expected_commit" "${green[@]}"
make_fixtures; jq '.outcomes[0].lane="fast"' "$test_root/observations/docs.json" >"$test_root/x"; mv "$test_root/x" "$test_root/observations/docs.json"
expect_failure CI_OBSERVATION_INVALID "$test_root" "$expected_commit" "${green[@]}"
make_fixtures; jq '.commit_oid="2222222222222222222222222222222222222222"' "$test_root/observations/security.json" >"$test_root/x"; mv "$test_root/x" "$test_root/observations/security.json"
expect_failure CI_OBSERVATION_INVALID "$test_root" "$expected_commit" "${green[@]}"
make_fixtures; jq '.clean=false' "$test_root/observations/source-scan.json" >"$test_root/x"; mv "$test_root/x" "$test_root/observations/source-scan.json"
expect_failure CI_OBSERVATION_INVALID "$test_root" "$expected_commit" "${green[@]}"
make_fixtures; jq '.commands=["true","true"]' "$test_root/observations/lint.json" >"$test_root/x"; mv "$test_root/x" "$test_root/observations/lint.json"
expect_failure CI_OBSERVATION_INVALID "$test_root" "$expected_commit" "${green[@]}"
make_fixtures; jq '.outcomes[0]={lane:"contract",status:"FAIL",exit_code:1}' "$test_root/observations/contract.json" >"$test_root/x"; mv "$test_root/x" "$test_root/observations/contract.json"
expect_failure CI_OBSERVATION_INVALID "$test_root" "$expected_commit" "${green[@]}"
make_fixtures; jq '.artifact_hashes += [.artifact_hashes[0]]' "$test_root/observations/fast.json" >"$test_root/x"; mv "$test_root/x" "$test_root/observations/fast.json"
expect_failure CI_OBSERVATION_INVALID "$test_root" "$expected_commit" "${green[@]}"
make_fixtures; jq '.artifact_hashes[0].path=".ci-artifacts/../escape"' "$test_root/observations/fast.json" >"$test_root/x"; mv "$test_root/x" "$test_root/observations/fast.json"
expect_failure CI_OBSERVATION_INVALID "$test_root" "$expected_commit" "${green[@]}"
make_fixtures; rm "$test_root/reports/contract.junit.xml"
expect_failure CI_ARTIFACT_INVALID "$test_root" "$expected_commit" "${green[@]}"
make_fixtures; printf 'tampered\n' >>"$test_root/reports/fast.junit.xml"
expect_failure ARTIFACT_HASH_MISMATCH "$test_root" "$expected_commit" "${green[@]}"
make_fixtures; printf 'extra\n' >"$test_root/unexpected.txt"
expect_failure CI_ARTIFACT_TREE_INVALID "$test_root" "$expected_commit" "${green[@]}"
make_fixtures; rm "$test_root/reports/fast.junit.xml"; ln -s /dev/null "$test_root/reports/fast.junit.xml"
expect_failure CI_ARTIFACT_INVALID "$test_root" "$expected_commit" "${green[@]}"
log "aggregator rejects every non-exact predecessor, observation, and artifact"
