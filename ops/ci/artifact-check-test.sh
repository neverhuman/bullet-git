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

# Exercise the actual stage/checker scripts without writing canonical diagnostics.
# The fixture only reads this immutable commit through the checker; its artifacts
# and upload tree are private, and no Git command mutates the shared directory.
make_fixture
fixture="$test_root/staging"
mkdir -p "$fixture/ops/ci" "$fixture/.ci-artifacts/observations" "$test_root/outside"
cp ops/ci/lib.sh ops/ci/artifact-check.sh ops/ci/stage-artifacts.sh "$fixture/ops/ci/"
ln -s "$REPO_ROOT/.git" "$fixture/.git"
input="$fixture/.ci-artifacts/observations/source-scan.json"
jq '.commands=["bash scripts/ci-doctor.sh source-scan","bash ops/ci/source-scan.sh"] |
  .outcomes=[{lane:"source-scan",status:"PASS",exit_code:0}] | .artifact_hashes=[]' \
  "$test_root/observations/fast.json" >"$input"
cp "$input" "$test_root/source-scan.json"
stage="$fixture/target/ci-upload/source-scan"

stage_refuses() {
  local reason="$1" output
  if output="$(bash "$fixture/ops/ci/stage-artifacts.sh" source-scan "$commit" 2>&1)"; then
    echo '[ci] INVALID_STAGE_ACCEPTED' >&2
    exit 1
  fi
  [[ "$output" == *"$reason"* ]] || {
    printf '[ci] stage did not refuse %s: %s\n' "$reason" "$output" >&2
    exit 1
  }
}

bash "$fixture/ops/ci/stage-artifacts.sh" source-scan "$commit" >/dev/null
for path in "$fixture/target/ci-upload" "$stage" "$stage/observations"; do
  [[ "$(find "$path" -maxdepth 0 -type d -perm 0700 -print)" == "$path" ]]
done
[[ "$(find "$stage/observations/source-scan.json" -maxdepth 0 -type f -perm 0600 -print)" \
  == "$stage/observations/source-scan.json" ]]
cmp "$input" "$stage/observations/source-scan.json"
cmp "$input" "$test_root/source-scan.json"
printf 'stale\n' >"$stage/stale.log"
bash "$fixture/ops/ci/stage-artifacts.sh" source-scan "$commit" >/dev/null
[[ ! -e "$stage/stale.log" ]]
cmp "$input" "$stage/observations/source-scan.json"

jq '.clean=false' "$test_root/source-scan.json" >"$input"
stage_refuses CI_OBSERVATION_INVALID
cmp "$test_root/source-scan.json" "$stage/observations/source-scan.json"
rm "$input"
ln -s "$test_root/source-scan.json" "$input"
stage_refuses CI_OBSERVATION_INVALID
cmp "$test_root/source-scan.json" "$stage/observations/source-scan.json"
rm "$input"
cp "$test_root/source-scan.json" "$input"
printf 'retain-outside\n' >"$test_root/outside/marker"
for relative in target target/ci-upload target/ci-upload/source-scan; do
  rm -rf -- "$fixture/target"
  mkdir -p "$(dirname "$fixture/$relative")"
  ln -s "$test_root/outside" "$fixture/$relative"
  stage_refuses CI_STAGE_ROOT_INVALID
  [[ -L "$fixture/$relative" && "$(cat "$test_root/outside/marker")" == retain-outside ]]
done
rm -rf -- "$fixture/target" "$fixture/.ci-artifacts"
mkdir "$fixture/.ci-artifacts"
cp -R "$test_root/observations" "$test_root/reports" "$fixture/.ci-artifacts/"
bash "$fixture/ops/ci/stage-artifacts.sh" fast "$commit" >/dev/null
cmp "$test_root/observations/fast.json" "$fixture/target/ci-upload/fast/observations/fast.json"
cmp "$test_root/reports/fast.junit.xml" "$fixture/target/ci-upload/fast/reports/fast.junit.xml"
log "actual staging exact bytes, private modes, retry, and refusal preservation passed"
log "artifact checker exact-subject, hash, tree, and sanitizer guards passed"
