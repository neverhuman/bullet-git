#!/usr/bin/env bash
# Filesystem/selection negatives only. Positive qualification builds real Cargo
# output through the canonical audit dispatcher; fixtures cannot grant it.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
source ops/ci/jankurai-bootstrap.sh
jk_fixture=$(mktemp -d)
trap 'printf "[ci] bootstrap component originals retained: %s\n" "$jk_fixture" >&2' EXIT
jk_failures=0
jk_check() {
  local name=$1; shift
  if "$@"; then printf 'PASS %s\n' "$name"; else printf 'FAIL %s\n' "$name" >&2; jk_failures=$((jk_failures + 1)); fi
}
jk_refusal=0
jk_refuse() {
  jk_refusal=$((jk_refusal + 1))
  if "$@" > "$jk_fixture/refusal.$jk_refusal.stdout" 2> "$jk_fixture/refusal.$jk_refusal.stderr"; then return 1; fi
}
jk_check unexpected_run_path jk_refuse jankurai_bootstrap_run "$jk_fixture/run.abcdefgh" "$$"

jk_test_root="$jk_fixture/source with spaces"
jk_test_dir="$jk_fixture/build"
mkdir -p -- "$jk_test_root" "$jk_test_dir"
jk_artifact() {
  jq -cn --arg src "$jk_test_root/crates/bullet-git-workspace/src/bin/bullet-ci-jankurai/main.rs" \
    --arg exe "$jk_test_dir/target/debug/bullet-ci-jankurai" \
    '{reason:"compiler-artifact",target:{name:"bullet-ci-jankurai",src_path:$src,kind:["bin"]},profile:{test:false},fresh:false,executable:$exe}'
}
{ jk_artifact; printf '%s\n' '{"reason":"build-finished","success":true}'; } > "$jk_test_dir/cargo.stdout"
jk_check exact_cargo_selection jankurai_bootstrap_artifact "$jk_test_root" "$jk_test_dir"
cp -- "$jk_test_dir/cargo.stdout" "$jk_fixture/original.jsonl"
jk_artifact >> "$jk_test_dir/cargo.stdout"
jk_check duplicate_artifact jk_refuse jankurai_bootstrap_artifact "$jk_test_root" "$jk_test_dir"
jq -c 'if .reason == "compiler-artifact" then .executable="/tmp/foreign" else . end' "$jk_fixture/original.jsonl" > "$jk_test_dir/cargo.stdout"
jk_check foreign_executable jk_refuse jankurai_bootstrap_artifact "$jk_test_root" "$jk_test_dir"
jq -c 'if .reason == "compiler-artifact" then .profile.test=true else . end' "$jk_fixture/original.jsonl" > "$jk_test_dir/cargo.stdout"
jk_check test_binary_refused jk_refuse jankurai_bootstrap_artifact "$jk_test_root" "$jk_test_dir"
jq -c 'if .reason == "compiler-artifact" then .fresh=true else . end' "$jk_fixture/original.jsonl" > "$jk_test_dir/cargo.stdout"
jk_check reused_artifact_refused jk_refuse jankurai_bootstrap_artifact "$jk_test_root" "$jk_test_dir"
jq -c 'if .reason == "build-finished" then .success=false else . end' "$jk_fixture/original.jsonl" > "$jk_test_dir/cargo.stdout"
jk_check failed_build_refused jk_refuse jankurai_bootstrap_artifact "$jk_test_root" "$jk_test_dir"
printf '%s\n' '{"reason":"build-finished","success":true}' > "$jk_test_dir/cargo.stdout"
jk_check no_artifact_refused jk_refuse jankurai_bootstrap_artifact "$jk_test_root" "$jk_test_dir"
printf '%s\n' '{broken' > "$jk_test_dir/cargo.stdout"
jk_check malformed_cargo_stream jk_refuse jankurai_bootstrap_artifact "$jk_test_root" "$jk_test_dir"

mkdir -p "$jk_test_root/ops/ci" "$jk_test_root/contracts/generated/rust"
for path in Cargo.toml Cargo.lock rust-toolchain.toml ops/ci/jankurai-bootstrap.sh contracts/generated/rust/bundle.rs; do
  printf 'fixture %s\n' "$path" > "$jk_test_root/$path"
done
for package in bullet-git-types bullet-git-journal bullet-git-workspace bullet-gitd; do
  mkdir -p "$jk_test_root/crates/$package/src"
  printf '%s\n' fixture > "$jk_test_root/crates/$package/Cargo.toml"
  printf '%s\n' fixture > "$jk_test_root/crates/$package/src/lib.rs"
done
jankurai_bootstrap_sources "$jk_test_root" > "$jk_fixture/source.before"
printf '%s\n' changed >> "$jk_test_root/crates/bullet-git-workspace/src/lib.rs"
jankurai_bootstrap_sources "$jk_test_root" > "$jk_fixture/source.after"
jk_check changed_source_detected jk_refuse cmp "$jk_fixture/source.before" "$jk_fixture/source.after"
ln -s lib.rs "$jk_test_root/crates/bullet-git-workspace/src/alias.rs"
jk_check source_symlink_refused jk_refuse jankurai_bootstrap_sources "$jk_test_root"
rm "$jk_test_root/crates/bullet-git-workspace/src/alias.rs"
mkfifo "$jk_test_root/crates/bullet-git-workspace/src/input.rs"
jk_check source_fifo_refused jk_refuse jankurai_bootstrap_sources "$jk_test_root"
rm "$jk_test_root/crates/bullet-git-workspace/src/input.rs"
cp -- ops/ci/jankurai-bootstrap.sh "$jk_test_root/ops/ci/jankurai-bootstrap.sh"
source "$jk_test_root/ops/ci/jankurai-bootstrap.sh"
# Guard this light suite against accidentally reaching a real compiler. The
# marker has its own observed shell-only control; real Cargo acceptance is separate.
mkdir "$jk_fixture/bin"
cat > "$jk_fixture/bin/rustc" <<'SH'
#!/bin/sh
printf 'compiler child reached\n' > "$BULLET_BOOTSTRAP_TEST_MARKER"
exit 97
SH
chmod 700 "$jk_fixture/bin/rustc"
export BULLET_BOOTSTRAP_TEST_MARKER="$jk_fixture/compiler-start.marker"
export PATH="$jk_fixture/bin:$PATH"
jk_check marker_control_refusal jk_refuse rustc --print sysroot
[[ -s $BULLET_BOOTSTRAP_TEST_MARKER ]]
mv "$BULLET_BOOTSTRAP_TEST_MARKER" "$jk_fixture/compiler-start.control"

jk_test_run="$jk_test_root/target/jankurai/audit-runs/run.abcdefgh"
mkdir -p -- "$jk_test_run"
chmod 700 "$jk_test_run"
jq -n --arg root "$jk_test_root" --argjson parent "$$" '{schema:"bullet.audit-invocation.v1",id:"run.abcdefgh",
  repository:$root,origin:"dispatcher",parent_pid:$parent}' > "$jk_test_run/invocation.json"
chmod 600 "$jk_test_run/invocation.json"
jk_check actual_owned_invocation jankurai_bootstrap_run "$jk_test_run" "$$"
jk_check foreign_parent_refused jk_refuse jankurai_bootstrap_run "$jk_test_run" 1
chmod 755 "$jk_test_run"
jk_check public_run_refused jk_refuse jankurai_bootstrap_run "$jk_test_run" "$$"
chmod 700 "$jk_test_run"
# shellcheck disable=SC2016 # This literal script is evaluated only in the child.
jk_check foreign_shell_parent_refused jk_refuse env RUSTC_WRAPPER=/bin/true bash -c \
  'source "$1"; jankurai_bootstrap_prepare "$2"' _ "$jk_test_root/ops/ci/jankurai-bootstrap.sh" "$jk_test_run"
# The separate shell has its own identity and must refuse before creating a
# build. Exercise the real prepare finalizer in this invocation as well.
export RUSTC_WRAPPER=/bin/true
jk_check prepare_failure_retained jk_refuse jankurai_bootstrap_prepare "$jk_test_run"
[[ $(cat "$jk_fixture/refusal.$jk_refusal.stderr") == *"unsupported RUSTC_WRAPPER"* ]]
unset RUSTC_WRAPPER
[[ $(cat "$jk_test_root/target/jankurai/bootstrap/run.abcdefgh/bootstrap.exit") == 1 ]]
[[ ! -e $jk_test_root/target/jankurai/bootstrap/run.abcdefgh/cargo.stdout ]]
cp "$jk_test_root/target/jankurai/bootstrap/run.abcdefgh/bootstrap.exit" "$jk_fixture/first-bootstrap.exit"
jk_check repeated_prepare_refused jk_refuse jankurai_bootstrap_prepare "$jk_test_run"
[[ ! -e $BULLET_BOOTSTRAP_TEST_MARKER ]]
[[ ! -e $jk_test_root/target/jankurai/bootstrap/run.abcdefgh/cargo.stdout ]]
cmp "$jk_fixture/first-bootstrap.exit" "$jk_test_root/target/jankurai/bootstrap/run.abcdefgh/bootstrap.exit"

# A command that prints a plausible size but exits nonzero must still refuse,
# including when the public source function is called inside a conditional.
cat > "$jk_fixture/bin/stat" <<'SH'
#!/bin/sh
if [ "$1" = -c ] && [ "$2" = %s ]; then
  printf 'numeric stat failure\n' >> "$BULLET_BOOTSTRAP_STAT_MARKER"
  printf '123\n'
  exit 64
fi
exec /usr/bin/stat "$@"
SH
chmod 700 "$jk_fixture/bin/stat"
export BULLET_BOOTSTRAP_STAT_MARKER="$jk_fixture/stat.marker"
jk_check nonzero_numeric_stat_refused jk_refuse jankurai_bootstrap_sources "$jk_test_root"
[[ -s $BULLET_BOOTSTRAP_STAT_MARKER ]]
mv "$jk_fixture/bin/stat" "$jk_fixture/stat.fixture"

cat > "$jk_fixture/bin/sync" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >> "$BULLET_BOOTSTRAP_SYNC_MARKER"
exit 61
SH
chmod 700 "$jk_fixture/bin/sync"
export BULLET_BOOTSTRAP_SYNC_MARKER="$jk_fixture/sync.marker"
mkdir "$jk_fixture/final-success" "$jk_fixture/final-native-failure"
printf 'original cargo failure\n' > "$jk_fixture/final-native-failure/cargo.stderr"
jk_check finalizer_failure_refused jk_refuse jankurai_bootstrap_finish "$jk_fixture/final-success" 0 0
[[ $(cat "$jk_fixture/final-success/bootstrap.exit") == 1 ]]
jk_status=0
jankurai_bootstrap_finish "$jk_fixture/final-native-failure" 1 23 \
  > "$jk_fixture/finalizer.stdout" 2> "$jk_fixture/finalizer.stderr" || jk_status=$?
[[ $jk_status == 23 && $(cat "$jk_fixture/final-native-failure/bootstrap.exit") == 23 ]]
[[ $(cat "$jk_fixture/final-native-failure/cargo.stderr") == 'original cargo failure' ]]
[[ -s $BULLET_BOOTSTRAP_SYNC_MARKER && $(cat "$BULLET_BOOTSTRAP_SYNC_MARKER") != *'-f '* ]]
printf 'PASS native_failure_survives_finalizer_failure\n'
[[ ! -e $BULLET_BOOTSTRAP_TEST_MARKER ]]
mv "$jk_fixture/bin/sync" "$jk_fixture/sync.fixture"
jk_checker="$jk_test_root/target/jankurai/checker-runs/check.abcdefgh"
mkdir -p "$jk_checker"
chmod 700 "$jk_checker"
jq -n --arg root "$jk_test_root" --argjson parent "$$" '{schema:"bullet.audit-check-invocation.v1",id:"check.abcdefgh",
  repository:$root,origin:"artifact-check",parent_pid:$parent}' > "$jk_checker/invocation.json"
chmod 600 "$jk_checker/invocation.json"
jk_check separate_checker_invocation jankurai_bootstrap_run "$jk_checker" "$$" check
jk_check checker_cannot_be_live_audit jk_refuse jankurai_bootstrap_run "$jk_checker" "$$" audit
jk_check audit_cannot_be_checker jk_refuse jankurai_bootstrap_run "$jk_test_run" "$$" check
jk_check unknown_purpose_refused jk_refuse jankurai_bootstrap_run "$jk_checker" "$$" unknown
export RUSTC_WRAPPER=/bin/true
jk_check fresh_checker_prepare_failure jk_refuse jankurai_bootstrap_check_prepare
unset RUSTC_WRAPPER
jk_created_count=0
for jk_created in "$jk_test_root"/target/jankurai/checker-runs/check.*; do
  [[ $jk_created != "$jk_checker" ]] || continue
  jk_created_count=$((jk_created_count + 1))
  [[ $(cat "$jk_created/bootstrap.exit") == 1 ]]
  [[ $(cat "$jk_created/bootstrap.stderr") == *'unsupported RUSTC_WRAPPER'* ]]
done
[[ $jk_created_count == 1 ]]
[[ ! -e $BULLET_BOOTSTRAP_TEST_MARKER ]]
((jk_failures == 0))
printf '[ci] bootstrap selection/filesystem components passed; actual build pending\n'
