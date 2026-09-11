#!/usr/bin/env bash
# Source from the dispatcher and its direct children. This is a local build
# diagnostic; continuous source/tool/dependency custody belongs to the wrapper.
# No caller-provided helper executable or expected digest is accepted.

jankurai_bootstrap_error() { printf '[ci] audit bootstrap: %s\n' "$*" >&2; return 1; }
jankurai_bootstrap_hash() { sha256sum -- "$1" | cut -d ' ' -f 1; }

jankurai_bootstrap_run() {
  local jk_run=$1 jk_parent=$2 jk_purpose=${3:-audit} jk_root jk_id jk_prefix jk_schema jk_origin jk_pattern
  jk_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P) || return
  jk_id=${jk_run##*/}
  case "$jk_purpose" in
    audit) jk_prefix=audit-runs; jk_pattern='^run\.[A-Za-z0-9]{8}$'; jk_schema=bullet.audit-invocation.v1; jk_origin=dispatcher ;;
    check) jk_prefix=checker-runs; jk_pattern='^check\.[A-Za-z0-9]{8}$'; jk_schema=bullet.audit-check-invocation.v1; jk_origin=artifact-check ;;
    *) jankurai_bootstrap_error 'unsupported purpose'; return 1 ;;
  esac
  [[ $jk_id =~ $jk_pattern && $jk_run == "$jk_root/target/jankurai/$jk_prefix/$jk_id" ]] ||
    { jankurai_bootstrap_error 'unexpected invocation path'; return 1; }
  [[ -d $jk_run && ! -L $jk_run && $(realpath -e -- "$jk_run") == "$jk_run" &&
     $(stat -c '%a:%u' -- "$jk_run") == "700:$EUID" &&
     -f $jk_run/invocation.json && ! -L $jk_run/invocation.json &&
     $(stat -c '%a:%u' -- "$jk_run/invocation.json") == "600:$EUID" ]] ||
    { jankurai_bootstrap_error 'unowned or nonprivate invocation'; return 1; }
  jq -e --arg root "$jk_root" --arg id "$jk_id" --argjson parent "$jk_parent" \
    --arg schema "$jk_schema" --arg origin "$jk_origin" '
    keys == ["id","origin","parent_pid","repository","schema"] and
    .schema == $schema and .id == $id and
    .repository == $root and .origin == $origin and .parent_pid == $parent
  ' "$jk_run/invocation.json" >/dev/null ||
    { jankurai_bootstrap_error 'foreign invocation'; return 1; }
  printf '%s\n' "$jk_root"
}

# Explicit compiled workspace source roots. Cargo registry/build-script/config
# dependencies are additional proof inputs, not certified by this snapshot.
jankurai_bootstrap_sources() (
  set -euo pipefail
  cd -- "$1" || exit 1
  local jk_path jk_file jk_list jk_special jk_size jk_total=0 jk_bytes=0
  local -a jk_paths=(Cargo.toml Cargo.lock rust-toolchain.toml ops/ci/jankurai-bootstrap.sh)
  for jk_path in bullet-git-types bullet-git-journal bullet-git-workspace bullet-gitd; do
    jk_paths+=("crates/$jk_path/Cargo.toml" "crates/$jk_path/src")
  done
  jk_paths+=(contracts/generated/rust)
  if [[ -e .cargo || -L .cargo ]]; then
    jk_paths+=(.cargo); printf 'PRESENT .cargo\0'
  else
    printf 'ABSENT .cargo\0'
  fi
  # find never follows a source symlink; reject special files rather than hash
  # their destinations or block on a FIFO. Ending checks do not detect restoration.
  for jk_path in "${jk_paths[@]}"; do
    [[ -e $jk_path && ! -L $jk_path && $(realpath -e -- "$jk_path") == "$PWD/$jk_path" ]] || exit 1
  done
  jk_special=$(find "${jk_paths[@]}" ! -type f ! -type d -print -quit) || exit 1
  [[ -z $jk_special ]] || exit 1
  jk_list=$(mktemp) || exit 1
  trap 'rm -f -- "$jk_list"' EXIT
  find "${jk_paths[@]}" -type f -print0 | LC_ALL=C sort -z > "$jk_list" || exit 1
  while IFS= read -r -d '' jk_file; do
    jk_size=$(stat -c %s -- "$jk_file") || exit 1
    [[ $jk_size =~ ^[0-9]{1,9}$ ]] && ((jk_size <= 67108864)) || exit 1
    jk_total=$((jk_total + 1)); jk_bytes=$((jk_bytes + jk_size))
    ((jk_total <= 4096 && jk_bytes <= 67108864)) || exit 1
    sha256sum -z -- "$jk_file" || exit 1
  done < "$jk_list"
  ((jk_total > 0))
)

jankurai_bootstrap_artifact() {
  local jk_root=$1 jk_dir=$2
  [[ -f $jk_dir/cargo.stdout && ! -L $jk_dir/cargo.stdout &&
     $(stat -c %s -- "$jk_dir/cargo.stdout") -le 33554432 ]] || return 1
  jq -es --arg src "$jk_root/crates/bullet-git-workspace/src/bin/bullet-ci-jankurai/main.rs" \
    --arg exe "$jk_dir/target/debug/bullet-ci-jankurai" '
    ([.[] | select(.reason == "compiler-artifact" and .target.name == "bullet-ci-jankurai")] | length) == 1 and
    ([.[] | select(.reason == "compiler-artifact" and .target.name == "bullet-ci-jankurai")][0] |
      .target.src_path == $src and .target.kind == ["bin"] and .profile.test == false and
      .fresh == false and .executable == $exe) and
    ([.[] | select(.reason == "build-finished")] == [{"reason":"build-finished","success":true}])
  ' "$jk_dir/cargo.stdout" >/dev/null
}

jankurai_bootstrap_subjects() (
  set -euo pipefail
  cd -- "$1" || exit 1
  local jk_file
  # Exact inventory: a supplied checksum file cannot add, omit or redirect reads.
  local -a jk_files=(invocation.json source.before.sha256z source.after.sha256z tools.sha256
    sysroot.stdout sysroot.stderr cargo.version cargo.version.stderr rustc.version rustc.version.stderr
    cargo.argv cargo.environment.json cargo.stdout cargo.stderr cargo.exit artifact.json
    tools.readback.stdout tools.readback.stderr)
  for jk_file in "${jk_files[@]}"; do
    [[ -f $jk_file && ! -L $jk_file && $(stat -c %u -- "$jk_file") == "$EUID" &&
       $(stat -c %s -- "$jk_file") -le 33554432 ]] || exit 1
  done
  sha256sum -- "${jk_files[@]}"
)

jankurai_bootstrap_tools() (
  set -euo pipefail
  local jk_sysroot jk_tool
  jk_sysroot=$(cat -- "$1/sysroot.stdout") || exit 1
  [[ $jk_sysroot == /* && $(realpath -e -- "$jk_sysroot") == "$jk_sysroot" ]] || exit 1
  for jk_tool in cargo rustc; do
    [[ -f $jk_sysroot/bin/$jk_tool && ! -L $jk_sysroot/bin/$jk_tool && -x $jk_sysroot/bin/$jk_tool ]] || exit 1
  done
  sha256sum -- "$jk_sysroot/bin/cargo" "$jk_sysroot/bin/rustc"
)

jankurai_bootstrap_finish() (
  local jk_dir=$1 jk_status=$2 jk_cargo_status=$3 jk_file jk_failed=0
  [[ -z $jk_cargo_status || $jk_cargo_status == 0 ]] || jk_status=$jk_cargo_status
  # GNU sync with explicit operands fsyncs these objects; -f would syncfs the
  # entire shared filesystem. The failed build must not depend on its own binary.
  local -a jk_files=(invocation.json source.before.sha256z source.after.sha256z tools.sha256
    sysroot.stdout sysroot.stderr cargo.version cargo.version.stderr rustc.version rustc.version.stderr
    cargo.argv cargo.environment.json cargo.stdout cargo.stderr cargo.exit artifact.json
    tools.readback.stdout tools.readback.stderr subjects.sha256 target/debug/bullet-ci-jankurai)
  for jk_file in "${jk_files[@]}"; do
    if [[ -e $jk_dir/$jk_file || -L $jk_dir/$jk_file ]]; then
      if [[ ! -f $jk_dir/$jk_file || -L $jk_dir/$jk_file ]]; then jk_failed=1
      elif ! sync -- "$jk_dir/$jk_file"; then jk_failed=1; fi
    fi
  done
  for jk_file in "$jk_dir/target/debug" "$jk_dir/target" "$jk_dir" "${jk_dir%/*}"; do
    if [[ -e $jk_file || -L $jk_file ]]; then
      if [[ ! -d $jk_file || -L $jk_file ]]; then jk_failed=1
      elif ! sync -- "$jk_file"; then jk_failed=1; fi
    fi
  done
  ((jk_status != 0 || jk_failed == 0)) || jk_status=1
  if ! (set -o noclobber; printf '%s\n' "$jk_status" > "$jk_dir/bootstrap.exit"); then
    ((jk_status != 0)) || jk_status=1
  elif ! sync -- "$jk_dir/bootstrap.exit" "$jk_dir"; then
    ((jk_status != 0)) || jk_status=1
  fi
  if ((jk_status != 0)); then
    printf '[ci] audit bootstrap failed (%s); retained %s\n' "$jk_status" "$jk_dir" >&2
  fi
  return "$jk_status"
)

jankurai_bootstrap_prepare() (
  set -euo pipefail
  umask 077
  local jk_run=$1 jk_purpose=${2:-audit} jk_root jk_dir jk_status=1 jk_cargo_status='' jk_sysroot jk_tool jk_home
  jk_root=$(jankurai_bootstrap_run "$jk_run" "$$" "$jk_purpose") || exit 1
  jk_dir="$jk_root/target/jankurai/bootstrap/${jk_run##*/}"
  mkdir -p -- "$jk_root/target/jankurai/bootstrap" || exit 1
  [[ $(realpath -e -- "$jk_root/target/jankurai/bootstrap") == "$jk_root/target/jankurai/bootstrap" ]] || exit 1
  # Explicit refusal is necessary even when a caller tests this function with if.
  mkdir -m 700 -- "$jk_dir" || exit 1 # exclusive: never resume an earlier build
  # Always retain the primary build failure without depending on the new binary.
  trap 'jk_status=$?; trap - EXIT; jankurai_bootstrap_finish "$jk_dir" "$jk_status" "$jk_cargo_status"; exit "$?"' EXIT
  cp -- "$jk_run/invocation.json" "$jk_dir/invocation.json" || exit 1
  jankurai_bootstrap_sources "$jk_root" > "$jk_dir/source.before.sha256z" || exit 1
  # Resolve the checked-in Rust toolchain, then use its direct binaries. Refuse
  # wrapper/target overrides instead of silently building another invocation.
  for jk_tool in RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_TARGET; do
    [[ -z ${!jk_tool-} ]] || { jankurai_bootstrap_error "unsupported $jk_tool"; exit 1; }
  done
  rustc --print sysroot > "$jk_dir/sysroot.stdout" 2> "$jk_dir/sysroot.stderr" || exit "$?"
  jk_sysroot=$(cat -- "$jk_dir/sysroot.stdout") || exit 1
  [[ $jk_sysroot == /* && $(realpath -e -- "$jk_sysroot") == "$jk_sysroot" ]] || exit 1
  for jk_tool in cargo rustc; do
    [[ -f $jk_sysroot/bin/$jk_tool && ! -L $jk_sysroot/bin/$jk_tool && -x $jk_sysroot/bin/$jk_tool ]] || exit 1
    "$jk_sysroot/bin/$jk_tool" --version > "$jk_dir/$jk_tool.version" 2> "$jk_dir/$jk_tool.version.stderr" || exit "$?"
    [[ $(cat -- "$jk_dir/$jk_tool.version") == "$jk_tool 1.97.1 "* ]] || exit 1
    sha256sum -- "$jk_sysroot/bin/$jk_tool" >> "$jk_dir/tools.sha256" || exit 1
  done
  jk_home=${CARGO_HOME:-${HOME:?}/.cargo}
  [[ $jk_home == /* && -d $jk_home ]] || exit 1
  local -a jk_argv=("$jk_sysroot/bin/cargo" build --frozen --manifest-path "$jk_root/Cargo.toml"
    --package bullet-git-workspace --bin bullet-ci-jankurai --message-format=json
    --target-dir "$jk_dir/target" --jobs 2)
  printf '%s\0' "${jk_argv[@]}" > "$jk_dir/cargo.argv" || exit 1
  jq -n --arg home "$HOME" --arg cargo_home "$jk_home" --arg path "$jk_sysroot/bin:/usr/bin:/bin" \
    --arg rustc "$jk_sysroot/bin/rustc" '{HOME:$home,CARGO_HOME:$cargo_home,PATH:$path,RUSTC:$rustc,
      CARGO_NET_OFFLINE:"true",CARGO_INCREMENTAL:"0",LANG:"C",LC_ALL:"C",TZ:"UTC0"}' > "$jk_dir/cargo.environment.json" || exit 1
  cd -- "$jk_root" || exit 1
  set +e
  env -i HOME="$HOME" CARGO_HOME="$jk_home" PATH="$jk_sysroot/bin:/usr/bin:/bin" RUSTC="$jk_sysroot/bin/rustc" \
    CARGO_NET_OFFLINE=true CARGO_INCREMENTAL=0 LANG=C LC_ALL=C TZ=UTC0 \
    "${jk_argv[@]}" > "$jk_dir/cargo.stdout" 2> "$jk_dir/cargo.stderr"
  jk_cargo_status=$?
  set -e
  printf '%s\n' "$jk_cargo_status" > "$jk_dir/cargo.exit" || exit 1
  ((jk_cargo_status == 0)) || exit "$jk_cargo_status"
  jankurai_bootstrap_artifact "$jk_root" "$jk_dir" || exit 1
  local jk_binary="$jk_dir/target/debug/bullet-ci-jankurai"
  [[ -f $jk_binary && ! -L $jk_binary && -x $jk_binary && $(realpath -e -- "$jk_binary") == "$jk_binary" ]] || exit 1
  jankurai_bootstrap_sources "$jk_root" > "$jk_dir/source.after.sha256z" || exit 1
  cmp -- "$jk_dir/source.before.sha256z" "$jk_dir/source.after.sha256z" || exit 1
  sha256sum -c -- "$jk_dir/tools.sha256" > "$jk_dir/tools.readback.stdout" 2> "$jk_dir/tools.readback.stderr" || exit 1
  local jk_hash
  jk_hash=$(jankurai_bootstrap_hash "$jk_binary") || exit 1
  jq -n --arg run "$jk_run" --arg purpose "$jk_purpose" --arg executable "$jk_binary" --arg sha256 "$jk_hash" \
    '{schema:"bullet.audit-bootstrap.v1",run:$run,purpose:$purpose,executable:$executable,sha256:$sha256,
      evidence_class:"local_diagnostic",continuous_custody:false}' > "$jk_dir/artifact.json" || exit 1
  jankurai_bootstrap_subjects "$jk_dir" > "$jk_dir/subjects.sha256" || exit 1
)

jankurai_bootstrap_resolve() (
  set -euo pipefail
  local jk_run=$1 jk_purpose=${2:-audit} jk_parent=$PPID jk_root jk_dir jk_binary jk_scratch jk_file jk_hash
  # Live capture is a direct dispatcher child. A historical checker owns its
  # separate build in this process; it cannot reinterpret the old audit's parent.
  [[ $jk_purpose != check ]] || jk_parent=$$
  jk_root=$(jankurai_bootstrap_run "$jk_run" "$jk_parent" "$jk_purpose") || exit 1
  jk_dir="$jk_root/target/jankurai/bootstrap/${jk_run##*/}"
  [[ -d $jk_dir && ! -L $jk_dir && $(realpath -e -- "$jk_dir") == "$jk_dir" &&
     $(stat -c '%a:%u' -- "$jk_dir") == "700:$EUID" ]] || exit 1
  for jk_file in bootstrap.exit cargo.exit subjects.sha256; do
    [[ -f $jk_dir/$jk_file && ! -L $jk_dir/$jk_file && $(stat -c %u -- "$jk_dir/$jk_file") == "$EUID" ]] || exit 1
  done
  [[ $(cat -- "$jk_dir/bootstrap.exit") == 0 && $(cat -- "$jk_dir/cargo.exit") == 0 ]] || exit 1
  # The final fsync itself can fail after the internal exit file was written.
  # Require the dispatcher's independently retained child status as well.
  [[ -f $jk_run/bootstrap.exit && ! -L $jk_run/bootstrap.exit &&
     $(cat -- "$jk_run/bootstrap.exit") == 0 ]] || exit 1
  jk_scratch=$(mktemp -d) || exit 1
  trap 'rm -rf -- "$jk_scratch"' EXIT
  jankurai_bootstrap_subjects "$jk_dir" > "$jk_scratch/subjects.sha256" || exit 1
  cmp -- "$jk_dir/subjects.sha256" "$jk_scratch/subjects.sha256" || exit 1
  cmp -- "$jk_run/invocation.json" "$jk_dir/invocation.json" || exit 1
  jankurai_bootstrap_tools "$jk_dir" > "$jk_scratch/tools.sha256" || exit 1
  cmp -- "$jk_dir/tools.sha256" "$jk_scratch/tools.sha256" || exit 1
  jankurai_bootstrap_artifact "$jk_root" "$jk_dir" || exit 1
  jk_binary="$jk_dir/target/debug/bullet-ci-jankurai"
  [[ -f $jk_binary && ! -L $jk_binary && -x $jk_binary && $(realpath -e -- "$jk_binary") == "$jk_binary" ]] || exit 1
  jk_hash=$(jankurai_bootstrap_hash "$jk_binary") || exit 1
  jq -e --arg run "$jk_run" --arg purpose "$jk_purpose" --arg exe "$jk_binary" --arg hash "$jk_hash" '
    keys == ["continuous_custody","evidence_class","executable","purpose","run","schema","sha256"] and
    .schema == "bullet.audit-bootstrap.v1" and .run == $run and .purpose == $purpose and .executable == $exe and
    .sha256 == $hash and .evidence_class == "local_diagnostic" and .continuous_custody == false
  ' "$jk_dir/artifact.json" >/dev/null || exit 1
  jankurai_bootstrap_sources "$jk_root" > "$jk_scratch/source.sha256z" || exit 1
  cmp -- "$jk_dir/source.before.sha256z" "$jk_scratch/source.sha256z" || exit 1
  printf '%s\n' "$jk_binary"
)

# Historical checking gets a fresh build without invoking the native auditor or
# changing the saved audit observation. This is the same bootstrap implementation.
jankurai_bootstrap_check_prepare() (
  set -euo pipefail
  umask 077
  local jk_root jk_run jk_dir jk_status=0
  jk_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P) || exit 1
  for jk_dir in "$jk_root/target" "$jk_root/target/jankurai" "$jk_root/target/jankurai/checker-runs"; do
    [[ ! -L $jk_dir && ( ! -e $jk_dir || -d $jk_dir ) ]] || exit 1
  done
  mkdir -p -- "$jk_root/target/jankurai/checker-runs" || exit 1
  jk_run=$(mktemp -d "$jk_root/target/jankurai/checker-runs/check.XXXXXXXX") || exit 1
  jq -n --arg root "$jk_root" --arg id "${jk_run##*/}" --argjson parent "$$" '
    {schema:"bullet.audit-check-invocation.v1",id:$id,repository:$root,origin:"artifact-check",parent_pid:$parent}
  ' > "$jk_run/invocation.json" || exit 1
  printf '%s\0' jankurai_bootstrap_prepare "$jk_run" check > "$jk_run/bootstrap.argv" || exit 1
  jankurai_bootstrap_prepare "$jk_run" check > "$jk_run/bootstrap.stdout" 2> "$jk_run/bootstrap.stderr" || jk_status=$?
  if ! (set -o noclobber; printf '%s\n' "$jk_status" > "$jk_run/bootstrap.exit"); then
    ((jk_status != 0)) || jk_status=1
  fi
  if ! sync -- "$jk_run/invocation.json" "$jk_run/bootstrap.argv" "$jk_run/bootstrap.stdout" \
    "$jk_run/bootstrap.stderr" "$jk_run/bootstrap.exit" "$jk_run" "${jk_run%/*}"; then
    ((jk_status != 0)) || jk_status=1
  fi
  printf '[ci] fresh checker build retained: %s (status %s)\n' "$jk_run" "$jk_status" >&2
  ((jk_status == 0)) || exit "$jk_status"
  printf '%s\n' "$jk_run"
)
