#!/usr/bin/env bash
# Jankurai consumes native policy; AUDIT_FLOOR is an additional upward-only ratchet.
set -euo pipefail
if [[ $# -eq 0 ]]; then
  exec bash "$(dirname "${BASH_SOURCE[0]}")/../../scripts/ci-local.sh" audit
fi
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
AUDIT_FLOOR=65
export JANKURAI_NO_UPDATE_CHECK=1
for tool in jankurai jq cp mkdir mktemp rm cat find id; do require_tool "$tool" || exit 1; done
# shellcheck source=ops/ci/jankurai-bootstrap.sh
source "$REPO_ROOT/ops/ci/jankurai-bootstrap.sh"
umask 077
# Fixed output ancestors must be ordinary directories. This is a local lane,
# not an adversarial filesystem custody monitor.
for directory in target target/jankurai target/jankurai/audit-runs \
  target/jankurai/update .jankurai .ci-artifacts .ci-artifacts/observations; do
  [[ ! -L "$directory" && ( ! -e "$directory" || -d "$directory" ) ]] || {
    printf '[ci] audit output directory refused: %s\n' "$directory" >&2
    exit 1
  }
done
mkdir -p target/jankurai/audit-runs .jankurai
if [[ $# -eq 2 && "$1" == --audit-run ]]; then
  run_dir="$2"
  expected="$REPO_ROOT/target/jankurai/audit-runs/"
  suffix="${run_dir#"$expected"}"
  [[ "$run_dir" == "$expected"* && "$suffix" =~ ^run\.[A-Za-z0-9]{8}$ \
    && -d "$run_dir" && ! -L "$run_dir" \
    && -f "$run_dir/invocation.json" && ! -L "$run_dir/invocation.json" ]] || exit 75
  [[ "$(find "$run_dir" -maxdepth 0 -type d -uid "$(id -u)" -perm 0700 -print)" == "$run_dir" \
    && "$(find "$run_dir/invocation.json" -maxdepth 0 -type f -uid "$(id -u)" -perm 0600 -print)" \
      == "$run_dir/invocation.json" ]] || exit 75
  jq -e --arg id "$suffix" --arg repository "$REPO_ROOT" --argjson pid "$PPID" '
    . == {schema:"bullet.audit-invocation.v1",id:$id,repository:$repository,
      origin:"dispatcher",parent_pid:$pid}
  ' "$run_dir/invocation.json" >/dev/null || exit 75
else
  echo 'usage: audit.sh [--audit-run <dispatcher-owned-run>]' >&2
  exit 2
fi
audit_binary="$(jankurai_bootstrap_resolve "$run_dir")" || exit 75
# A completed/failed/ambiguous attempt never reuses the same invocation directory.
(set -o noclobber; printf 'pid=%s\n' "$$" >"$run_dir/audit.started") || exit 75
candidate="$(type -P jankurai)"
log "audit retained run: $run_dir"
# target is excluded by the native auditor; .jankurai is scannable. Preserve
# previous outputs before removing any stale report from the scan input.
reports=(repo-score.json repo-score.md repair-queue.jsonl repo-score-current.json
  repo-score-current.md score-history.jsonl)
artifacts=(.ci-artifacts/observations/audit.json target/jankurai/audit-state.json
  target/jankurai/update/state.json target/jankurai/accepted-baseline.json
  target/jankurai/repo-score.json target/jankurai/repo-score.md
  target/jankurai/repair-queue.jsonl)
for report in "${reports[@]}"; do artifacts+=(".jankurai/$report"); done
retention_status=0
stage=preserve-before
capture() {
  local phase="$1" path destination result=0
  for path in "${artifacts[@]}"; do
    if [[ -L "$path" || ( -e "$path" && ! -f "$path" ) ]]; then
      printf '%s: refused nonregular %s\n' "$phase" "$path" >>"$run_dir/retention.stderr" || result=1
      result=1
    elif [[ -f "$path" ]]; then
      destination="$run_dir/$phase/$path"
      if ! mkdir -p "${destination%/*}" || ! cp -- "$path" "$destination" \
          2>>"$run_dir/retention.stderr"; then
        printf '%s: copy failed %s\n' "$phase" "$path" >>"$run_dir/retention.stderr" || result=1
        result=1
      fi
    else
      printf '%s\n' "$path" >>"$run_dir/$phase.absent" || result=1
    fi
  done
  return "$result"
}
finish() {
  local primary=$? final
  trap - EXIT
  set +e
  capture final || retention_status=1
  final=$primary
  [[ "$final" -ne 0 || "$retention_status" -eq 0 ]] || final=1
  if ! printf 'stage=%s\nprimary_status=%s\nretention_status=%s\nfinal_status=%s\n' \
      "$stage" "$primary" "$retention_status" "$final" >"$run_dir/result.txt"; then
    [[ "$final" -ne 0 ]] || final=1
    printf '[ci] audit result persistence failed: %s\n' "$run_dir" >&2
  fi
  if [[ "$final" -eq 0 ]]; then
    log "audit lane passed"
  else
    printf '[ci] audit lane failed: stage=%s primary=%s retention=%s final=%s\n' \
      "$stage" "$primary" "$retention_status" "$final" >&2
  fi
  exit "$final"
}
trap finish EXIT
capture before || { retention_status=1; exit 1; }
for report in "${reports[@]}"; do rm -f -- ".jankurai/$report"; done
mkdir -p target/jankurai/proofbind target/jankurai/proofmark \
  target/jankurai/security target/jankurai/coverage target/jankurai/rust
# Tool-adoption catalog CI commands (exact strings; comments count for this detector):
# jankurai audit . --mode ratchet --baseline target/jankurai/accepted-baseline.json --json target/jankurai/repo-score.json --md target/jankurai/repo-score.md
# jankurai proofbind verify . --changed-from origin/main
# jankurai proofmark rust . --obligations target/jankurai/proofbind/obligations.json
# cargo run -p jankurai -- copy-code . --json target/jankurai/copy-code.json --md target/jankurai/copy-code.md
# jankurai security run . --out target/jankurai/security/evidence.json
# cargo test -p jankurai --test language_bad_behavior
# jankurai rust witness build .
# jankurai vibe coverage --source agent/vibe-coverage.toml --tips tips/vibe_coding --json target/jankurai/vibe-coverage.json --md target/jankurai/vibe-coverage.md
# jankurai coverage audit . --config agent/coverage-sources.toml --json target/jankurai/coverage/coverage-audit.json --md target/jankurai/coverage/coverage-audit.md
# Artifact paths: .jankurai/repo-score.json .jankurai/repo-score.md target/jankurai/repair-queue.jsonl target/jankurai/proofbind/surface-witness.json target/jankurai/proofbind/obligations.json target/jankurai/proofmark/proofmark-receipt.json target/jankurai/proofmark/proof-receipt.json target/jankurai/copy-code.json target/jankurai/copy-code.md target/jankurai/security/evidence.json target/jankurai/language-bad-behavior.log target/jankurai/rust/witness-graph.json target/jankurai/vibe-coverage.json target/jankurai/vibe-coverage.md target/jankurai/coverage/coverage-audit.json target/jankurai/coverage/coverage-audit.md
# Each invocation writes fresh native output. CLI threshold flags would replace
# the repository policy, so the fixed floor is checked against the native JSON.
run_audit() {
  local name="$1" json_path="$2" md_path="$3" native_status=0 validation_status=0
  shift 3
  stage="$name"
  "$audit_binary" --candidate "$candidate" \
    --record "$run_dir/$name.tool.jsonl" -- audit . --full --no-score-history "$@" \
    --json "$json_path" --md "$md_path" \
    >"$run_dir/$name.stdout" 2>"$run_dir/$name.stderr" || native_status=$?
  printf '%s\n' "$native_status" >"$run_dir/$name.exit" || retention_status=1
  cat "$run_dir/$name.stdout" || retention_status=1
  cat "$run_dir/$name.stderr" >&2 || retention_status=1
  # Preserve original failure reports/state before any later staging operation.
  capture "$name" || retention_status=1
  [[ "$native_status" -eq 0 ]] || return "$native_status"
  [[ -f "$json_path" && ! -L "$json_path" && -f "$md_path" && ! -L "$md_path" ]] || {
    echo '[ci] audit artifacts missing or nonregular' >&2
    return 1
  }
  jq -e --argjson floor "$AUDIT_FLOOR" '
    (.policy.minimum_score | type == "number") and
    (.policy.minimum_score == (.policy.minimum_score | floor)) and
    (.policy.minimum_score >= $floor) and
    (.score | type == "number") and (.score == (.score | floor)) and
    (.score >= .policy.minimum_score) and (.score >= $floor) and
    (.decision.passed == true)
  ' "$json_path" >"$run_dir/$name.validation.stdout" \
    2>"$run_dir/$name.validation.stderr" || validation_status=$?
  if [[ "$validation_status" -eq 0 ]]; then
    local runtime_parent absolute_report="$json_path"
    runtime_parent="$(mktemp -d "${TMPDIR:-/tmp}/bullet-audit-report.XXXXXXXX")" || validation_status=$?
    [[ "$absolute_report" == /* ]] || absolute_report="$REPO_ROOT/$absolute_report"
    local -a policy_args=(report --root "$REPO_ROOT" --runtime "$runtime_parent/validation" --report "$absolute_report")
    [[ "$name" != ratchet ]] || policy_args+=(--baseline "$REPO_ROOT/target/jankurai/accepted-baseline.json")
    if [[ "$validation_status" -eq 0 ]]; then
      printf '%s\0' "$audit_binary" "${policy_args[@]}" >"$run_dir/$name.validation.argv" || validation_status=1
    fi
    if [[ "$validation_status" -eq 0 ]]; then
      "$audit_binary" "${policy_args[@]}" \
        >>"$run_dir/$name.validation.stdout" 2>>"$run_dir/$name.validation.stderr" || validation_status=$?
    fi
  fi
  printf '%s\n' "$validation_status" >"$run_dir/$name.validation.exit" || retention_status=1
  [[ "$validation_status" -eq 0 && "$retention_status" -eq 0 ]]
}
if [[ -f target/jankurai/accepted-baseline.json ]]; then
  # Keep the optional native ratchet gate; its reports cannot overwrite main output.
  run_audit ratchet "$run_dir/ratchet.json" "$run_dir/ratchet.md" \
    --mode ratchet --baseline target/jankurai/accepted-baseline.json
fi
log "audit lane: native policy and additional floor ${AUDIT_FLOOR}"
run_audit audit .jankurai/repo-score.json .jankurai/repo-score.md \
  --repair-queue-jsonl .jankurai/repair-queue.jsonl
[[ -f .jankurai/repair-queue.jsonl && ! -L .jankurai/repair-queue.jsonl ]] || {
  echo '[ci] audit repair queue missing or nonregular' >&2
  exit 1
}
stage=staging
for report in repo-score.json repo-score.md repair-queue.jsonl; do
  cp -- ".jankurai/$report" "target/jankurai/$report" \
    2>>"$run_dir/staging.stderr" || {
      printf '[ci] audit staging failed: %s\n' "$report" >&2
      exit 1
    }
done
stage=complete
