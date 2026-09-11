#!/usr/bin/env bash
# Shell component evidence only: fake native output does not qualify Jankurai policy.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
fixture="$(mktemp -d "${TMPDIR:-/tmp}/bulletgit-audit-component.XXXXXXXX")"
printf '[ci] audit component evidence retained: %s\n' "$fixture"
mkdir -p "$fixture/bin"
export CI_AUDIT_REAL_CP
CI_AUDIT_REAL_CP="$(command -v cp)"
cat >"$fixture/bin/jankurai" <<'NATIVE'
#!/usr/bin/env bash
set -euo pipefail
printf 'started\n' >>"$CI_AUDIT_CASE/starts"
printf '%s\n' "$@" >>"$CI_AUDIT_CASE/argv"
[[ "$JANKURAI_NO_UPDATE_CHECK" == 1 ]]
[[ "$1" == audit && "$2" == . && "$3" == --full && "$4" == --no-score-history ]]
shift 4
json= md= queue= mode=standard
while [[ $# -gt 0 ]]; do
  case "$1" in
    --json) json="$2" ;;
    --md) md="$2" ;;
    --repair-queue-jsonl) queue="$2" ;;
    --mode) mode="$2" ;;
    --baseline) [[ "$2" == target/jankurai/accepted-baseline.json ]] ;;
    *) printf 'unexpected native override: %s\n' "$1" >&2; exit 97 ;;
  esac
  shift 2
done
printf 'mode=%s\n' "$mode" >>"$CI_AUDIT_CASE/modes"
for name in repo-score.json repo-score.md repair-queue.jsonl repo-score-current.json \
  repo-score-current.md score-history.jsonl; do
  [[ ! -e ".jankurai/$name" ]]
done
printf 'native stdout %s\n' "$mode"
printf 'native stderr %s\n' "$mode" >&2
printf 'fresh audit state\n' >target/jankurai/audit-state.json
if [[ "$CI_AUDIT_SCENARIO" != missing ]]; then
  if [[ "$mode" == ratchet ]]; then
    jq -c --slurpfile baseline target/jankurai/accepted-baseline.json '
      .policy.mode="ratchet" | .decision.ratchet={passed:true,allowed_drop:0,
        baseline_score:$baseline[0].score,score_delta:(.score-$baseline[0].score),
        new_caps:[],new_hard_findings:[],policy_changed:false,
        baseline_report_fingerprint:$baseline[0].report_fingerprint,
        baseline_input_fingerprint:$baseline[0].input_fingerprint,
        baseline_policy_fingerprint:$baseline[0].policy_fingerprint}
    ' <<<"$CI_AUDIT_JSON" >"$json"
  else
    printf '%s\n' "$CI_AUDIT_JSON" >"$json"
  fi
  printf 'native markdown %s\n' "$mode" >"$md"
  [[ -z "$queue" ]] || printf 'native repair\n' >"$queue"
fi
exit "${CI_AUDIT_NATIVE_STATUS:-0}"
NATIVE
cat >"$fixture/bin/cp" <<'COPY'
#!/usr/bin/env bash
set -euo pipefail
# Fail only the actual production copy selected by each scenario.
if [[ "${CI_AUDIT_SCENARIO:-}" == stage_fail && "$*" == *' target/jankurai/repo-score.json' ]]; then
  printf 'injected staging failure\n' >&2
  exit 42
fi
if [[ "${CI_AUDIT_SCENARIO:-}" == retain_fail && "$*" == *'/audit/.jankurai/repo-score.json' ]]; then
  printf 'injected preservation failure\n' >&2
  exit 49
fi
if [[ "${CI_AUDIT_SCENARIO:-}" == final_fail && "$*" == *'/final/.jankurai/repo-score.json' ]]; then
  printf 'injected final preservation failure\n' >&2
  exit 51
fi
exec "$CI_AUDIT_REAL_CP" "$@"
COPY
# This explicit fixture does not perform artifact admission. The real helper's
# independent ELF tests and later checksum-pinned auditor run establish that seam.
cat >"$fixture/helper.py" <<'HELPER'
import json
import importlib.util
import os
from pathlib import Path
import subprocess
import sys
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("original_helper", Path(__file__).with_name("jankurai-tool-source.py"))
original = importlib.util.module_from_spec(spec)
spec.loader.exec_module(original)
# The report consumer reuses actual nofollow reader primitives. Only the
# explicit fixture's command execution branch below replaces artifact admission.
globals().update({name: value for name, value in vars(original).items() if not name.startswith("__")})
if __name__ == "__main__":
    candidate, record = sys.argv[2], sys.argv[4]
    assert sys.argv[1] == "--candidate" and sys.argv[3] == "--record" and sys.argv[5] == "--"
    command = sys.argv[6:]
    assert Path(candidate).is_absolute() and Path(record).is_absolute()
    try:
        with open(record, "x") as output:
            json.dump({"fixture": True, "artifact_admission": False, "candidate": candidate, "argv": command}, output)
    except FileExistsError:
        sys.exit(75)
    if command == ["--version"]:
        with open(Path(os.environ["CI_AUDIT_CASE"]) / "version-starts", "a") as marker:
            marker.write("started\n")
        print("jankurai 1.6.11")
        sys.exit(0)
    sys.exit(subprocess.call([candidate, *command]))
HELPER
chmod +x "$fixture/bin/jankurai" "$fixture/bin/cp"
export CI_AUDIT_CASE CI_AUDIT_SCENARIO CI_AUDIT_JSON CI_AUDIT_NATIVE_STATUS
valid="$(python3 -I -S - <<'POLICY'
import hashlib, json, pathlib, tomllib
raw = pathlib.Path('agent/audit-policy.toml').read_bytes()
policy = tomllib.loads(raw.decode())
print(json.dumps(dict(policy={**{k:policy[k] for k in ('minimum_score','fail_on','advisory_on')},'mode':'standard'},
    score=90, decision=dict(passed=True,status='pass',minimum_score=policy['minimum_score'],hard_findings=0),
    findings=[],caps_applied=[],policy_fingerprint='sha256:'+hashlib.sha256(raw).hexdigest(),
    report_fingerprint='fixture-report',input_fingerprint='fixture-input',schema_version='fixture',standard_version='fixture'),separators=(',',':')))
POLICY
)"
case_count=0
new_case() {
  CI_AUDIT_CASE="$fixture/$1"
  mkdir -p "$CI_AUDIT_CASE/repo/ops/ci" "$CI_AUDIT_CASE/repo/scripts" "$CI_AUDIT_CASE/repo/.jankurai" "$CI_AUDIT_CASE/repo/agent" \
    "$CI_AUDIT_CASE/repo/.ci-artifacts/observations" "$CI_AUDIT_CASE/repo/target/jankurai/update"
  "$CI_AUDIT_REAL_CP" ops/ci/audit.sh ops/ci/lib.sh "$CI_AUDIT_CASE/repo/ops/ci/"
  "$CI_AUDIT_REAL_CP" "$fixture/helper.py" "$CI_AUDIT_CASE/repo/ops/ci/jankurai-tool.py"
  "$CI_AUDIT_REAL_CP" ops/ci/jankurai-tool.py "$CI_AUDIT_CASE/repo/ops/ci/jankurai-tool-source.py"
  "$CI_AUDIT_REAL_CP" ops/ci/audit-observation.py "$CI_AUDIT_CASE/repo/ops/ci/"
  "$CI_AUDIT_REAL_CP" agent/audit-policy.toml "$CI_AUDIT_CASE/repo/agent/"
  "$CI_AUDIT_REAL_CP" scripts/ci-doctor.sh "$CI_AUDIT_CASE/repo/scripts/"
  git -C "$CI_AUDIT_CASE/repo" init --quiet --template=
  git -C "$CI_AUDIT_CASE/repo" add agent/audit-policy.toml
  git -C "$CI_AUDIT_CASE/repo" -c core.hooksPath=/dev/null -c user.name=Component \
    -c user.email=component@example.invalid commit --quiet -m 'component policy input'
  CI_AUDIT_SCENARIO=normal CI_AUDIT_JSON="$valid" CI_AUDIT_NATIVE_STATUS=0
}
run_case() {
  local expected="$1" starts="$2" status=0
  shift 2
  PATH="$fixture/bin:$PATH" JANKURAI_NO_UPDATE_CHECK=0 \
    bash "$CI_AUDIT_CASE/repo/ops/ci/audit.sh" "$@" \
    >"$CI_AUDIT_CASE/stdout" 2>"$CI_AUDIT_CASE/stderr" || status=$?
  printf '%s\n' "$status" >"$CI_AUDIT_CASE/exit"
  for stream in stdout stderr exit; do
    "$CI_AUDIT_REAL_CP" "$CI_AUDIT_CASE/$stream" "$CI_AUDIT_CASE/invocation-$case_count.$stream"
  done
  [[ "$status" -eq "$expected" ]] || {
    printf '[ci] audit component %s: got %s expected %s\n' "$CI_AUDIT_CASE" "$status" "$expected" >&2
    exit 1
  }
  if [[ "$starts" -eq 0 ]]; then
    [[ ! -e "$CI_AUDIT_CASE/starts" ]]
  else
    [[ -f "$CI_AUDIT_CASE/starts" && "$(wc -l <"$CI_AUDIT_CASE/starts")" -eq "$starts" ]]
  fi
  if [[ "$status" -eq 0 ]]; then
    [[ "$(<"$CI_AUDIT_CASE/stdout")" == *'[ci] audit lane passed'* ]]
  else
    [[ "$(<"$CI_AUDIT_CASE/stdout")" != *'[ci] audit lane passed'* ]]
    [[ "$(<"$CI_AUDIT_CASE/stderr")" == *'[ci] audit lane failed:'* ]]
  fi
  case_count=$((case_count + 1))
  printf 'PASS %s\n' "${CI_AUDIT_CASE##*/}"
}
run_path() {
  local -a runs=("$CI_AUDIT_CASE/repo/target/jankurai/audit-runs"/run.*)
  [[ ${#runs[@]} -eq 1 && -d "${runs[0]}" ]]
  printf '%s\n' "${runs[0]}"
}
new_case success_preserves_previous
for file in .jankurai/repo-score.json .jankurai/repo-score.md .jankurai/repair-queue.jsonl \
  .jankurai/repo-score-current.json .jankurai/repo-score-current.md .jankurai/score-history.jsonl \
  .ci-artifacts/observations/audit.json target/jankurai/repo-score.json \
  target/jankurai/repo-score.md target/jankurai/repair-queue.jsonl \
  target/jankurai/audit-state.json target/jankurai/update/state.json; do
  printf 'previous %s\n' "$file" >"$CI_AUDIT_CASE/repo/$file"
done
run_case 0 1
retained="$(run_path)"
for file in .jankurai/repo-score.json .jankurai/repo-score.md .jankurai/repair-queue.jsonl \
  .jankurai/repo-score-current.json .jankurai/repo-score-current.md .jankurai/score-history.jsonl \
  .ci-artifacts/observations/audit.json target/jankurai/repo-score.json \
  target/jankurai/repo-score.md target/jankurai/repair-queue.jsonl \
  target/jankurai/audit-state.json target/jankurai/update/state.json; do
  [[ "$(<"$retained/before/$file")" == "previous $file" ]]
done
[[ "$(<"$retained/final/target/jankurai/audit-state.json")" == 'fresh audit state' ]]
[[ "$(<"$retained/final/target/jankurai/update/state.json")" == 'previous target/jankurai/update/state.json' ]]
# Repeating a run keeps the original run and creates a separate preserved subject.
run_case 0 2
runs=("$CI_AUDIT_CASE/repo/target/jankurai/audit-runs"/run.*)
[[ ${#runs[@]} -eq 2 && "$(<"$retained/before/.jankurai/repo-score.json")" == 'previous .jankurai/repo-score.json' ]]
for spec in 'below_native:84:85' 'below_fixed:64:64' 'weak_policy:90:64'; do
  IFS=: read -r name score minimum <<<"$spec"
  new_case "$name"
  CI_AUDIT_JSON="$(jq -cn --argjson s "$score" --argjson m "$minimum" \
    '{score:$s,policy:{minimum_score:$m},decision:{passed:true}}')"
  run_case 1 1
  [[ -f "$(run_path)/audit/.jankurai/repo-score.json" ]]
done
new_case lowered_report_policy
CI_AUDIT_JSON="$(jq -c '.policy.minimum_score=70 | .decision.minimum_score=70' <<<"$valid")"
run_case 1 1
[[ "$(<"$(run_path)/audit.validation.stderr")" == *'REPORT_POLICY_MISMATCH:minimum_score'* ]]
for name in missing malformed decision_failed string_score; do
  new_case "$name"
  case "$name" in
    missing) CI_AUDIT_SCENARIO=missing ;;
    malformed) CI_AUDIT_JSON='invalid json' ;;
    decision_failed) CI_AUDIT_JSON="$(jq '.decision.passed=false' <<<"$valid")" ;;
    string_score) CI_AUDIT_JSON="$(jq '.score="90"' <<<"$valid")" ;;
  esac
  run_case 1 1
done
new_case native_failure
CI_AUDIT_NATIVE_STATUS=23
run_case 23 1
retained="$(run_path)"
[[ "$(<"$retained/audit.exit")" == 23 ]]
[[ "$(<"$retained/audit.stdout")" == 'native stdout standard' ]]
[[ "$(<"$retained/audit.stderr")" == 'native stderr standard' ]]
[[ "$(<"$retained/audit/.jankurai/repo-score.json")" == "$valid" ]]
[[ ! -e "$CI_AUDIT_CASE/repo/target/jankurai/repo-score.json" ]]
for native in 0 23; do
  new_case "retention_failure_$native"
  CI_AUDIT_SCENARIO=retain_fail CI_AUDIT_NATIVE_STATUS="$native"
  expected="$native"; [[ "$expected" -ne 0 ]] || expected=1
  run_case "$expected" 1
  retained="$(run_path)"
  [[ "$(<"$retained/retention.stderr")" == *'injected preservation failure'* ]]
  [[ "$(<"$retained/result.txt")" == *'retention_status=1'* ]]
  [[ "$(<"$retained/final/.jankurai/repo-score.json")" == "$valid" ]]
done
for native in 0 23; do
  new_case "final_retention_failure_$native"
  CI_AUDIT_SCENARIO=final_fail CI_AUDIT_NATIVE_STATUS="$native"
  expected="$native"; [[ "$expected" -ne 0 ]] || expected=1
  run_case "$expected" 1
  retained="$(run_path)"
  [[ "$(<"$retained/result.txt")" == *"primary_status=$native"* ]]
  [[ "$(<"$retained/result.txt")" == *'retention_status=1'* ]]
  [[ "$(<"$retained/audit/.jankurai/repo-score.json")" == "$valid" ]]
done
new_case staging_failure
CI_AUDIT_SCENARIO=stage_fail
run_case 1 1
retained="$(run_path)"
[[ "$(<"$retained/staging.stderr")" == 'injected staging failure' ]]
[[ "$(<"$retained/audit.exit")" == 0 && "$(<"$retained/result.txt")" == *'stage=staging'* ]]
[[ "$(<"$retained/audit/.jankurai/repo-score.json")" == "$valid" ]]
for native in 0 23; do
  new_case "optional_ratchet_$native"
  baseline="$(jq -c '.score=89' <<<"$valid")"
  printf '%s\n' "$baseline" >"$CI_AUDIT_CASE/repo/target/jankurai/accepted-baseline.json"
  CI_AUDIT_NATIVE_STATUS="$native"
  starts=1; [[ "$native" -ne 0 ]] || starts=2
  run_case "$native" "$starts"
  retained="$(run_path)"
  [[ -f "$retained/ratchet.json" && "$(<"$retained/before/target/jankurai/accepted-baseline.json")" == "$baseline" ]]
  [[ "$(<"$retained/ratchet.exit")" == "$native" ]]
done
new_case symlink_report_refused
ln -s "$CI_AUDIT_CASE/foreign" "$CI_AUDIT_CASE/repo/.jankurai/repo-score.json"
printf 'foreign\n' >"$CI_AUDIT_CASE/foreign"
run_case 1 0
[[ "$(<"$CI_AUDIT_CASE/foreign")" == foreign ]]
# Parent identity and one-use relationships use actual doctor/audit scripts;
# the native helper is explicitly the component fixture above.
fresh_binding() {
  mkdir -p "$CI_AUDIT_CASE/repo/target/jankurai/audit-runs"
  bound="$(mktemp -d "$CI_AUDIT_CASE/repo/target/jankurai/audit-runs/run.XXXXXXXX")"
  (umask 077; jq -n --arg id "${bound##*/}" --arg repository "$CI_AUDIT_CASE/repo" --argjson pid "$1" \
    '{schema:"bullet.audit-invocation.v1",id:$id,repository:$repository,origin:"dispatcher",parent_pid:$pid}' \
    >"$bound/invocation.json")
}
new_case doctor_bound
fresh_binding "$$"
PATH="$fixture/bin:$PATH" bash "$CI_AUDIT_CASE/repo/scripts/ci-doctor.sh" audit --audit-run "$bound" \
  >"$CI_AUDIT_CASE/doctor.stdout" 2>"$CI_AUDIT_CASE/doctor.stderr"
jq -e '.fixture==true and .artifact_admission==false and .argv==["--version"]' "$bound/doctor.tool.jsonl" >/dev/null
status=0
PATH="$fixture/bin:$PATH" bash "$CI_AUDIT_CASE/repo/scripts/ci-doctor.sh" audit --audit-run "$bound" \
  >"$CI_AUDIT_CASE/replay.stdout" 2>"$CI_AUDIT_CASE/replay.stderr" || status=$?
[[ "$status" -eq 75 && "$(wc -l <"$CI_AUDIT_CASE/version-starts")" -eq 1 ]]
case_count=$((case_count + 2))
new_case doctor_foreign_parent
fresh_binding "$(( $$ + 1 ))"
status=0
PATH="$fixture/bin:$PATH" bash "$CI_AUDIT_CASE/repo/scripts/ci-doctor.sh" audit --audit-run "$bound" \
  >"$CI_AUDIT_CASE/doctor.stdout" 2>"$CI_AUDIT_CASE/doctor.stderr" || status=$?
[[ "$status" -eq 75 && ! -e "$bound/doctor.tool.jsonl" && ! -e "$CI_AUDIT_CASE/version-starts" ]]
case_count=$((case_count + 1))
new_case audit_bound
fresh_binding "$$"
run_case 0 1 --audit-run "$bound"
[[ -f "$bound/audit.started" && -f "$bound/audit.tool.jsonl" ]]
status=0
PATH="$fixture/bin:$PATH" bash "$CI_AUDIT_CASE/repo/ops/ci/audit.sh" --audit-run "$bound" \
  >"$CI_AUDIT_CASE/replay.stdout" 2>"$CI_AUDIT_CASE/replay.stderr" || status=$?
[[ "$status" -eq 75 && "$(wc -l <"$CI_AUDIT_CASE/starts")" -eq 1 ]]
case_count=$((case_count + 1))
new_case audit_foreign_parent
fresh_binding "$(( $$ + 1 ))"
status=0
PATH="$fixture/bin:$PATH" bash "$CI_AUDIT_CASE/repo/ops/ci/audit.sh" --audit-run "$bound" \
  >"$CI_AUDIT_CASE/stdout" 2>"$CI_AUDIT_CASE/stderr" || status=$?
[[ "$status" -eq 75 && ! -e "$bound/audit.started" && ! -e "$CI_AUDIT_CASE/starts" ]]
case_count=$((case_count + 1))
new_case actual_score_alias_refuses_unadmitted_candidate
"$CI_AUDIT_REAL_CP" Justfile "$CI_AUDIT_CASE/repo/"
"$CI_AUDIT_REAL_CP" scripts/ci-local.sh scripts/ci-observation.sh "$CI_AUDIT_CASE/repo/scripts/"
# This case uses the unchanged production admission helper, not helper.py.
"$CI_AUDIT_REAL_CP" ops/ci/jankurai-tool.py "$CI_AUDIT_CASE/repo/ops/ci/"
for name in repo-score.json repo-score.md repair-queue.jsonl; do
  printf 'historical %s\n' "$name" >"$CI_AUDIT_CASE/repo/.jankurai/$name"
done
status=0
PATH="$fixture/bin:$PATH" just --justfile "$CI_AUDIT_CASE/repo/Justfile" \
  --working-directory "$CI_AUDIT_CASE/repo" score >"$CI_AUDIT_CASE/score.stdout" \
  2>"$CI_AUDIT_CASE/score.stderr" || status=$?
printf '%s\n' "$status" >"$CI_AUDIT_CASE/score.exit"
[[ "$status" -eq 75 && ! -e "$CI_AUDIT_CASE/starts" && ! -e "$CI_AUDIT_CASE/version-starts" ]]
[[ "$(<"$CI_AUDIT_CASE/score.stderr")" == *'CANDIDATE_KIND_MODE_OR_SIZE_MISMATCH'* ]]
for name in repo-score.json repo-score.md repair-queue.jsonl; do
  [[ "$(<"$CI_AUDIT_CASE/repo/.jankurai/$name")" == "historical $name" ]]
done
retained="$(run_path)"
jq -e '.primary_status==75 and .outcome=="FAIL" and .tools.doctor.native_returncode==null' \
  "$retained/observation.json" >/dev/null
[[ ! -e "$CI_AUDIT_CASE/repo/.git/bullet-ci.lock.d" ]]
case_count=$((case_count + 1))
printf '[ci] audit shell components passed: %s (native semantics unqualified)\n' "$case_count"
