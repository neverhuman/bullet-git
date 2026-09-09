#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

test_root="$(mktemp -d)"
fixture="$test_root/repo"
outside="$test_root/outside"
owner_pid=
child_pid=
cleanup() {
  [[ -z "$owner_pid" ]] || kill -KILL "$owner_pid" 2>/dev/null || true
  [[ -z "$child_pid" ]] || kill -KILL "$child_pid" 2>/dev/null || true
  rm -rf -- "$test_root"
}
trap cleanup EXIT
mkdir -p "$fixture/.git" "$fixture/scripts" "$fixture/ops/ci" "$outside"
printf 'ref: refs/heads/main\n' >"$fixture/.git/HEAD"
cp scripts/ci-local.sh "$fixture/scripts/ci-local.sh"

cat >"$fixture/scripts/ci-doctor.sh" <<'FIXTURE'
#!/usr/bin/env bash
printf 'doctor:%s\n' "$$" >>children
printf '%s\n' "$1" >doctor-lane
[[ ${BULLET_CI_PROOF_CUSTODY+x} ]] && state=present || state=unset
printf '%s\n' "$state" >doctor-token-state
FIXTURE
cat >"$fixture/ops/ci/fast.sh" <<'FIXTURE'
#!/usr/bin/env bash
set -eu
printf 'fast:%s\n' "$$" >>children
if [[ ${BULLET_CI_PROOF_CUSTODY+x} ]]; then
  printf 'present\n' >token-state
else
  printf 'unset\n' >token-state
fi
: >child-started
if [[ "${CI_FIXTURE_NESTED:-0}" == 1 ]]; then
  set +e
  CI_FIXTURE_NESTED=0 bash scripts/ci-local.sh fast >nested-output 2>&1
  printf '%s\n' "$?" >nested-status
  set -e
fi
while [[ "${CI_FIXTURE_HOLD:-0}" == 1 && ! -e release-child ]]; do sleep 0.05; done
exit "${CI_FIXTURE_STATUS:-0}"
FIXTURE
cat >"$fixture/ops/ci/required.sh" <<'FIXTURE'
#!/usr/bin/env bash
set -eu
printf 'required:%s\n' "$$" >>children
printf 'required\n' >invoked-target
: >alias-child-started
while [[ "${CI_FIXTURE_HOLD:-0}" == 1 && ! -e release-alias-child ]]; do sleep 0.05; done
FIXTURE
cat >"$fixture/scripts/ci-observation.sh" <<'FIXTURE'
#!/usr/bin/env bash
set -eu
printf 'observation:%s\n' "$$" >>observation-calls
printf '%s\n' "$1" >observation-lane
[[ ${BULLET_CI_PROOF_CUSTODY+x} ]] && state=present || state=unset
printf '%s\n' "$state" >observation-token-state
mkdir -p .ci-artifacts/observations
printf 'status=%s\n' "$2" >".ci-artifacts/observations/$1.json"
FIXTURE
chmod +x "$fixture/scripts/"*.sh "$fixture/ops/ci/fast.sh" "$fixture/ops/ci/required.sh"

wait_for() {
  local path="$1"
  for _ in {1..200}; do
    [[ -e "$path" ]] && return 0
    sleep 0.05
  done
  printf '[ci] CI_PROOF_CUSTODY_TEST_TIMEOUT: %s\n' "$path" >&2
  return 1
}

line_count() {
  [[ -f "$1" ]] && wc -l <"$1" || printf '0\n'
}

assert_alias_custody() {
  local alias="$1" alias_record alias_pattern
  rm -f -- "$fixture/alias-child-started" "$fixture/release-alias-child" \
    "$fixture/invoked-target" "$fixture/doctor-lane" "$fixture/observation-lane" \
    "$fixture/.ci-artifacts/observations/$alias.json" \
    "$fixture/.ci-artifacts/observations/required.json"
  (
    cd "$fixture"
    exec env CI_FIXTURE_HOLD=1 bash scripts/ci-local.sh "$alias"
  ) >"$fixture/$alias-output" 2>&1 &
  owner_pid=$!
  wait_for "$fixture/alias-child-started"
  alias_record="$(<"$owner")"
  alias_pattern="^schema=2 repository=bullet-git scope=standalone pid=$owner_pid lane=$alias nonce=([0-9]+-[0-9]+-[0-9]+-[0-9]+)$"
  [[ "$alias_record" =~ $alias_pattern ]] \
    || { refuse CI_PROOF_ALIAS_OWNER_LANE_INVALID "$alias"; exit 1; }
  : >"$fixture/release-alias-child"
  wait "$owner_pid"
  owner_pid=
  [[ ! -e "$lock" && "$(<"$fixture/invoked-target")" == required \
    && "$(<"$fixture/doctor-lane")" == required \
    && "$(<"$fixture/observation-lane")" == required \
    && "$(<"$fixture/.ci-artifacts/observations/required.json")" == status=0 \
    && ! -e "$fixture/.ci-artifacts/observations/$alias.json" ]] \
    || { refuse CI_PROOF_ALIAS_RELEASE_INVALID "$alias"; exit 1; }
}

assert_parent_record_refused() {
  local record="$1" code="$2" extra_line="${3:-false}" output status before_children before_observations
  (umask 077; mkdir "$lock"; printf '%s\n' "$record" >"$owner")
  $extra_line && printf '\n' >>"$owner"
  before_children="$(line_count "$fixture/children")"
  before_observations="$(line_count "$fixture/observation-calls")"
  set +e
  output="$(BULLET_CI_PROOF_CUSTODY="$record" bash "$fixture/scripts/ci-local.sh" fast 2>&1)"
  status=$?
  set -e
  [[ "$status" -eq 75 && "$output" == *CI_PROOF_LOCKED_OR_STALE* \
    && "$(line_count "$fixture/children")" -eq "$before_children" \
    && "$(line_count "$fixture/observation-calls")" -eq "$before_observations" ]] \
    || { refuse "$code" bullet-git; exit 1; }
  rm -- "$owner"
  rmdir -- "$lock"
}

start_owner() {
  rm -f -- "$fixture/child-started" "$fixture/release-child" "$fixture/children"
  (
    cd "$fixture"
    umask 000
    exec env CI_FIXTURE_HOLD=1 bash scripts/ci-local.sh fast
  ) >"$fixture/owner-output" 2>&1 &
  owner_pid=$!
  wait_for "$fixture/child-started"
}

start_owner
lock="$fixture/.git/bullet-ci.lock.d"
owner="$lock/owner"
[[ -n "$(find "$lock" -maxdepth 0 -type d -perm 0700 -print)" \
  && -n "$(find "$owner" -maxdepth 0 -type f -perm 0600 -print)" ]] \
  || { refuse CI_PROOF_CUSTODY_MODE_INVALID "$lock"; exit 1; }
mkdir -p "$fixture/.ci-artifacts/reports" "$fixture/.ci-artifacts/observations"
printf 'preserve-report\n' >"$fixture/.ci-artifacts/reports/fast.junit.xml"
printf 'preserve-observation\n' >"$fixture/.ci-artifacts/observations/fast.json"
children_before="$(line_count "$fixture/children")"
set +e
overlap_output="$(cd "$fixture" && bash scripts/ci-local.sh fast 2>&1)"
overlap_status=$?
set -e
[[ "$overlap_status" -eq 75 && "$overlap_output" == *CI_PROOF_LOCKED_OR_STALE* \
  && "$(line_count "$fixture/children")" -eq "$children_before" \
  && "$(<"$fixture/.ci-artifacts/reports/fast.junit.xml")" == preserve-report \
  && "$(<"$fixture/.ci-artifacts/observations/fast.json")" == preserve-observation ]] \
  || { refuse CI_PROOF_OVERLAP_REFUSAL_INVALID bullet-git; exit 1; }
: >"$fixture/release-child"
wait "$owner_pid"
owner_pid=
[[ ! -e "$lock" && "$(<"$fixture/.ci-artifacts/observations/fast.json")" == status=0 ]] \
  || { refuse CI_PROOF_PASS_RELEASE_INVALID bullet-git; exit 1; }

set +e
(cd "$fixture" && CI_FIXTURE_STATUS=19 bash scripts/ci-local.sh fast >/dev/null 2>&1)
failure_status=$?
set -e
[[ "$failure_status" -eq 19 && ! -e "$lock" \
  && "$(<"$fixture/.ci-artifacts/observations/fast.json")" == status=19 ]] \
  || { refuse CI_PROOF_FAIL_RELEASE_INVALID bullet-git; exit 1; }

assert_alias_custody gates
assert_alias_custody all

start_owner
child_pid="$(awk -F: '$1 == "fast" { pid=$2 } END { print pid }' "$fixture/children")"
kill -KILL "$owner_pid"
set +e
wait "$owner_pid" 2>/dev/null
set -e
owner_pid=
kill -TERM "$child_pid" 2>/dev/null || true
for _ in {1..100}; do
  kill -0 "$child_pid" 2>/dev/null || break
  sleep 0.05
done
if kill -0 "$child_pid" 2>/dev/null; then
  kill -KILL "$child_pid" 2>/dev/null || true
  for _ in {1..100}; do
    kill -0 "$child_pid" 2>/dev/null || break
    sleep 0.05
  done
fi
kill -0 "$child_pid" 2>/dev/null \
  && { refuse CI_PROOF_CRASH_CHILD_SURVIVED "$child_pid"; exit 1; }
child_pid=
children_before="$(line_count "$fixture/children")"
observations_before="$(line_count "$fixture/observation-calls")"
set +e
stale_output="$(cd "$fixture" && bash scripts/ci-local.sh fast 2>&1)"
stale_status=$?
set -e
[[ "$stale_status" -eq 75 && "$stale_output" == *CI_PROOF_LOCKED_OR_STALE* \
  && "$(line_count "$fixture/children")" -eq "$children_before" \
  && "$(line_count "$fixture/observation-calls")" -eq "$observations_before" ]] \
  || { refuse CI_PROOF_CRASH_STALE_REFUSAL_INVALID bullet-git; exit 1; }
rm -- "$owner"
rmdir -- "$lock"

parent_record="schema=2 repository=bullet-git scope=family pid=$$ lane=family nonce=$$-12345-23456-34567"
(umask 077; mkdir "$lock"; printf '%s\n' "$parent_record" >"$owner")
rm -f -- "$fixture/children" "$fixture/nested-status" "$fixture/nested-output"
BULLET_CI_PROOF_CUSTODY="$parent_record" CI_FIXTURE_NESTED=1 \
  bash "$fixture/scripts/ci-local.sh" fast >/dev/null
[[ -d "$lock" && ! -L "$lock" && -f "$owner" && ! -L "$owner" \
  && "$(<"$owner")" == "$parent_record" && "$(<"$fixture/token-state")" == unset \
  && "$(<"$fixture/doctor-token-state")" == unset \
  && "$(<"$fixture/observation-token-state")" == unset \
  && "$(<"$fixture/nested-status")" -eq 75 \
  && "$(<"$fixture/nested-output")" == *CI_PROOF_LOCKED_OR_STALE* ]] \
  || { refuse CI_PROOF_INHERITED_CUSTODY_INVALID bullet-git; exit 1; }
rm -- "$owner"
rmdir -- "$lock"

children_before="$(line_count "$fixture/children")"
observations_before="$(line_count "$fixture/observation-calls")"
set +e
replay_output="$(BULLET_CI_PROOF_CUSTODY="$parent_record" \
  bash "$fixture/scripts/ci-local.sh" fast 2>&1)"
replay_status=$?
set -e
[[ "$replay_status" -eq 75 && "$replay_output" == *CI_PROOF_LOCKED_OR_STALE* \
  && "$(line_count "$fixture/children")" -eq "$children_before" \
  && "$(line_count "$fixture/observation-calls")" -eq "$observations_before" ]] \
  || { refuse CI_PROOF_REPLAY_REFUSAL_INVALID bullet-git; exit 1; }

set +e
empty_output="$(BULLET_CI_PROOF_CUSTODY='' bash "$fixture/scripts/ci-local.sh" fast 2>&1)"
empty_status=$?
set -e
[[ "$empty_status" -eq 75 && "$empty_output" == *CI_PROOF_LOCKED_OR_STALE* \
  && "$(line_count "$fixture/children")" -eq "$children_before" \
  && "$(line_count "$fixture/observation-calls")" -eq "$observations_before" ]] \
  || { refuse CI_PROOF_EMPTY_INHERITED_INVALID bullet-git; exit 1; }

set +e
(cd "$fixture" && bash scripts/ci-local.sh bad_lane >/dev/null 2>&1)
invalid_lane_status=$?
set -e
[[ "$invalid_lane_status" -eq 2 && ! -e "$lock" ]] \
  || { refuse CI_PROOF_INVALID_LANE_MUTATED bullet-git; exit 1; }

(umask 077; mkdir "$lock"; printf '%s\n' "$parent_record" >"$owner")
set +e
wrong_output="$(BULLET_CI_PROOF_CUSTODY="$parent_record-mutated" \
  bash "$fixture/scripts/ci-local.sh" fast 2>&1)"
wrong_status=$?
set -e
[[ "$wrong_status" -eq 75 && "$wrong_output" == *CI_PROOF_LOCKED_OR_STALE* \
  && "$(<"$owner")" == "$parent_record" ]] \
  || { refuse CI_PROOF_OWNER_MISMATCH_INVALID bullet-git; exit 1; }
rm -- "$owner"
rmdir -- "$lock"

assert_parent_record_refused \
  "${parent_record/repository=bullet-git/repository=bullet-kernel}" CI_PROOF_FORGED_REPOSITORY_INVALID
assert_parent_record_refused \
  "${parent_record/scope=family/scope=standalone}" CI_PROOF_FORGED_SCOPE_INVALID
assert_parent_record_refused \
  "${parent_record/pid=$$/pid=$(( $$ + 1 ))}" CI_PROOF_FORGED_PID_INVALID
assert_parent_record_refused \
  "${parent_record/lane=family/lane=required}" CI_PROOF_FORGED_FAMILY_LANE_INVALID
assert_parent_record_refused \
  "${parent_record/nonce=$$-12345-23456-34567/nonce=parent-fixture}" CI_PROOF_FORGED_NONCE_INVALID
assert_parent_record_refused "$parent_record" CI_PROOF_OWNER_EXTRA_LINE_INVALID true

(umask 077; mkdir "$lock"; printf '%s\0\n' "$parent_record" >"$owner")
set +e
nul_output="$(BULLET_CI_PROOF_CUSTODY="$parent_record" \
  bash "$fixture/scripts/ci-local.sh" fast 2>&1)"
nul_status=$?
set -e
[[ "$nul_status" -eq 75 && "$nul_output" == *CI_PROOF_LOCKED_OR_STALE* \
  && "$(line_count "$fixture/children")" -eq "$children_before" \
  && "$(line_count "$fixture/observation-calls")" -eq "$observations_before" ]] \
  || { refuse CI_PROOF_OWNER_NUL_INVALID bullet-git; exit 1; }
rm -- "$owner"
rmdir -- "$lock"

(umask 077; mkdir "$lock"; printf '%s\n' "$parent_record" >"$owner")
chmod 0755 "$lock"
set +e
(BULLET_CI_PROOF_CUSTODY="$parent_record" \
  bash "$fixture/scripts/ci-local.sh" fast >/dev/null 2>&1)
mode_status=$?
set -e
[[ "$mode_status" -eq 75 ]] \
  || { refuse CI_PROOF_LOCK_MODE_REFUSAL_INVALID bullet-git; exit 1; }
chmod 0700 "$lock"
chmod 0644 "$owner"
set +e
(BULLET_CI_PROOF_CUSTODY="$parent_record" \
  bash "$fixture/scripts/ci-local.sh" fast >/dev/null 2>&1)
mode_status=$?
set -e
[[ "$mode_status" -eq 75 ]] \
  || { refuse CI_PROOF_OWNER_MODE_REFUSAL_INVALID bullet-git; exit 1; }
chmod 0600 "$owner"
rm -- "$owner"
rmdir -- "$lock"

printf 'preserve\n' >"$outside/sentinel"
children_before="$(line_count "$fixture/children")"
observations_before="$(line_count "$fixture/observation-calls")"
rm "$fixture/.git/HEAD"
set +e
(cd "$fixture" && bash scripts/ci-local.sh fast >/dev/null 2>&1)
head_status=$?
set -e
[[ "$head_status" -eq 75 && "$(line_count "$fixture/children")" -eq "$children_before" \
  && "$(line_count "$fixture/observation-calls")" -eq "$observations_before" ]] \
  || { refuse CI_PROOF_MISSING_HEAD_INVALID bullet-git; exit 1; }
ln -s "$outside/sentinel" "$fixture/.git/HEAD"
(umask 077; mkdir "$lock"; printf '%s\n' "$parent_record" >"$owner")
set +e
(BULLET_CI_PROOF_CUSTODY="$parent_record" \
  bash "$fixture/scripts/ci-local.sh" fast >/dev/null 2>&1)
head_status=$?
set -e
[[ "$head_status" -eq 75 && "$(line_count "$fixture/children")" -eq "$children_before" \
  && "$(line_count "$fixture/observation-calls")" -eq "$observations_before" \
  && "$(<"$outside/sentinel")" == preserve ]] \
  || { refuse CI_PROOF_SYMLINK_HEAD_INVALID bullet-git; exit 1; }
rm -- "$owner"
rmdir -- "$lock"
rm "$fixture/.git/HEAD"
rmdir "$fixture/.git"
ln -s "$outside" "$fixture/.git"
set +e
(cd "$fixture" && bash scripts/ci-local.sh fast >/dev/null 2>&1)
symlink_status=$?
set -e
[[ "$symlink_status" -eq 75 && "$(<"$outside/sentinel")" == preserve \
  && ! -e "$outside/bullet-ci.lock.d" ]] \
  || { refuse CI_PROOF_GIT_SYMLINK_INVALID bullet-git; exit 1; }
rm "$fixture/.git"
mkdir "$fixture/.git"
children_before="$(line_count "$fixture/children")"
report_before="$(<"$fixture/.ci-artifacts/reports/fast.junit.xml")"
set +e
(cd "$fixture" && bash scripts/ci-local.sh fast >/dev/null 2>&1)
head_status=$?
set -e
[[ "$head_status" -eq 75 && "$(line_count "$fixture/children")" -eq "$children_before" \
  && "$(<"$fixture/.ci-artifacts/reports/fast.junit.xml")" == "$report_before" ]] \
  || { refuse CI_PROOF_HEAD_MISSING_INVALID bullet-git; exit 1; }
ln -s "$outside/sentinel" "$fixture/.git/HEAD"
(umask 077; mkdir "$lock"; printf '%s\n' "$parent_record" >"$owner")
set +e
(BULLET_CI_PROOF_CUSTODY="$parent_record" \
  bash "$fixture/scripts/ci-local.sh" fast >/dev/null 2>&1)
head_status=$?
set -e
[[ "$head_status" -eq 75 && "$(line_count "$fixture/children")" -eq "$children_before" \
  && "$(<"$outside/sentinel")" == preserve ]] \
  || { refuse CI_PROOF_HEAD_SYMLINK_INVALID bullet-git; exit 1; }
rm -- "$owner"
rmdir -- "$lock"
rm "$fixture/.git/HEAD"
printf 'ref: refs/heads/main\n' >"$fixture/.git/HEAD"
ln -s "$outside" "$lock"
set +e
(cd "$fixture" && bash scripts/ci-local.sh fast >/dev/null 2>&1)
symlink_status=$?
set -e
[[ "$symlink_status" -eq 75 && "$(<"$outside/sentinel")" == preserve ]] \
  || { refuse CI_PROOF_LOCK_SYMLINK_INVALID bullet-git; exit 1; }
rm "$lock"

(umask 077; mkdir "$lock")
ln -s "$outside/sentinel" "$owner"
set +e
(BULLET_CI_PROOF_CUSTODY="$parent_record" \
  bash "$fixture/scripts/ci-local.sh" fast >/dev/null 2>&1)
symlink_status=$?
set -e
[[ "$symlink_status" -eq 75 && "$(<"$outside/sentinel")" == preserve && -L "$owner" ]] \
  || { refuse CI_PROOF_OWNER_SYMLINK_INVALID bullet-git; exit 1; }
rm "$owner"
rmdir "$lock"

(umask 077; mkdir "$lock"; printf '%s\n' "$parent_record" >"$owner")
rm -f -- "$fixture/child-started" "$fixture/release-child"
observations_before="$(line_count "$fixture/observation-calls")"
(
  exec env BULLET_CI_PROOF_CUSTODY="$parent_record" CI_FIXTURE_HOLD=1 \
    bash "$fixture/scripts/ci-local.sh" fast
) >"$fixture/substitution-output" 2>&1 &
owner_pid=$!
wait_for "$fixture/child-started"
rm "$owner"
ln -s "$outside/sentinel" "$owner"
: >"$fixture/release-child"
set +e
wait "$owner_pid"
substitution_status=$?
set -e
owner_pid=
[[ "$substitution_status" -eq 75 \
  && "$(line_count "$fixture/observation-calls")" -eq "$observations_before" \
  && "$(<"$outside/sentinel")" == preserve && -L "$owner" ]] \
  || { refuse CI_PROOF_OWNER_SUBSTITUTION_INVALID bullet-git; exit 1; }
rm "$owner"
rmdir "$lock"

log "proof custody hostile matrix passed"
