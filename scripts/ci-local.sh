#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
REPO_ROOT="$PWD"

CI_PROOF_LOCK_DIR="$REPO_ROOT/.git/bullet-ci.lock.d"
CI_PROOF_LOCK_OWNER="$CI_PROOF_LOCK_DIR/owner"
CI_PROOF_LOCK_RECORD=""
CI_PROOF_LOCK_INHERITED=false
CI_PROOF_REQUESTED_LANE=""
# bullet-member-proof-custody-v1
if [[ ${BULLET_CI_PROOF_CUSTODY+x} ]]; then
  CI_PROOF_LOCK_INHERITED=true
  CI_PROOF_LOCK_RECORD="$BULLET_CI_PROOF_CUSTODY"
fi
unset BULLET_CI_PROOF_CUSTODY

proof_lock_refusal() {
  printf '%s\n' \
    "ci-local: CI_PROOF_LOCKED_OR_STALE: $CI_PROOF_LOCK_DIR is occupied or cannot be trusted" \
    "ci-local: verify that no scripts/ci-local.sh process is using this exact checkout; then inspect and explicitly reconcile only $CI_PROOF_LOCK_DIR" >&2
  return 75
}

proof_lock_record_is_valid() {
  local family_pattern standalone_pattern
  family_pattern='^schema=2 repository=bullet-git scope=family pid=([1-9][0-9]*) lane=(family|family-contract) nonce=([0-9]+-[0-9]+-[0-9]+-[0-9]+)$'
  standalone_pattern='^schema=2 repository=bullet-git scope=standalone pid=([1-9][0-9]*) lane=([a-z0-9-]+) nonce=([0-9]+-[0-9]+-[0-9]+-[0-9]+)$'
  if [[ "$CI_PROOF_LOCK_INHERITED" == true ]]; then
    [[ "$CI_PROOF_LOCK_RECORD" =~ $family_pattern \
      && "${BASH_REMATCH[1]}" == "$PPID" ]]
  else
    [[ "$CI_PROOF_LOCK_RECORD" =~ $standalone_pattern \
      && "${BASH_REMATCH[1]}" == "$$" \
      && "${BASH_REMATCH[2]}" == "$CI_PROOF_REQUESTED_LANE" ]]
  fi
}

proof_path_is_exact() {
  local path="$1" type="$2" mode="$3" uid
  uid="$(id -u)"
  [[ "$(find "$path" -maxdepth 0 -type "$type" -uid "$uid" -perm "$mode" -print 2>/dev/null)" == "$path" ]]
}

verify_proof_lock() {
  local record extra first_status extra_status owner_fd byte_count expected_bytes
  if ! [[ -d "$REPO_ROOT/.git" && ! -L "$REPO_ROOT/.git" \
    && -f "$REPO_ROOT/.git/HEAD" && ! -L "$REPO_ROOT/.git/HEAD" \
    && -d "$CI_PROOF_LOCK_DIR" && ! -L "$CI_PROOF_LOCK_DIR" \
    && -f "$CI_PROOF_LOCK_OWNER" && ! -L "$CI_PROOF_LOCK_OWNER" ]] \
    || ! proof_path_is_exact "$CI_PROOF_LOCK_DIR" d 0700 \
    || ! proof_path_is_exact "$CI_PROOF_LOCK_OWNER" f 0600; then
    proof_lock_refusal
    return 75
  fi
  exec {owner_fd}<"$CI_PROOF_LOCK_OWNER" || {
    proof_lock_refusal
    return 75
  }
  first_status=0
  IFS= read -r record <&"$owner_fd" || first_status=$?
  extra=
  extra_status=0
  IFS= read -r extra <&"$owner_fd" || extra_status=$?
  exec {owner_fd}<&-
  byte_count="$(LC_ALL=C wc -c <"$CI_PROOF_LOCK_OWNER")" || {
    proof_lock_refusal
    return 75
  }
  expected_bytes=$((${#CI_PROOF_LOCK_RECORD} + 1))
  if [[ "$first_status" -ne 0 || "$extra_status" -eq 0 || -n "$extra" \
    || "$byte_count" -ne "$expected_bytes" || -z "$CI_PROOF_LOCK_RECORD" \
    || "$record" != "$CI_PROOF_LOCK_RECORD" ]] \
    || ! proof_lock_record_is_valid; then
    proof_lock_refusal
    return 75
  fi
}

acquire_proof_lock() {
  local lane="$1"
  CI_PROOF_REQUESTED_LANE="$lane"
  if [[ "$CI_PROOF_LOCK_INHERITED" == true ]]; then
    verify_proof_lock
    return $?
  fi
  [[ "$lane" =~ ^[a-z0-9-]+$ \
    && -d "$REPO_ROOT/.git" && ! -L "$REPO_ROOT/.git" \
    && -f "$REPO_ROOT/.git/HEAD" && ! -L "$REPO_ROOT/.git/HEAD" ]] || {
    proof_lock_refusal
    return 75
  }
  if ! (umask 077; mkdir -- "$CI_PROOF_LOCK_DIR") 2>/dev/null; then
    proof_lock_refusal
    return 75
  fi
  [[ -d "$CI_PROOF_LOCK_DIR" && ! -L "$CI_PROOF_LOCK_DIR" ]] || {
    proof_lock_refusal
    return 75
  }
  CI_PROOF_LOCK_RECORD="schema=2 repository=bullet-git scope=standalone pid=$$ lane=$lane nonce=$$-${BASHPID:-$$}-$RANDOM-$RANDOM"
  if ! (umask 077; set -o noclobber; printf '%s\n' "$CI_PROOF_LOCK_RECORD" \
      >"$CI_PROOF_LOCK_OWNER") 2>/dev/null; then
    proof_lock_refusal
    return 75
  fi
  verify_proof_lock
}

release_proof_lock() {
  verify_proof_lock || return $?
  [[ "$CI_PROOF_LOCK_INHERITED" == false ]] || return 0
  rm -- "$CI_PROOF_LOCK_OWNER" || {
    proof_lock_refusal
    return 75
  }
  rmdir -- "$CI_PROOF_LOCK_DIR" || {
    proof_lock_refusal
    return 75
  }
}

run_observed() {
  local custody_lane="$1" script="$2" observation_lane="${3:-$1}" status observation_status
  acquire_proof_lock "$custody_lane" || return $?
  set +e
  bash scripts/ci-doctor.sh "$observation_lane"
  status=$?
  set -e
  verify_proof_lock || return $?
  if [[ "$status" -eq 0 ]]; then
    set +e
    bash "$script"
    status=$?
    set -e
    verify_proof_lock || return $?
  fi
  verify_proof_lock || return $?
  set +e
  bash scripts/ci-observation.sh "$observation_lane" "$status" \
    "bash scripts/ci-doctor.sh $observation_lane" "bash $script"
  observation_status=$?
  set -e
  verify_proof_lock || return $?
  release_proof_lock || return $?
  [[ "$observation_status" -eq 0 ]] || return "$observation_status"
  return "$status"
}

lane="${1:-required}"
case "$lane" in
  source-scan) run_observed source-scan ops/ci/source-scan.sh ;;
  fast) run_observed fast ops/ci/fast.sh ;;
  lint) run_observed lint ops/ci/lint.sh ;;
  contract) run_observed contract ops/ci/contract.sh ;;
  security) run_observed security ops/ci/security.sh ;;
  docs) run_observed docs ops/ci/docs.sh ;;
  required) run_observed required ops/ci/required.sh ;;
  audit) run_observed audit ops/ci/audit.sh ;;
  nightly) run_observed nightly ops/ci/nightly.sh ;;
  history) run_observed history ops/ci/history.sh ;;
  links) run_observed links ops/ci/external-links.sh ;;
  advisory) run_observed advisory ops/ci/advisory.sh ;;
  coverage) run_observed coverage ops/ci/coverage.sh ;;
  platform) run_observed platform ops/ci/platform-refusal.sh ;;
  toolchain-msrv) run_observed toolchain-msrv ops/ci/toolchain-msrv.sh ;;
  gates|all) run_observed "$lane" ops/ci/required.sh required ;;
  *)
    echo "usage: $0 {source-scan|fast|lint|contract|security|docs|required|audit|nightly|history|links|advisory|coverage|platform|toolchain-msrv|all}" >&2
    exit 2
    ;;
esac
