#!/usr/bin/env bash
# Converge the six hosted predecessor results against observations and
# diagnostics downloaded from this exact workflow run.
set -euo pipefail
lanes=(source-scan fast lint contract security docs)
[[ "$#" -eq 8 ]] || {
  printf 'CI_JOB_MISSING: expected artifact root, commit, and six results; got %s arguments\n' "$#" >&2
  exit 1
}
artifact_root="$1"
expected_commit="$2"
shift 2
[[ -d "$artifact_root" && ! -L "$artifact_root" ]] || {
  printf 'CI_ARTIFACT_ROOT_INVALID: %s\n' "$artifact_root" >&2
  exit 1
}
[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]] || {
  printf 'CI_COMMIT_INVALID: %s\n' "$expected_commit" >&2
  exit 1
}

for lane in "${lanes[@]}"; do
  result="$1"
  shift
  [[ "$result" == success ]] || {
    printf 'CI_JOB_NOT_SUCCESSFUL: %s=%s\n' "$lane" "${result:-missing}" >&2
    exit 1
  }
  bash ops/ci/artifact-check.sh "$lane" "$expected_commit" "$artifact_root" merged
done

expected_files=(
  observations/contract.json
  observations/docs.json
  observations/fast.json
  observations/lint.json
  observations/security.json
  observations/source-scan.json
  reports/contract.junit.xml
  reports/fast.junit.xml
)
mapfile -t actual_files < <(
  find "$artifact_root" -mindepth 1 \( -type f -o -type l \) -print \
    | sed "s#^$artifact_root/##" | LC_ALL=C sort
)
[[ "${actual_files[*]}" == "${expected_files[*]}" ]] || {
  printf 'CI_ARTIFACT_TREE_INVALID: expected=[%s] actual=[%s]\n' \
    "${expected_files[*]}" "${actual_files[*]}" >&2
  exit 1
}
printf 'CI / required: six jobs, clean exact-subject observations, and hashed sanitized artifacts passed\n'
