#!/usr/bin/env bash
set -euo pipefail
lanes=(source-scan fast lint contract security docs)
expected_args=$(( ${#lanes[@]} * 2 ))
[[ "$#" -eq "$expected_args" ]] || {
  printf 'CI_JOB_MISSING: expected %s result/observation values, got %s\n' "$expected_args" "$#" >&2
  exit 1
}
for lane in "${lanes[@]}"; do
  result="$1" observation="$2"
  shift 2
  [[ "$result" == success ]] || {
    printf 'CI_JOB_NOT_SUCCESSFUL: %s=%s\n' "$lane" "${result:-missing}" >&2
    exit 1
  }
  [[ "$observation" == present ]] || {
    printf 'CI_OBSERVATION_MISSING: %s=%s\n' "$lane" "${observation:-missing}" >&2
    exit 1
  }
done
echo "CI / required: all atomic jobs and observations are present and successful"
