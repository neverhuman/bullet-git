#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
for tool in cargo-nextest cmp comm jq mktemp sort; do require_tool "$tool" || exit 1; done

actual_packages="$(cargo metadata --locked --no-deps --format-version 1 | jq -r '.packages[].name' | LC_ALL=C sort)"
expected_packages="$(printf '%s\n' bullet-git-journal bullet-git-types bullet-git-workspace bullet-gitd | LC_ALL=C sort)"
[[ "$actual_packages" == "$expected_packages" ]] || {
  echo "[ci] UNCLASSIFIED_TEST_PACKAGE: workspace package inventory changed" >&2
  diff -u <(printf '%s\n' "$expected_packages") <(printf '%s\n' "$actual_packages") >&2 || true
  exit 1
}

partition_tmp="$(mktemp -d)"
cleanup() { rm -rf -- "$partition_tmp"; }
trap cleanup EXIT
list_tests() {
  local filter="$1" output="$2"
  cargo nextest list --locked --workspace -E "$filter" --message-format json \
    | jq -r '."rust-suites" | to_entries[] | .key as $suite
      | .value.testcases | to_entries[]
      | select(.value."filter-match".status == "matches")
      | [$suite, .key] | @tsv' \
    | LC_ALL=C sort -u >"$output"
}
list_tests 'all()' "$partition_tmp/all"
list_tests "$FAST_FILTER" "$partition_tmp/fast"
list_tests "$CONTRACT_FILTER" "$partition_tmp/contract"
for partition in all fast contract; do
  [[ -s "$partition_tmp/$partition" ]] || {
    printf '[ci] ZERO_TEST_PARTITION: %s has no cases\n' "$partition" >&2
    exit 1
  }
done
overlap="$(LC_ALL=C comm -12 "$partition_tmp/fast" "$partition_tmp/contract")"
[[ -z "$overlap" ]] || {
  echo "[ci] OVERLAPPING_TEST_PARTITIONS: fast and contract share cases" >&2
  printf '%s\n' "$overlap" >&2
  exit 1
}
LC_ALL=C sort -u "$partition_tmp/fast" "$partition_tmp/contract" >"$partition_tmp/union"
cmp -s "$partition_tmp/all" "$partition_tmp/union" || {
  echo "[ci] SILENT_TEST_LOSS: fast and contract do not exactly cover the workspace" >&2
  diff -u "$partition_tmp/all" "$partition_tmp/union" >&2 || true
  exit 1
}
fast_count="$(wc -l <"$partition_tmp/fast")"
contract_count="$(wc -l <"$partition_tmp/contract")"
total_count="$(wc -l <"$partition_tmp/all")"
if [[ "$fast_count" -ne "$FAST_EXPECTED_TESTS" ||
      "$contract_count" -ne "$CONTRACT_EXPECTED_TESTS" ||
      "$total_count" -ne "$TOTAL_EXPECTED_TESTS" ]]; then
  printf '[ci] TEST_PARTITION_DRIFT: fast=%s/%s contract=%s/%s total=%s/%s\n' \
    "$fast_count" "$FAST_EXPECTED_TESTS" \
    "$contract_count" "$CONTRACT_EXPECTED_TESTS" \
    "$total_count" "$TOTAL_EXPECTED_TESTS" >&2
  exit 1
fi
printf '[ci] test partitions exact: fast=%s contract=%s total=%s\n' \
  "$fast_count" "$contract_count" "$total_count"
