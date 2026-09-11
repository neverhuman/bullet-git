#!/usr/bin/env bash
# Local components only; no installed native auditor or distribution credit.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
bash ops/ci/jankurai-bootstrap-test.sh
bash ops/ci/audit-test.sh
mkdir -p target/jankurai/component-runs
run="$(mktemp -d "$PWD/target/jankurai/component-runs/run.XXXXXXXX")"
export CARGO_TARGET_DIR="$run/target"
# Cargo's target directory does not relocate Nextest's workspace-relative store.
# A unique lower-priority tool config keeps the repository's test profile intact.
jq -nr --arg directory "$CARGO_TARGET_DIR/nextest" \
  '"[store]\ndir = " + ($directory | tojson)' >"$run/nextest.toml"
# nextest rejects empty selection and retains individual completed identities.
# The same binary's tests are also selected by the canonical contract partition.
list=(cargo nextest list --locked --offline --package bullet-git-workspace --bin bullet-ci-jankurai --message-format json)
execute=(cargo nextest run --locked --offline --package bullet-git-workspace --bin bullet-ci-jankurai --profile contract
  --tool-config-file "bullet-audit:$run/nextest.toml")
printf '%s\0' "${list[@]}" >"$run/selection.argv"
status=0
"${list[@]}" >"$run/selection.json" 2>"$run/selection.stderr" || status=$?
printf '%s\n' "$status" >"$run/selection.exit"
[[ "$status" -eq 0 ]] || exit "$status"
jq -e '.["test-count"] | type == "number" and . > 0' "$run/selection.json" >/dev/null
printf '%s\0' "${execute[@]}" >"$run/execution.argv"
"${execute[@]}" >"$run/execution.stdout" 2>"$run/execution.stderr" || status=$?
printf '%s\n' "$status" >"$run/execution.exit"
printf '[ci] Rust component originals retained: %s (status %s)\n' "$run" "$status"
cat "$run/execution.stdout"
cat "$run/execution.stderr" >&2
[[ "$status" -eq 0 ]] || exit "$status"
[[ -s "$CARGO_TARGET_DIR/nextest/contract/junit.xml" ]]
printf '[ci] audit components passed (local fixtures; installed auditor unqualified)\n'
