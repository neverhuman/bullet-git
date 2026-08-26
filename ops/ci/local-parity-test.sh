#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

toml_job_block() {
  local config="$1" job="$2" line block='' in_job=false found=false
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == '[[job]]' ]]; then
      if [[ "$found" == true ]]; then
        printf '%s' "$block"
        return 0
      fi
      block=$'[[job]]\n'
      in_job=true
      continue
    fi
    [[ "$in_job" == true ]] || continue
    block+="$line"$'\n'
    [[ "$line" == "id = \"$job\"" ]] && found=true
  done <<<"$config"
  [[ "$found" == true ]] && printf '%s' "$block"
}

toml_line_count() {
  local block="$1" expected="$2" line count=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == "$expected" ]] && count=$((count + 1))
  done <<<"$block"
  printf '%s\n' "$count"
}

toml_prefix_count() {
  local block="$1" prefix="$2" line count=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == "$prefix"* ]] && count=$((count + 1))
  done <<<"$block"
  printf '%s\n' "$count"
}

toml_semantic_line_count() {
  local block="$1" line trimmed count=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    trimmed="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$trimmed" || "$trimmed" == \#* ]] && continue
    count=$((count + 1))
  done <<<"$block"
  printf '%s\n' "$count"
}

toml_preamble_is_inert() {
  local config="$1" line trimmed
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == '[[job]]' ]] && return 0
    trimmed="${line#"${line%%[![:space:]]*}"}"
    [[ -z "$trimmed" || "$trimmed" == \#* ]] || return 1
  done <<<"$config"
}

toml_job_count() {
  local config="$1" line count=0
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" == '[[job]]' ]] && count=$((count + 1))
  done <<<"$config"
  printf '%s\n' "$count"
}

toml_job_ids() {
  local config="$1" line id want_id=false
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" == '[[job]]' ]]; then
      want_id=true
    elif [[ "$want_id" == true && "$line" == 'id = "'*'"' ]]; then
      id="${line#'id = "'}"
      id="${id%'"'}"
      printf '%s\n' "$id"
      want_id=false
    fi
  done <<<"$config"
}

validate_jeryu_graph() {
  local config="$1" actual_ids expected_ids job block expected_semantic_lines
  local -a jobs=(activation source_scan fast lint contract security docs required)
  local -A names needs runs artifacts

  names[activation]='name = "prepared activation refusal"'
  names[source_scan]='name = "source scan"'
  names[fast]='name = "fast"'
  names[lint]='name = "lint"'
  names[contract]='name = "contract"'
  names[security]='name = "security"'
  names[docs]='name = "docs"'
  names[required]='name = "CI / required"'

  needs[activation]=''
  needs[source_scan]='needs = ["activation"]'
  needs[fast]='needs = ["source_scan"]'
  needs[lint]='needs = ["source_scan"]'
  needs[contract]='needs = ["source_scan"]'
  needs[security]='needs = ["source_scan"]'
  needs[docs]='needs = ["source_scan"]'
  needs[required]='needs = ["source_scan", "fast", "lint", "contract", "security", "docs"]'

  runs[activation]='run = ["bash ops/ci/jeryu-activation-gate.sh"]'
  runs[source_scan]='run = ["bash ops/ci/jeryu-activation-gate.sh", "bash scripts/ci-local.sh source-scan"]'
  runs[fast]='run = ["bash ops/ci/jeryu-activation-gate.sh", "bash scripts/ci-local.sh fast"]'
  runs[lint]='run = ["bash ops/ci/jeryu-activation-gate.sh", "bash scripts/ci-local.sh lint"]'
  runs[contract]='run = ["bash ops/ci/jeryu-activation-gate.sh", "bash scripts/ci-local.sh contract"]'
  runs[security]='run = ["bash ops/ci/jeryu-activation-gate.sh", "bash scripts/ci-local.sh security"]'
  runs[docs]='run = ["bash ops/ci/jeryu-activation-gate.sh", "bash scripts/ci-local.sh docs"]'
  runs[required]='run = ["bash ops/ci/jeryu-activation-gate.sh", "bash ops/ci/jeryu-required.sh"]'

  artifacts[activation]='artifact_paths = []'
  artifacts[source_scan]='artifact_paths = [".ci-artifacts/observations/source-scan.json"]'
  artifacts[fast]='artifact_paths = [".ci-artifacts/observations/fast.json", ".ci-artifacts/reports/fast.junit.xml"]'
  artifacts[lint]='artifact_paths = [".ci-artifacts/observations/lint.json"]'
  artifacts[contract]='artifact_paths = [".ci-artifacts/observations/contract.json", ".ci-artifacts/reports/contract.junit.xml"]'
  artifacts[security]='artifact_paths = [".ci-artifacts/observations/security.json"]'
  artifacts[docs]='artifact_paths = [".ci-artifacts/observations/docs.json"]'
  artifacts[required]='artifact_paths = []'

  toml_preamble_is_inert "$config" || return 1
  [[ "$(toml_job_count "$config")" -eq 8 ]] || return 1
  actual_ids="$(toml_job_ids "$config")"
  expected_ids="$(printf '%s\n' "${jobs[@]}")"
  [[ "$actual_ids" == "$expected_ids" ]] || return 1

  for job in "${jobs[@]}"; do
    block="$(toml_job_block "$config" "$job")"
    [[ -n "$block" ]] || return 1
    [[ "$(toml_line_count "$block" "id = \"$job\"")" -eq 1 ]] || return 1
    [[ "$(toml_prefix_count "$block" 'id = ')" -eq 1 ]] || return 1
    [[ "$(toml_line_count "$block" "${names[$job]}")" -eq 1 ]] || return 1
    [[ "$(toml_prefix_count "$block" 'name = ')" -eq 1 ]] || return 1
    [[ "$(toml_line_count "$block" 'runner_class = "native-rust-clean"')" -eq 1 ]] || return 1
    [[ "$(toml_prefix_count "$block" 'runner_class = ')" -eq 1 ]] || return 1
    [[ "$(toml_line_count "$block" "${runs[$job]}")" -eq 1 ]] || return 1
    [[ "$(toml_prefix_count "$block" 'run = ')" -eq 1 ]] || return 1
    [[ "$(toml_line_count "$block" 'cache_mounts = []')" -eq 1 ]] || return 1
    [[ "$(toml_prefix_count "$block" 'cache_mounts = ')" -eq 1 ]] || return 1
    [[ "$(toml_line_count "$block" "${artifacts[$job]}")" -eq 1 ]] || return 1
    [[ "$(toml_prefix_count "$block" 'artifact_paths = ')" -eq 1 ]] || return 1
    if [[ -n "${needs[$job]}" ]]; then
      [[ "$(toml_line_count "$block" "${needs[$job]}")" -eq 1 ]] || return 1
      [[ "$(toml_prefix_count "$block" 'needs = ')" -eq 1 ]] || return 1
    else
      [[ "$(toml_prefix_count "$block" 'needs = ')" -eq 0 ]] || return 1
    fi
    expected_semantic_lines=8
    [[ "$job" == activation ]] && expected_semantic_lines=7
    [[ "$(toml_semantic_line_count "$block")" -eq "$expected_semantic_lines" ]] || return 1
  done
}

replace_line_once() {
  local config="$1" target="$2" replacement="$3" line replaced=false
  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$replaced" == false && "$line" == "$target" ]]; then
      line="$replacement"
      replaced=true
    fi
    printf '%s\n' "$line"
  done <<<"$config"
}

expect_jeryu_graph_rejection() {
  local label="$1" hostile="$2"
  [[ "$hostile" != "$ci_config" ]] || {
    printf '[ci] Jeryu hostile fixture did not mutate the graph: %s\n' "$label" >&2
    exit 1
  }
  if validate_jeryu_graph "$hostile"; then
    printf '[ci] Jeryu graph admitted hostile bypass: %s\n' "$label" >&2
    exit 1
  fi
}

controls=(
  scripts/ci-doctor.sh
  scripts/ci-local.sh
  scripts/ci-observation.sh
  ops/ci/jeryu-activation-gate.sh
  ops/ci/jeryu-required.sh
  ops/ci/quality-gates.sh
  ops/git-hooks/pre-push
)
for control in "${controls[@]}"; do
  [[ -x "$control" ]] || {
    printf '[ci] local parity control is not executable: %s\n' "$control" >&2
    exit 1
  }
  bash -n "$control"
done

while IFS= read -r -d '' entrypoint; do
  [[ -x "$entrypoint" ]] || {
    printf '[ci] CI shell entrypoint is not executable: %s\n' "$entrypoint" >&2
    exit 1
  }
done < <(git ls-files --cached --others --exclude-standard -z -- 'ops/ci/*.sh' 'scripts/ci*.sh')

ci_config="$(< ci.toml)"
validate_jeryu_graph "$ci_config" || {
  printf '[ci] inactive Jeryu graph is not the exact admitted eight-job topology\n' >&2
  exit 1
}
[[ "$ci_config" != *'aggregate.sh success present'* ]]

expect_jeryu_graph_rejection commented-noop "$(replace_line_once "$ci_config" \
  'run = ["bash ops/ci/jeryu-activation-gate.sh"]' \
  'run = ["true # bash ops/ci/jeryu-activation-gate.sh"]')"
expect_jeryu_graph_rejection omitted-activation-edge "$(replace_line_once "$ci_config" \
  'needs = ["activation"]' 'needs = []')"
expect_jeryu_graph_rejection direct-atomic-run "$(replace_line_once "$ci_config" \
  'run = ["bash ops/ci/jeryu-activation-gate.sh", "bash scripts/ci-local.sh fast"]' \
  'run = ["bash scripts/ci-local.sh fast"]')"
expect_jeryu_graph_rejection direct-required-run "$(replace_line_once "$ci_config" \
  'run = ["bash ops/ci/jeryu-activation-gate.sh", "bash ops/ci/jeryu-required.sh"]' \
  'run = ["bash ops/ci/jeryu-required.sh"]')"
expect_jeryu_graph_rejection continue-on-error-unknown-key "$(replace_line_once "$ci_config" \
  'runner_class = "native-rust-clean"' \
  $'runner_class = "native-rust-clean"\ncontinue_on_error = true')"
expect_jeryu_graph_rejection global-condition-key \
  $'if = "always"\n'"$ci_config"
expect_jeryu_graph_rejection global-status-key \
  $'continue_on_error = true\n'"$ci_config"
expect_jeryu_graph_rejection global-executor-key \
  $'runner_class = "hostile"\n'"$ci_config"

expected_activation_refusal='{"schema_version":"bullet.ci-activation-refusal.v1","code":"JERYU_CI_NOT_RATIFIED","status":"BLOCKED","exit_code":78,"release_authority":false}'
set +e
activation_output="$(bash ops/ci/jeryu-activation-gate.sh 2>&1)"
activation_status=$?
set -e
[[ "$activation_status" -eq 78 && "$activation_output" == "$expected_activation_refusal" ]] || {
  printf '[ci] inactive Jeryu activation gate did not refuse exactly (status=%s)\n' \
    "$activation_status" >&2
  exit 1
}

set +e
jeryu_output="$(bash ops/ci/jeryu-required.sh 2>&1)"
jeryu_status=$?
set -e
[[ "$jeryu_status" -eq 78 && "$jeryu_output" == *'JERYU_STATUS_BINDING_UNRATIFIED'* ]] || {
  printf '[ci] inactive Jeryu required job did not refuse truthfully (status=%s)\n' "$jeryu_status" >&2
  exit 1
}

quality_gate="$(< ops/ci/quality-gates.sh)"
[[ "$quality_gate" == *"exec bash ops/ci/fast.sh"* ]]
[[ "$quality_gate" != *"ops/ci/required.sh"* ]]
pre_push="$(< ops/git-hooks/pre-push)"
[[ "$pre_push" == *'ops/ci/quality-gates.sh'* ]]
justfile="$(< Justfile)"
[[ "$justfile" == *"ci-doctor lane=\"all\":"* ]]
[[ "$justfile" == *"git config --local core.hooksPath ops/git-hooks"* ]]
for recipe in fast lint contract security docs required; do
  [[ "$justfile" == *"$recipe:"* ]] || {
    printf '[ci] Justfile missing %s recipe\n' "$recipe" >&2
    exit 1
  }
done

bash scripts/ci-doctor.sh fast >/dev/null
set +e
bash scripts/ci-doctor.sh invalid >/dev/null 2>&1
invalid_status=$?
set -e
[[ "$invalid_status" -eq 2 ]] || {
  printf '[ci] invalid doctor lane returned %s, expected 2\n' "$invalid_status" >&2
  exit 1
}

bash_path="$(command -v bash)"
set +e
missing_output="$(PATH=/nonexistent "$bash_path" scripts/ci-doctor.sh fast 2>&1)"
missing_status=$?
set -e
[[ "$missing_status" -eq 1 ]] || {
  printf '[ci] missing-tool doctor returned %s, expected 1\n' "$missing_status" >&2
  exit 1
}
for tool in cargo cargo-nextest find id jq rustc wc; do
  [[ "$missing_output" == *"ci-doctor: missing $tool for fast"* ]] || {
    printf '[ci] doctor did not report missing %s\n' "$tool" >&2
    exit 1
  }
done

log "local parity controls passed"
