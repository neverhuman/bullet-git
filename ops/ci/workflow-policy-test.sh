#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

required=.github/workflows/ci.yml
scheduled=.github/workflows/scheduled.yml
[[ -f "$required" && -f "$scheduled" ]] || { echo "[ci] WORKFLOW_MISSING" >&2; exit 1; }

job_block() {
  local file="$1" job="$2"
  awk -v header="  $job:" '
    $0 == header { active=1 }
    active && $0 ~ /^  [A-Za-z0-9_-]+:/ && $0 != header { exit }
    active { print }
  ' "$file"
}

step_block() {
  local block="$1" name="$2" header="      - name: $2"
  [[ "$(grep -Fxc "$header" <<<"$block")" -eq 1 ]] || return 1
  awk -v header="$header" '
    $0 == header { active=1 }
    active && $0 ~ /^      - / && $0 != header { exit }
    active { print }
  ' <<<"$block"
}

exact_scalar_step() {
  local block="$1" name="$2" command="$3" shell="${4:--}" step expected
  step="$(step_block "$block" "$name")" || return 1
  if [[ "$shell" == - ]]; then
    expected="$(printf '%s\n' "      - name: $name" "        run: $command")"
  else
    expected="$(printf '%s\n' "      - name: $name" "        shell: $shell" "        run: $command")"
  fi
  [[ "$step" == "$expected" ]]
}

exact_upload_step() {
  local block="$1" name="$2" artifact_name="$3" expected_path="$4" step expected
  step="$(step_block "$block" "$name")" || return 1
  expected="$(printf '%s\n' \
    "      - name: $name" \
    "        if: \${{ !cancelled() && steps.stage.outcome == 'success' }}" \
    '        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2' \
    '        with:' \
    "          name: $artifact_name" \
    "          path: $expected_path" \
    '          include-hidden-files: true' \
    '          if-no-files-found: error' \
    '          retention-days: 14')"
  [[ "$step" == "$expected" ]]
}

exact_validation_step() {
  local block="$1" name="$2" lane="$3" step expected
  step="$(step_block "$block" "$name")" || return 1
  expected="$(printf '%s\n' \
    "      - name: $name" \
    "        if: \${{ !cancelled() }}" \
    '        env:' \
    "          EXPECTED_COMMIT: \${{ github.sha }}" \
    '        run: |' \
    "          bash ops/ci/artifact-check.sh $lane \"\$EXPECTED_COMMIT\"")"
  [[ "$step" == "$expected" ]]
}

exact_stage_step() {
  local block="$1" lane="$2" shell="${3:--}" step expected name="Stage exact $2 diagnostics"
  step="$(step_block "$block" "$name")" || return 1
  if [[ "$shell" == - ]]; then
    expected="$(printf '%s\n' \
      "      - name: $name" \
      '        id: stage' \
      "        if: \${{ !cancelled() }}" \
      '        env:' \
      "          EXPECTED_COMMIT: \${{ github.sha }}" \
      "        run: bash ops/ci/stage-artifacts.sh $lane \"\$EXPECTED_COMMIT\"")"
  else
    expected="$(printf '%s\n' \
      "      - name: $name" \
      '        id: stage' \
      "        if: \${{ !cancelled() }}" \
      "        shell: $shell" \
      '        env:' \
      "          EXPECTED_COMMIT: \${{ github.sha }}" \
      "        run: bash ops/ci/stage-artifacts.sh $lane \"\$EXPECTED_COMMIT\"")"
  fi
  [[ "$step" == "$expected" ]]
}

exact_required_download_step() {
  local block="$1" step expected name="Download this run's atomic observations and sanitized reports"
  step="$(step_block "$block" "$name")" || return 1
  expected="$(printf '%s\n' \
    "      - name: $name" \
    '        uses: actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093 # v4.3.0' \
    '        with:' \
    "          pattern: bullet-git-*-\${{ github.run_id }}-\${{ github.run_attempt }}" \
    '          path: .ci-artifacts/atomic' \
    '          merge-multiple: true')"
  [[ "$step" == "$expected" ]]
}

exact_required_convergence_step() {
  local block="$1" step expected name='Converge exact CI / required context'
  step="$(step_block "$block" "$name")" || return 1
  expected="$(printf '%s\n' \
    "      - name: $name" \
    "        if: \${{ always() }}" \
    '        run: |' \
    "          bash ops/ci/aggregate.sh .ci-artifacts/atomic \"\$EXPECTED_COMMIT\" \\" \
    "            \"\$SOURCE_SCAN_RESULT\" \"\$FAST_RESULT\" \"\$LINT_RESULT\" \\" \
    "            \"\$CONTRACT_RESULT\" \"\$SECURITY_RESULT\" \"\$DOCS_RESULT\"")"
  [[ "$step" == "$expected" ]]
}

exact_workflow_inventory() {
  local definition="$1" expected_ids="$2" expected_uploads="$3" expected_downloads="$4" expected_hash="$5"
  local actual_ids upload_count download_count definition_hash
  actual_ids="$(awk '
    $0 == "jobs:" { active=1; next }
    active && $0 ~ /^  [a-z][a-z0-9_-]*:$/ {
      id=$0
      sub(/^  /, "", id)
      sub(/:$/, "", id)
      print id
    }
  ' <<<"$definition")"
  upload_count="$(awk 'index($0, "actions/upload-artifact@") { count++ } END { print count+0 }' <<<"$definition")"
  download_count="$(awk 'index($0, "actions/download-artifact@") { count++ } END { print count+0 }' <<<"$definition")"
  definition_hash="$(printf '%s' "$definition" | sha256sum)"
  definition_hash="${definition_hash%% *}"
  [[ "$actual_ids" == "$expected_ids" && "$upload_count" -eq "$expected_uploads" && \
    "$download_count" -eq "$expected_downloads" && "$definition_hash" == "$expected_hash" ]]
}

exact_workflow_file_inventory() {
  local -a entries=("$@")
  [[ "${#entries[@]}" -eq 2 && "${entries[0]:-}" == ci.yml:f && \
    "${entries[1]:-}" == scheduled.yml:f ]]
}

exact_scheduled_validation_step() {
  local block="$1" name="$2" lane="$3" shell="${4:--}" step expected
  step="$(step_block "$block" "$name")" || return 1
  if [[ "$lane" == source-scan ]]; then
    expected="$(printf '%s\n' \
      "      - name: $name" \
      '        id: artifacts' \
      "        if: \${{ !cancelled() }}" \
      '        env:' \
      "          EXPECTED_COMMIT: \${{ github.sha }}" \
      '        run: |' \
      "          bash ops/ci/artifact-check.sh source-scan \"\$EXPECTED_COMMIT\"" \
      "          echo \"observation=present\" >> \"\$GITHUB_OUTPUT\"")"
  elif [[ "$shell" == - ]]; then
    expected="$(printf '%s\n' \
      "      - name: $name" \
      "        if: \${{ !cancelled() }}" \
      '        env:' \
      "          EXPECTED_COMMIT: \${{ github.sha }}" \
      "        run: bash ops/ci/artifact-check.sh $lane \"\$EXPECTED_COMMIT\"")"
  else
    expected="$(printf '%s\n' \
      "      - name: $name" \
      "        if: \${{ !cancelled() }}" \
      "        shell: $shell" \
      '        env:' \
      "          EXPECTED_COMMIT: \${{ github.sha }}" \
      "        run: bash ops/ci/artifact-check.sh $lane \"\$EXPECTED_COMMIT\"")"
  fi
  [[ "$step" == "$expected" ]]
}

for workflow in "$required" "$scheduled"; do
  grep -Eq 'runs-on: (ubuntu-24.04|macos-15|windows-2025)' "$workflow"
  if grep -Eq 'ubuntu-latest|pull_request_target|continue-on-error|secrets\.|permissions:.*write|uses:.*cache|rust-cache' "$workflow"; then
    printf '[ci] FORBIDDEN_WORKFLOW_CONTROL: %s\n' "$workflow" >&2
    exit 1
  fi
  if grep -Eq '^defaults:|^    defaults:|^[[:space:]]+(BASH_ENV|ENV|PATH):' "$workflow"; then
    printf '[ci] HOSTED_EXECUTION_ENVIRONMENT_FORBIDDEN: %s\n' "$workflow" >&2
    exit 1
  fi
  if grep -Eq '^[[:space:]]+paths(-ignore)?:' "$workflow"; then
    printf '[ci] PATH_FILTERED_REQUIRED_WORKFLOW: %s\n' "$workflow" >&2
    exit 1
  fi
  while IFS= read -r use; do
    [[ "$use" =~ @[0-9a-f]{40}([[:space:]]*#.*)?$ ]] || {
      printf '[ci] ACTION_NOT_PINNED_TO_SHA: %s: %s\n' "$workflow" "$use" >&2
      exit 1
    }
  done < <(grep -E '^[[:space:]]+- uses:' "$workflow")
  checkout_count="$(grep -c 'uses: actions/checkout@' "$workflow")"
  credential_count="$(grep -c 'persist-credentials: false' "$workflow")"
  [[ "$checkout_count" -eq "$credential_count" ]] || {
    printf '[ci] CHECKOUT_CREDENTIAL_POLICY_DRIFT: %s\n' "$workflow" >&2
    exit 1
  }
done

workflow_file_inventory=()
while IFS= read -r -d '' entry; do
  workflow_file_inventory+=("$entry")
done < <(find .github/workflows -mindepth 1 -maxdepth 1 -printf '%f:%y\0' | sort -z)
exact_workflow_file_inventory "${workflow_file_inventory[@]}" || {
  echo '[ci] WORKFLOW_FILE_INVENTORY_DRIFT' >&2
  exit 1
}
required_definition="$(<"$required")"
scheduled_definition="$(<"$scheduled")"
required_job_ids=$'source_scan\nfast\nlint\ncontract\nsecurity\ndocs\nrequired'
scheduled_job_ids=$'source_scan\nhistory\nlinks\nadvisory\ncoverage\nmacos\nwindows\naudit'
required_workflow_hash=aab8fea7656420a66897aef2eca86362dc7d04fcc81b12354f222f14f5b3d737
scheduled_workflow_hash=74d2f0e3a174ca1e90c98083518d1eebc862493d68ebce391b79e44442b2cf5d
exact_workflow_inventory "$required_definition" "$required_job_ids" 6 1 "$required_workflow_hash" || {
  echo '[ci] REQUIRED_WORKFLOW_INVENTORY_DRIFT' >&2
  exit 1
}
exact_workflow_inventory "$scheduled_definition" "$scheduled_job_ids" 8 0 "$scheduled_workflow_hash" || {
  echo '[ci] SCHEDULED_WORKFLOW_INVENTORY_DRIFT' >&2
  exit 1
}

grep -q '^name: CI$' "$required"
grep -q '^  merge_group:$' "$required"
grep -Fq "cancel-in-progress: \${{ github.event_name == 'pull_request' }}" "$required"
grep -q '^    name: required$' "$required"
grep -Fq "if: \${{ always() }}" "$required"
grep -Eq 'uses: actions/download-artifact@[0-9a-f]{40}' "$required"
grep -Fq "EXPECTED_COMMIT: \${{ github.sha }}" "$required"
grep -Fq "pattern: bullet-git-*-\${{ github.run_id }}-\${{ github.run_attempt }}" "$required"
[[ "$(grep -c 'name: bullet-git-.*github.run_id.*github.run_attempt' "$required")" -eq 6 ]] || {
  echo '[ci] RUN_BOUND_ARTIFACT_NAME_DRIFT' >&2
  exit 1
}
if grep -q 'needs\..*outputs\.observation' "$required"; then
  echo '[ci] UNVERIFIED_OUTPUT_AGGREGATION' >&2
  exit 1
fi

main_jobs=(source_scan fast lint contract security docs)
declare -A main_lanes lane_steps validation_steps upload_steps
main_lanes[source_scan]=source-scan; lane_steps[source_scan]='Scan source and lockfiles before dependency installation'
main_lanes[fast]=fast; lane_steps[fast]='Run fast lane'
main_lanes[lint]=lint; lane_steps[lint]='Run lint lane'
main_lanes[contract]=contract; lane_steps[contract]='Run contract lane'
main_lanes[security]=security; lane_steps[security]='Run security lane'
main_lanes[docs]=docs; lane_steps[docs]='Run docs lane'
validation_steps[source_scan]='Validate sanitized observation'
validation_steps[fast]='Validate sanitized JUnit and observation'
validation_steps[lint]='Validate sanitized observation'
validation_steps[contract]='Validate sanitized JUnit and observation'
validation_steps[security]='Validate sanitized observation'
validation_steps[docs]='Validate sanitized observation'
upload_steps[source_scan]='Upload source-scan observation'
upload_steps[fast]='Upload fast diagnostics'
upload_steps[lint]='Upload lint observation'
upload_steps[contract]='Upload contract diagnostics'
upload_steps[security]='Upload security observation'
upload_steps[docs]='Upload docs observation'

validate_main_job() {
  local job="$1" block="$2" lane
  lane="${main_lanes[$job]}"
  ! grep -Eq '^    defaults:|^[[:space:]]+(BASH_ENV|ENV|PATH):' <<<"$block" || return 1
  exact_scalar_step "$block" "${lane_steps[$job]}" "bash scripts/ci-local.sh $lane" || return 1
  exact_validation_step "$block" "${validation_steps[$job]}" "$lane" || return 1
  exact_stage_step "$block" "$lane" || return 1
  exact_upload_step "$block" "${upload_steps[$job]}" \
    "bullet-git-$lane-\${{ github.run_id }}-\${{ github.run_attempt }}" \
    "target/ci-upload/$lane/" || return 1
  [[ "$(grep -c 'uses: actions/upload-artifact@' <<<"$block")" -eq 1 ]] || return 1
  if [[ "$job" == source_scan ]]; then
    ! grep -Eq '^    needs:' <<<"$block" || return 1
  else
    grep -Fqx '    needs: source_scan' <<<"$block" || return 1
  fi
}

for job in "${main_jobs[@]}"; do
  block="$(job_block "$required" "$job")"
  validate_main_job "$job" "$block" || {
    printf '[ci] HOSTED_JOB_CONTRACT_INVALID: %s\n' "$job" >&2
    exit 1
  }
done

required_block="$(job_block "$required" required)"
grep -Fqx '    needs: [source_scan, fast, lint, contract, security, docs]' <<<"$required_block"
grep -Fqx "    if: \${{ always() }}" <<<"$required_block"
exact_required_download_step "$required_block"
exact_required_convergence_step "$required_block"
[[ "$(grep -c 'uses: actions/download-artifact@' <<<"$required_block")" -eq 1 ]]

scheduled_jobs=(source_scan history links advisory coverage macos windows)
declare -A scheduled_lanes scheduled_lane_steps scheduled_validation_steps scheduled_upload_steps scheduled_names
scheduled_lanes[source_scan]=source-scan; scheduled_lane_steps[source_scan]='Scan current source and lockfiles'; scheduled_validation_steps[source_scan]='Validate sanitized observation'; scheduled_upload_steps[source_scan]='Upload source-scan observation'; scheduled_names[source_scan]='bullet-git-scheduled-source-scan'
scheduled_lanes[history]=history; scheduled_lane_steps[history]='Scan complete Git history'; scheduled_validation_steps[history]='Validate sanitized observation'; scheduled_upload_steps[history]='Upload history observation'; scheduled_names[history]='bullet-git-history'
scheduled_lanes[links]=links; scheduled_lane_steps[links]='Check external links'; scheduled_validation_steps[links]='Validate sanitized observation'; scheduled_upload_steps[links]='Upload link observation'; scheduled_names[links]='bullet-git-links'
scheduled_lanes[advisory]=advisory; scheduled_lane_steps[advisory]='Refresh and scan RustSec advisories'; scheduled_validation_steps[advisory]='Validate sanitized observation'; scheduled_upload_steps[advisory]='Upload advisory observation'; scheduled_names[advisory]='bullet-git-advisory'
scheduled_lanes[coverage]=coverage; scheduled_lane_steps[coverage]='Generate LCOV report'; scheduled_validation_steps[coverage]='Validate sanitized coverage artifact'; scheduled_upload_steps[coverage]='Upload coverage diagnostic'; scheduled_names[coverage]='bullet-git-coverage'
scheduled_lanes[macos]=platform; scheduled_lane_steps[macos]='Compile and prove typed mutation refusal'; scheduled_validation_steps[macos]='Validate sanitized observation'; scheduled_upload_steps[macos]='Upload macOS observation'; scheduled_names[macos]='bullet-git-macos-refusal'
scheduled_lanes[windows]=platform; scheduled_lane_steps[windows]='Compile and prove typed mutation refusal'; scheduled_validation_steps[windows]='Validate sanitized observation'; scheduled_upload_steps[windows]='Upload Windows observation'; scheduled_names[windows]='bullet-git-windows-refusal'
for job in "${scheduled_jobs[@]}"; do
  block="$(job_block "$scheduled" "$job")"
  shell=-
  [[ "$job" == macos || "$job" == windows ]] && shell=bash
  exact_scalar_step "$block" "${scheduled_lane_steps[$job]}" \
    "bash scripts/ci-local.sh ${scheduled_lanes[$job]}" "$shell" || {
    printf '[ci] SCHEDULED_LANE_EXECUTION_DRIFT: %s\n' "$job" >&2
    exit 1
  }
  exact_scheduled_validation_step "$block" "${scheduled_validation_steps[$job]}" \
    "${scheduled_lanes[$job]}" "$shell" || exit 1
  exact_stage_step "$block" "${scheduled_lanes[$job]}" "$shell" || exit 1
  exact_upload_step "$block" "${scheduled_upload_steps[$job]}" \
    "${scheduled_names[$job]}" "target/ci-upload/${scheduled_lanes[$job]}/" || {
    printf '[ci] SCHEDULED_UPLOAD_ALLOWLIST_DRIFT: %s\n' "$job" >&2
    exit 1
  }
  [[ "$(grep -c 'uses: actions/upload-artifact@' <<<"$block")" -eq 1 ]] || exit 1
  if [[ "$job" != source_scan ]]; then
    grep -Fqx '    needs: source_scan' <<<"$block" || exit 1
  fi
done

coverage_block="$(job_block "$scheduled" coverage)"
failed_stage_upload="${coverage_block/"        if: \${{ !cancelled() && steps.stage.outcome == 'success' }}"/"        if: \${{ !cancelled() }}"}"
if exact_upload_step "$failed_stage_upload" "${scheduled_upload_steps[coverage]}" \
  "${scheduled_names[coverage]}" 'target/ci-upload/coverage/'; then
  echo '[ci] FAILED_SCHEDULED_STAGE_UPLOAD_ACCEPTED' >&2
  exit 1
fi

# Hosted audit job: the whole job is exact. Neutral only through the typed 78
# auditor refusal, an unconditional lane, and an upload only a green lane reaches.
expected_audit_job() {
  printf '%s\n' \
    '  audit:' \
    '    name: Jankurai audit' \
    '    needs: source_scan' \
    '    runs-on: ubuntu-24.04' \
    '    timeout-minutes: 15' \
    '    steps:' \
    '      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2' \
    '        with:' \
    '          persist-credentials: false' \
    '      - name: Resolve the pinned auditor or refuse neutral' \
    '        run: |' \
    '          command -v jankurai >/dev/null 2>&1 || {' \
    '            echo "::error::AUDITOR_UNAVAILABLE_HOSTED: jankurai 1.6.11 is a machine-local build with no checksum-pinned hosted artifact; the audit lane did not run"' \
    '            exit 78' \
    '          }' \
    '      - name: Run audit lane' \
    '        id: lane' \
    '        run: bash scripts/ci-local.sh audit' \
    '      - name: Upload audit observation' \
    "        if: \${{ !cancelled() && steps.lane.outcome == 'success' }}" \
    '        uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2' \
    '        with:' \
    '          name: bullet-git-audit' \
    '          path: .ci-artifacts/observations/audit.json' \
    '          include-hidden-files: true' \
    '          if-no-files-found: error' \
    '          retention-days: 14'
}
validate_audit_job() { [[ "$1" == "$(expected_audit_job)" ]]; }
audit_block="$(job_block "$scheduled" audit)"
validate_audit_job "$audit_block" || { echo '[ci] SCHEDULED_AUDIT_JOB_CONTRACT_INVALID' >&2; exit 1; }
expect_audit_rejection() {
  validate_audit_job "$1" >/dev/null 2>&1 || return 0
  printf '[ci] %s\n' "$2" >&2
  exit 1
}
expect_audit_rejection "${audit_block/'            exit 78'/'            exit 0'}" GREEN_AUDITOR_NEUTRAL_ACCEPTED
expect_audit_rejection "${audit_block/'::error::AUDITOR_UNAVAILABLE_HOSTED'/'::warning::AUDITOR_UNAVAILABLE_HOSTED'}" UNTYPED_AUDITOR_NEUTRAL_ACCEPTED
expect_audit_rejection "${audit_block/'        run: bash scripts/ci-local.sh audit'/'        run: true # run: bash scripts/ci-local.sh audit'}" COMMENTED_NOOP_AUDIT_LANE_ACCEPTED
expect_audit_rejection "${audit_block/'        run: bash scripts/ci-local.sh audit'/$'        if: ${{ always() }}\n        run: bash scripts/ci-local.sh audit'}" CONDITIONAL_AUDIT_LANE_ACCEPTED
expect_audit_rejection "${audit_block/"        if: \${{ !cancelled() && steps.lane.outcome == 'success' }}"/"        if: \${{ !cancelled() }}"}" FAILED_AUDIT_LANE_UPLOAD_ACCEPTED
expect_audit_rejection "${audit_block/'          path: .ci-artifacts/observations/audit.json'/'          path: .ci-artifacts/'}" HOSTILE_AUDIT_UPLOAD_PATH_ACCEPTED

# Mutation proofs: surviving command text in a comment is not execution, and
# upload paths are an allowlist rather than an expanding broad-root denylist.
fast_block="$(job_block "$required" fast)"
expect_main_rejection() {
  local candidate="$1" code="$2" status
  status=0
  ( set +e; validate_main_job fast "$candidate" >/dev/null 2>&1 ) || status=$?
  [[ "$status" -ne 0 ]] || { printf '[ci] %s\n' "$code" >&2; exit 1; }
}
noop_block="${fast_block/'        run: bash scripts/ci-local.sh fast'/'        run: true # run: bash scripts/ci-local.sh fast'}"
expect_main_rejection "$noop_block" COMMENTED_NOOP_LANE_ACCEPTED
skipped_block="${fast_block/'        run: bash scripts/ci-local.sh fast'/$'        if: ${{ false }}\n        run: bash scripts/ci-local.sh fast'}"
expect_main_rejection "$skipped_block" SKIPPED_LANE_ACCEPTED
custom_shell_block="${fast_block/'        run: bash scripts/ci-local.sh fast'/$'        shell: bash -c '\''true'\'' {0}\n        run: bash scripts/ci-local.sh fast'}"
expect_main_rejection "$custom_shell_block" CUSTOM_SHELL_LANE_ACCEPTED
validator_line="          bash ops/ci/artifact-check.sh fast \"\$EXPECTED_COMMIT\""
forged_validator=$'          printf forged=true\n'"$validator_line"
extra_validator_block="${fast_block/"$validator_line"/"$forged_validator"}"
expect_main_rejection "$extra_validator_block" EXTRA_VALIDATOR_BODY_ACCEPTED
defaults_block="${fast_block/'    timeout-minutes: 15'/$'    timeout-minutes: 15\n    defaults:\n      run:\n        shell: bash -c '\''true'\'' {0}'}"
expect_main_rejection "$defaults_block" CUSTOM_DEFAULT_SHELL_ACCEPTED
for replacement in \
  '          path: "target/ci-upload/fast/"' \
  '          path: ./target/ci-upload/fast/' \
  '          path: target/ci-upload/fast/**' \
  $'          path: |\n            target/ci-upload/fast/\n            .ci-artifacts/'; do
  hostile="${fast_block/'          path: target/ci-upload/fast/'/$replacement}"
  expect_main_rejection "$hostile" HOSTILE_UPLOAD_PATH_ACCEPTED
done
duplicate_upload_block="${fast_block/'      - name: Upload fast diagnostics'/$'      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02\n        with:\n          path: .ci-artifacts/\n      - name: Upload fast diagnostics'}"
expect_main_rejection "$duplicate_upload_block" DUPLICATE_UPLOAD_ACTION_ACCEPTED

expect_required_rejection() {
  local candidate="$1" code="$2"
  if exact_required_download_step "$candidate" && exact_required_convergence_step "$candidate"; then
    printf '[ci] %s\n' "$code" >&2
    exit 1
  fi
}
aggregate_line="          bash ops/ci/aggregate.sh .ci-artifacts/atomic \"\$EXPECTED_COMMIT\" \\"
noop_aggregate_line="          true # bash ops/ci/aggregate.sh .ci-artifacts/atomic \"\$EXPECTED_COMMIT\" \\"
noop_required_block="${required_block/"$aggregate_line"/"$noop_aggregate_line"}"
expect_required_rejection "$noop_required_block" COMMENTED_NOOP_CONVERGENCE_ACCEPTED
custom_required_shell="${required_block/'        run: |'/$'        shell: bash -c '\''true'\'' {0}\n        run: |'}"
expect_required_rejection "$custom_required_shell" CUSTOM_SHELL_CONVERGENCE_ACCEPTED

broad_upload_job=$'\n  broad-upload:\n    runs-on: ubuntu-24.04\n    steps:\n      - uses: actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2\n        with:\n          name: broad-root\n          path: .ci-artifacts/'
if exact_workflow_inventory "${required_definition}${broad_upload_job}" "$required_job_ids" 6 1 "$required_workflow_hash"; then
  echo '[ci] EXTRA_REQUIRED_BROAD_UPLOAD_JOB_ACCEPTED' >&2
  exit 1
fi
if exact_workflow_inventory "${scheduled_definition}${broad_upload_job}" "$scheduled_job_ids" 8 0 "$scheduled_workflow_hash"; then
  echo '[ci] EXTRA_SCHEDULED_BROAD_UPLOAD_JOB_ACCEPTED' >&2
  exit 1
fi
upload_marker='      - name: Upload fast diagnostics'
spaced_upload_step=$'      - uses : actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02 # v4.6.2\n        with:\n          name: hidden-broad-root\n          path: .ci-artifacts/'
spaced_upload_replacement="$spaced_upload_step"$'\n'"$upload_marker"
spaced_upload_definition="${required_definition/"$upload_marker"/"$spaced_upload_replacement"}"
if exact_workflow_inventory "$spaced_upload_definition" "$required_job_ids" 6 1 "$required_workflow_hash"; then
  echo '[ci] SPACED_USES_BROAD_UPLOAD_ACCEPTED' >&2
  exit 1
fi
escaped_upload_step=$'      - uses: "actions/upload-artifact\\u0040ea165f8d65b6e75b540449e92b4886f43607fa02"\n        with:\n          name: escaped-broad-root\n          path: .ci-artifacts/'
escaped_upload_replacement="$escaped_upload_step"$'\n'"$upload_marker"
escaped_upload_definition="${required_definition/"$upload_marker"/"$escaped_upload_replacement"}"
if exact_workflow_inventory "$escaped_upload_definition" "$required_job_ids" 6 1 "$required_workflow_hash"; then
  echo '[ci] ESCAPED_ACTION_BROAD_UPLOAD_ACCEPTED' >&2
  exit 1
fi
for hostile_entry in broad.yml:f broad.yaml:f .exfil.yml:f .exfil.yaml:f broad.yml:d broad.yaml:l; do
  candidate_inventory=("${workflow_file_inventory[@]}" "$hostile_entry")
  if exact_workflow_file_inventory "${candidate_inventory[@]}"; then
    echo '[ci] EXTRA_WORKFLOW_ENTRY_ACCEPTED' >&2
    exit 1
  fi
done
for hostile_type in l d; do
  if exact_workflow_file_inventory ci.yml:f "scheduled.yml:$hostile_type"; then
    echo '[ci] NON_REGULAR_WORKFLOW_ENTRY_ACCEPTED' >&2
    exit 1
  fi
done

# upload-artifact v4 uses a single file's parent as its root and therefore
# flattens observations/lint.json. A directory input preserves the subtree.
model_root="$(mktemp -d)"
trap 'rm -rf -- "$model_root"' EXIT
mkdir -p "$model_root/stage/observations"
touch "$model_root/stage/observations/lint.json"
single_entry="$(basename "$model_root/stage/observations/lint.json")"
directory_entry="${model_root}/stage/observations/lint.json"
directory_entry="${directory_entry#"$model_root/stage/"}"
[[ "$single_entry" == lint.json && "$directory_entry" == observations/lint.json ]] || {
  echo '[ci] UPLOAD_ROOT_MODEL_FAILED' >&2
  exit 1
}

grep -q 'toolchain: 1.97.1' "$required"
[[ "$(grep -c 'run: bash ops/ci/install-gitleaks.sh' "$required")" -eq 2 ]] || exit 1
grep -q 'runs-on: macos-15' "$scheduled"
grep -q 'runs-on: windows-2025' "$scheduled"
grep -q 'fetch-depth: 0' "$scheduled"
source_scan_line="$(grep -n -m1 '^[[:space:]]*bash scripts/ci-local.sh source-scan$' Justfile | cut -d: -f1)"
rustup_line="$(grep -n -m1 '^[[:space:]]*rustup component add rustfmt clippy$' Justfile | cut -d: -f1)"
cargo_fetch_line="$(grep -n -m1 '^[[:space:]]*cargo fetch --locked$' Justfile | cut -d: -f1)"
if (( source_scan_line >= rustup_line || source_scan_line >= cargo_fetch_line )); then
  echo '[ci] SETUP_SOURCE_SCAN_ORDER_DRIFT' >&2
  exit 1
fi
log "workflow policy: exact execution, source admission, staged layouts, and closed uploads passed"
