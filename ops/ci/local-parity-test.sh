#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

controls=(
  scripts/ci-doctor.sh
  scripts/ci-local.sh
  scripts/ci-observation.sh
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
[[ "$ci_config" == *'run = ["bash ops/ci/jeryu-required.sh"]'* ]]
[[ "$ci_config" != *'aggregate.sh success present'* ]]
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
for tool in cargo cargo-nextest jq rustc; do
  [[ "$missing_output" == *"ci-doctor: missing $tool for fast"* ]] || {
    printf '[ci] doctor did not report missing %s\n' "$tool" >&2
    exit 1
  }
done

log "local parity controls passed"
