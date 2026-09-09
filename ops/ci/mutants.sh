#!/usr/bin/env bash
# L-16a mutation baseline. --baseline proves the pinned examine list exists.
# This is not a mutation-score receipt; L-16b owns the threshold gate.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

baseline=0
for arg in "$@"; do
  case "$arg" in
    --baseline) baseline=1 ;;
    *)
      refuse USAGE "unknown mutants argument: $arg"
      exit 1
      ;;
  esac
done
if [[ "$baseline" -ne 1 ]]; then
  refuse USAGE "ops/ci/mutants.sh --baseline"
  exit 1
fi

[[ -f "$REPO_ROOT/mutants.toml" ]] \
  || { refuse MUTANTS_CONFIG_MISSING "mutants.toml is required for the baseline"; exit 1; }
grep -Eq '^examine[[:space:]]*=' "$REPO_ROOT/mutants.toml" \
  || { refuse MUTANTS_EXAMINE_MISSING "mutants.toml has no examine list"; exit 1; }
grep -Fq 'crates/bullet-git-types' "$REPO_ROOT/mutants.toml" \
  || { refuse MUTANTS_EXAMINE_MISSING "baseline must name crates/bullet-git-types"; exit 1; }

log "mutants baseline: config only; not a mutation-score receipt"
if command -v cargo-mutants >/dev/null 2>&1 || cargo mutants --version >/dev/null 2>&1; then
  cargo mutants --list --manifest-path "$REPO_ROOT/Cargo.toml" >/dev/null
fi
log "mutants baseline passed"
