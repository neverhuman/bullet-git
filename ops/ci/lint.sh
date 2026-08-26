#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
log "lint lane: formatting, Clippy, CI meta-guards, and pinned source linters"
bash ops/ci/proof-custody-test.sh
bash ops/ci/local-parity-test.sh
bash ops/ci/test-partitions.sh
bash ops/ci/junit-test.sh
bash ops/ci/artifact-check-test.sh
bash ops/ci/aggregate-test.sh
bash ops/ci/workflow-policy-test.sh
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --manifest-path crates/bullet-git-workspace/fuzz/Cargo.toml -- --check
cargo clippy --locked --manifest-path crates/bullet-git-workspace/fuzz/Cargo.toml \
  --all-targets -- -D warnings
actionlint .github/workflows/*.yml
zizmor --offline --no-ignores --strict-collection .
find ops scripts tools -type f -name '*.sh' -print0 | xargs -0 shellcheck -x
shellcheck -x ops/git-hooks/pre-push
log "lint lane passed"
