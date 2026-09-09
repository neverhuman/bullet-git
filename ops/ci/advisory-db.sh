#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
require_tool cargo-deny || exit 1
require_tool git || exit 1
cargo deny fetch db
advisory_db_max_age_days=14
advisory_db=''
for candidate in target/advisory-db/advisory-db-*; do
  [[ -d "$candidate/.git" ]] || continue
  advisory_db="$candidate"
  break
done
[[ -n "$advisory_db" ]] || { echo "[ci] ADVISORY_DB_ABSENT: no advisory database under target/advisory-db" >&2; exit 1; }
advisory_db_commit="$(git -C "$advisory_db" log -1 --format=%ct)" || {
  echo "[ci] ADVISORY_DB_UNREADABLE: $advisory_db has no readable git history" >&2
  exit 1
}
advisory_db_age_days=$(( ( $(date -u +%s) - advisory_db_commit ) / 86400 ))
(( advisory_db_age_days <= advisory_db_max_age_days )) || {
  printf '[ci] ADVISORY_DB_STALE: %s newest commit is %sd old, limit %sd\n' \
    "$advisory_db" "$advisory_db_age_days" "$advisory_db_max_age_days" >&2
  exit 1
}
log "advisory database admitted at ${advisory_db_age_days}d old"
