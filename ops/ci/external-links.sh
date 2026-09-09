#!/usr/bin/env bash
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"
require_tool curl || exit 1
mapfile -t links < <(bash ops/ci/check-links.sh --external)
[[ "${#links[@]}" -gt 0 ]] || { echo "[ci] EXTERNAL_LINK_INVENTORY_EMPTY" >&2; exit 1; }
failed=0
for url in "${links[@]}"; do
  if curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
    --retry 2 --retry-all-errors --max-time 30 --head --user-agent 'bullet-ci-link-check/1' "$url" >/dev/null; then
    continue
  fi
  if ! curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
    --retry 2 --retry-all-errors --max-time 30 --range 0-0 \
    --user-agent 'bullet-ci-link-check/1' --output /dev/null "$url"; then
    printf '[ci] EXTERNAL_LINK_UNREACHABLE: %s\n' "$url" >&2
    failed=1
  fi
done
[[ "$failed" -eq 0 ]] || exit 1
log "external links passed: ${#links[@]}"
