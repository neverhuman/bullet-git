#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
lane="${1:-all}"
case "$lane" in
  required|fast|gates|all) bash ops/ci/fast.sh ;;
  *) echo "usage: $0 {required|fast|all}" >&2; exit 2 ;;
esac
