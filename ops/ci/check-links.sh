#!/usr/bin/env bash
set -euo pipefail

# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

if [[ "$#" -ne 1 ]]; then
  echo "usage: $0 --relative|--external" >&2
  exit 2
fi
mode="$1"
case "$mode" in
  --relative|--external) ;;
  *)
    echo "usage: $0 --relative|--external" >&2
    exit 2
    ;;
esac

emit_targets() {
  local relative_source source line remainder target
  while IFS= read -r -d '' relative_source; do
    source="$REPO_ROOT/$relative_source"
    while IFS= read -r line || [[ -n "$line" ]]; do
      remainder="$line"
      while [[ "$remainder" =~ \[[^][]*\]\(([^[:space:]\)]+) ]]; do
        target="${BASH_REMATCH[1]}"
        printf '%s\t%s\n' "$relative_source" "$target"
        remainder="${remainder#*"${BASH_REMATCH[0]}"}"
      done
      if [[ "$line" =~ ^[[:space:]]*\[[^][]+\]:[[:space:]]*([^[:space:]]+) ]]; then
        printf '%s\t%s\n' "$relative_source" "${BASH_REMATCH[1]}"
      fi
    done <"$source"
  done < <(git ls-files -z -- '*.md')
}

if [[ "$mode" == "--external" ]]; then
  while IFS=$'\t' read -r _source raw; do
    target="${raw#<}"
    target="${target%>}"
    case "$target" in
      http://*|https://*) printf '%s\n' "$target" ;;
    esac
  done < <(emit_targets) | sort -u
  exit 0
fi

checked=0
failures=0
while IFS=$'\t' read -r source raw; do
  target="${raw#<}"
  target="${target%>}"
  case "$target" in
    http://*|https://*|\#*) continue ;;
    *:*) continue ;;
  esac

  path="${target%%#*}"
  path="${path%%\?*}"
  [[ -n "$path" ]] || continue
  checked=$((checked + 1))
  if [[ "$path" == /* ]]; then
    candidate="$REPO_ROOT/${path#/}"
  else
    candidate="$REPO_ROOT/$(dirname "$source")/$path"
  fi

  if [[ ! -e "$candidate" ]]; then
    printf '%s: missing link target: %s\n' "$source" "$target" >&2
    failures=$((failures + 1))
    continue
  fi
  canonical="$(readlink -f -- "$candidate")"
  case "$canonical" in
    "$REPO_ROOT"|"$REPO_ROOT"/*) ;;
    *)
      printf '%s: link escapes repository: %s\n' "$source" "$target" >&2
      failures=$((failures + 1))
      ;;
  esac
done < <(emit_targets)

if [[ "$checked" -eq 0 ]]; then
  echo "[ci] RELATIVE_LINK_INVENTORY_EMPTY" >&2
  exit 1
fi
[[ "$failures" -eq 0 ]] || exit 1
log "relative links passed: $checked"
