#!/usr/bin/env bash
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

lane="${1:-}"
status="${2:-}"
shift 2 || true
[[ -n "$lane" && "$status" =~ ^[0-9]+$ && "$#" -gt 0 ]] || {
  echo "usage: $0 <lane> <exit-code> <command> [command ...]" >&2
  exit 2
}

outcome=FAIL
[[ "$status" -eq 0 ]] && outcome=PASS
commit_oid="$(git rev-parse HEAD)"
tree_oid="$(git rev-parse 'HEAD^{tree}')"
clean=true
[[ -z "$(git status --porcelain --untracked-files=normal)" ]] || clean=false
commands_json="$(printf '%s\n' "$@" | jq -R . | jq -s .)"
tool_versions='{}'

record_version() {
  local name="$1"
  shift
  local version
  command -v "$1" >/dev/null 2>&1 || return 0
  version="$("$@" 2>&1 | head -n 1 | tr -d '\r')"
  tool_versions="$(jq --arg name "$name" --arg version "$version" '. + {($name): $version}' <<<"$tool_versions")"
}

record_version bash bash --version
record_version cargo cargo --version
record_version rustc rustc --version
record_version git git --version
record_version cargo_nextest cargo-nextest --version
record_version gitleaks gitleaks version
record_version cargo_deny cargo-deny --version
record_version actionlint actionlint -version
record_version zizmor zizmor --version
if command -v shellcheck >/dev/null 2>&1; then
  shellcheck_version="$(shellcheck --version | awk '/^version:/{print $2}')"
  tool_versions="$(jq --arg version "$shellcheck_version" '. + {shellcheck: $version}' <<<"$tool_versions")"
fi
if command -v cargo-llvm-cov >/dev/null 2>&1; then
  llvm_cov_version="$(cargo llvm-cov --version)"
  tool_versions="$(jq --arg version "$llvm_cov_version" '. + {cargo_llvm_cov: $version}' <<<"$tool_versions")"
fi

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

artifact_hashes='[]'
if [[ -d .ci-artifacts/reports ]]; then
  while IFS= read -r file; do
    [[ -n "$file" ]] || continue
    artifact_name="$(basename "$file")"
    if [[ "$lane" == required ]]; then
      case "$artifact_name" in
        fast.junit.xml|contract.junit.xml) ;;
        *) continue ;;
      esac
    elif [[ "$artifact_name" != "$lane".* ]]; then
      continue
    fi
    relative="${file#./}"
    digest="$(sha256_file "$file")"
    artifact_hashes="$(jq --arg path "$relative" --arg sha256 "$digest" \
      '. + [{path: $path, sha256: $sha256}]' <<<"$artifact_hashes")"
  done < <(find .ci-artifacts/reports -maxdepth 1 -type f -print | LC_ALL=C sort)
fi

mkdir -p .ci-artifacts/observations
output=".ci-artifacts/observations/$lane.json"
temporary="$output.tmp.$$"
jq -n \
  --arg schema_version "bullet.ci-observation.v1" \
  --arg repository "bullet-git" \
  --arg commit_oid "$commit_oid" \
  --arg tree_oid "$tree_oid" \
  --argjson clean "$clean" \
  --argjson commands "$commands_json" \
  --argjson tool_versions "$tool_versions" \
  --arg lane "$lane" \
  --arg status "$outcome" \
  --argjson exit_code "$status" \
  --argjson artifact_hashes "$artifact_hashes" \
  '{schema_version: $schema_version, repository: $repository,
    commit_oid: $commit_oid, tree_oid: $tree_oid, clean: $clean,
    commands: $commands, tool_versions: $tool_versions,
    outcomes: [{lane: $lane, status: $status, exit_code: $exit_code}],
    artifact_hashes: $artifact_hashes, signed: false,
    evidence_class: "DIAGNOSTIC_ONLY"}' >"$temporary"
mv "$temporary" "$output"
printf 'ci-observation: wrote %s (%s, unsigned diagnostic only)\n' "$output" "$outcome"
