#!/usr/bin/env bash
set -euo pipefail

lane="${1:-all}"
case "$lane" in
  fast) tools=(bash cargo cargo-nextest dirname rustc rustfmt) ;;
  required) tools=(bash cargo cargo-clippy cargo-nextest dirname rustc rustfmt) ;;
  contract) tools=(bash cargo cargo-nextest dirname rustc) ;;
  security) tools=(bash cargo-deny dirname gitleaks) ;;
  audit) tools=(bash dirname jankurai mkdir) ;;
  nightly) tools=(bash dirname) ;;
  all) tools=(bash cargo cargo-clippy cargo-deny cargo-nextest dirname gitleaks jankurai mkdir rustc rustfmt) ;;
  *) echo "ci-doctor: expected fast|required|contract|security|audit|nightly|all" >&2; exit 2 ;;
esac

missing=0
for tool in "${tools[@]}"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'ci-doctor: missing %s for %s\n' "$tool" "$lane" >&2
    missing=1
  fi
done
[[ "$missing" -eq 0 ]] || exit 1

if [[ "$lane" =~ ^(fast|required|contract|all)$ ]]; then
  rust_version="$(rustc --version)"
  [[ "$rust_version" == "rustc 1.97.1 "* ]] || {
    printf 'ci-doctor: expected rustc 1.97.1, found %s\n' "$rust_version" >&2
    exit 1
  }
  nextest_version="$(cargo-nextest --version)"
  [[ "$nextest_version" == "cargo-nextest 0.9.137 "* ]] || {
    printf 'ci-doctor: expected cargo-nextest 0.9.137, found %s\n' "$nextest_version" >&2
    exit 1
  }
fi
if [[ "$lane" == audit || "$lane" == all ]]; then
  jankurai_version="$(jankurai --version)"
  [[ "$jankurai_version" == "jankurai 1.6.11" ]] || {
    printf 'ci-doctor: expected jankurai 1.6.11, found %s\n' "$jankurai_version" >&2
    exit 1
  }
fi
if [[ "$lane" == security || "$lane" == all ]]; then
  [[ "$(gitleaks version)" == "8.21.2" ]] || {
    echo "ci-doctor: expected gitleaks 8.21.2" >&2
    exit 1
  }
  [[ "$(cargo-deny --version)" == "cargo-deny 0.19.8" ]] || {
    echo "ci-doctor: expected cargo-deny 0.19.8" >&2
    exit 1
  }
fi
printf 'ci-doctor: %s lane tools present\n' "$lane"
