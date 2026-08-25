#!/usr/bin/env bash
set -euo pipefail

lane="${1:-all}"
case "$lane" in
  fast) tools=(bash cargo cargo-nextest dirname rustc rustfmt) ;;
  required) tools=(bash cargo cargo-clippy cargo-nextest dirname rustc rustfmt) ;;
  contract) tools=(bash cargo cargo-nextest dirname rustc) ;;
  security) tools=(bash cargo cargo-deny dirname git gitleaks zizmor) ;;
  audit) tools=(bash dirname jankurai mkdir) ;;
  nightly) tools=(bash dirname) ;;
  toolchain-msrv) tools=(b3sum bash cargo dirname git jq rustc rustup) ;;
  all) tools=(bash cargo cargo-clippy cargo-deny cargo-nextest dirname git gitleaks jankurai mkdir rustc rustfmt zizmor) ;;
  *) echo "ci-doctor: expected fast|required|contract|security|audit|nightly|toolchain-msrv|all" >&2; exit 2 ;;
esac

missing=0
for tool in "${tools[@]}"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'ci-doctor: missing %s for %s\n' "$tool" "$lane" >&2
    missing=1
  fi
done
[[ "$missing" -eq 0 ]] || exit 1

if [[ "$lane" == toolchain-msrv ]]; then
  # Lane-scoped admission only: the explicit MSRV lane may use rustup toolchain
  # 1.95.0 in addition to (never instead of) the repository pin.
  rust_version="$(rustc --version)"
  [[ "$rust_version" == "rustc 1.97.1 "* ]] || {
    printf 'ci-doctor: expected rustc 1.97.1, found %s\n' "$rust_version" >&2
    exit 1
  }
  export RUSTUP_AUTO_INSTALL=0
  rustup toolchain list | grep -q '^1\.95\.0-' || {
    echo "ci-doctor: expected rustup toolchain 1.95.0 for toolchain-msrv; run: rustup toolchain install 1.95.0 --profile minimal" >&2
    exit 1
  }
  msrv_version="$(rustup run 1.95.0 rustc --version)"
  [[ "$msrv_version" == "rustc 1.95.0 "* ]] || {
    printf 'ci-doctor: expected rustc 1.95.0 for toolchain-msrv, found %s\n' "$msrv_version" >&2
    exit 1
  }
  [[ "$(b3sum --version)" == "b3sum 1.8.2" ]] || {
    printf 'ci-doctor: expected b3sum 1.8.2, found %s\n' "$(b3sum --version)" >&2
    exit 1
  }
fi
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
  [[ "$(zizmor --version)" == "zizmor 1.25.2" ]] || {
    echo "ci-doctor: expected zizmor 1.25.2" >&2
    exit 1
  }
fi
printf 'ci-doctor: %s lane tools present\n' "$lane"
