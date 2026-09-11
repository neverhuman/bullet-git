#!/usr/bin/env bash
set -euo pipefail

lane="${1:-all}"
audit_run=""
if [[ $# -gt 1 ]]; then
  [[ $# -eq 3 && "$lane" == audit && "$2" == --audit-run ]] || {
    echo 'ci-doctor: only audit accepts --audit-run <dispatcher-owned-run>' >&2
    exit 2
  }
  audit_run="$3"
fi
case "$lane" in
  source-scan) tools=(bash dirname git gitleaks jq) ;;
  fast) tools=(bash cargo cargo-nextest cp dirname git jq rustc) ;;
  lint) tools=(actionlint bash cargo cargo-clippy cargo-nextest cmp comm dirname git jq mktemp python3 rustc rustfmt shellcheck sort zizmor) ;;
  contract) tools=(bash cargo cargo-nextest cp dirname git jq rustc) ;;
  security) tools=(bash cargo cargo-deny date dirname git gitleaks jq rustc) ;;
  docs) tools=(bash cargo dirname git jq readlink rustc) ;;
  required) tools=(actionlint bash cargo cargo-clippy cargo-deny cargo-nextest cmp comm cp date dirname git gitleaks jq mktemp python3 readlink rustc rustfmt shellcheck sort zizmor) ;;
  audit) tools=(bash cargo cat cmp cp cut dirname env git jankurai jq mkdir mktemp mv realpath rm rustc sha256sum sort stat sync) ;;
  audit-components) tools=(bash cargo cargo-nextest cat chmod cmp cp cut dirname env git jq just ln mkdir mktemp mv realpath rm rustc sha256sum sort stat sync uname) ;;
  nightly) tools=(bash dirname git jq) ;;
  history) tools=(bash dirname git gitleaks jq) ;;
  links) tools=(bash curl dirname git jq sort) ;;
  advisory) tools=(bash cargo cargo-deny date dirname git jq rustc) ;;
  coverage) tools=(bash cargo cargo-llvm-cov cargo-nextest dirname git jq rustc) ;;
  platform) tools=(awk bash cargo dirname git jq rustc) ;;
  toolchain-msrv) tools=(b3sum bash cargo dirname git jq rustc rustup) ;;
  all) tools=(actionlint bash cargo cargo-clippy cargo-deny cargo-nextest cmp comm cp date dirname git gitleaks jq mkdir mktemp python3 readlink rustc rustfmt shellcheck sort zizmor) ;;
  *)
    echo "ci-doctor: expected source-scan|fast|lint|contract|security|docs|required|audit|audit-components|nightly|history|links|advisory|coverage|platform|toolchain-msrv|all" >&2
    exit 2
    ;;
esac
tools+=(find id wc)

missing=0
for tool in "${tools[@]}"; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    printf 'ci-doctor: missing %s for %s\n' "$tool" "$lane" >&2
    missing=1
  fi
done
[[ "$missing" -eq 0 ]] || exit 1

if [[ "$lane" == audit-components ]]; then
  [[ "$(uname -s)" == Linux && "$(uname -m)" == x86_64 ]] || {
    echo 'ci-doctor: AUDIT_COMPONENT_PROFILE_UNAVAILABLE (local Linux x86_64 required)' >&2
    exit 75
  }
fi

if [[ "$lane" == toolchain-msrv ]]; then
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

if [[ "$lane" =~ ^(fast|lint|contract|security|docs|required|advisory|coverage|platform|audit-components|all)$ ]]; then
  rust_version="$(rustc --version)"
  [[ "$rust_version" == "rustc 1.97.1 "* ]] || {
    printf 'ci-doctor: expected rustc 1.97.1, found %s\n' "$rust_version" >&2
    exit 1
  }
fi
if [[ "$lane" =~ ^(fast|lint|contract|required|coverage|audit-components|all)$ ]]; then
  nextest_version="$(cargo-nextest --version)"
  [[ "$nextest_version" == "cargo-nextest 0.9.137 "* ]] || {
    printf 'ci-doctor: expected cargo-nextest 0.9.137, found %s\n' "$nextest_version" >&2
    exit 1
  }
fi
if [[ "$lane" =~ ^(source-scan|security|required|history|all)$ ]]; then
  [[ "$(gitleaks version)" == "8.21.2" ]] || {
    echo "ci-doctor: expected gitleaks 8.21.2" >&2
    exit 1
  }
fi
if [[ "$lane" =~ ^(security|required|advisory|all)$ ]]; then
  [[ "$(cargo-deny --version)" == "cargo-deny 0.19.8" ]] || {
    echo "ci-doctor: expected cargo-deny 0.19.8" >&2
    exit 1
  }
fi
if [[ "$lane" =~ ^(lint|required|all)$ ]]; then
  [[ "$(actionlint -version | head -n 1)" == "1.7.8" ]] || {
    echo "ci-doctor: expected actionlint 1.7.8" >&2
    exit 1
  }
  [[ "$(shellcheck --version | awk '/^version:/{print $2}')" == "0.10.0" ]] || {
    echo "ci-doctor: expected ShellCheck 0.10.0" >&2
    exit 1
  }
  [[ "$(zizmor --version)" == "zizmor 1.25.2" ]] || {
    echo "ci-doctor: expected zizmor 1.25.2" >&2
    exit 1
  }
fi
if [[ "$lane" == coverage ]]; then
  [[ "$(cargo llvm-cov --version)" == "cargo-llvm-cov 0.8.7" ]] || {
    echo "ci-doctor: expected cargo-llvm-cov 0.8.7" >&2
    exit 1
  }
fi
if [[ "$lane" == audit ]]; then
  # Only this local profile admits Jankurai; candidate code cannot run a version
  # probe until its exact reviewed bytes have been copied, verified and sealed.
  repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  if [[ -z "$audit_run" ]]; then
    echo 'ci-doctor: AUDIT_BOOTSTRAP_REQUIRED; run bash scripts/ci-local.sh audit' >&2
    exit 75
  fi
  expected="$repo_root/target/jankurai/audit-runs/"
    suffix="${audit_run#"$expected"}"
    [[ "$audit_run" == "$expected"* && "$suffix" =~ ^run\.[A-Za-z0-9]{8}$ \
      && -d "$audit_run" && ! -L "$audit_run" \
      && -f "$audit_run/invocation.json" && ! -L "$audit_run/invocation.json" ]] || exit 75
    [[ "$(find "$audit_run" -maxdepth 0 -type d -uid "$(id -u)" -perm 0700 -print)" == "$audit_run" \
      && "$(find "$audit_run/invocation.json" -maxdepth 0 -type f -uid "$(id -u)" -perm 0600 -print)" \
        == "$audit_run/invocation.json" ]] || exit 75
    jq -e --arg id "$suffix" --arg repository "$repo_root" --argjson pid "$PPID" '
      . == {schema:"bullet.audit-invocation.v1",id:$id,repository:$repository,
        origin:"dispatcher",parent_pid:$pid}
    ' "$audit_run/invocation.json" >/dev/null || exit 75
    record="$audit_run/doctor.tool.jsonl"
  printf 'ci-doctor: auditor evidence %s\n' "$record" >&2
  candidate="$(type -P jankurai)"
  # shellcheck source=ops/ci/jankurai-bootstrap.sh
  source "$repo_root/ops/ci/jankurai-bootstrap.sh"
  audit_binary="$(jankurai_bootstrap_resolve "$audit_run")" || exit 75
  "$audit_binary" --candidate "$candidate" --record "$record" -- --version
fi
printf 'ci-doctor: %s lane tools present\n' "$lane"
