#!/usr/bin/env bash
set -euo pipefail
: "${RUNNER_TEMP:?RUNNER_TEMP is required}"
: "${GITHUB_PATH:?GITHUB_PATH is required}"
version=8.21.2
sha256=5bc41815076e6ed6ef8fbecc9d9b75bcae31f39029ceb55da08086315316e3ba
archive="$RUNNER_TEMP/gitleaks_${version}_linux_x64.tar.gz"
tools="$RUNNER_TEMP/bullet-tools-gitleaks"
curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
  "https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_x64.tar.gz" --output "$archive"
printf '%s  %s\n' "$sha256" "$archive" | sha256sum --check --status
mkdir -p "$tools"
tar -xzf "$archive" -C "$tools" gitleaks
printf '%s\n' "$tools" >>"$GITHUB_PATH"
