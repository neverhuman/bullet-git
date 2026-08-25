#!/usr/bin/env bash
# Canonical Jankurai security-lane adapter for bullet-git.
#
# It owns no commands of its own: it delegates to the single executable lane
# script, `ops/ci/security.sh`, which runs
#   gitleaks detect --source . --no-git --redact --no-banner
#   cargo deny check bans
# and fails closed when either pinned tool is missing (`ops/ci/lib.sh`
# `require_tool`). `bash scripts/ci-local.sh security`, `just security`, and the
# hosted security job call that same script, so this adapter can never drift into
# a second, weaker definition of the lane.
set -euo pipefail
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
exec bash "$repo_root/ops/ci/security.sh"
