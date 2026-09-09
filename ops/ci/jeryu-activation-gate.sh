#!/usr/bin/env bash
# Prepared Jeryu jobs stay inert until forge, runner, and protected-context
# authority are ratified and read back. Every job invokes this gate first so a
# direct dispatch cannot produce a misleading green local-lane observation.
set -euo pipefail
printf '%s\n' \
  '{"schema_version":"bullet.ci-activation-refusal.v1","code":"JERYU_CI_NOT_RATIFIED","status":"BLOCKED","exit_code":78,"release_authority":false}' >&2
exit 78
