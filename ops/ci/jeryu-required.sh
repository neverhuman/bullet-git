#!/usr/bin/env bash
set -euo pipefail

echo '[ci] JERYU_STATUS_BINDING_UNRATIFIED: ci.toml cannot converge predecessor outcomes until forge and runner admission are ratified' >&2
exit 78
