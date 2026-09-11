#!/usr/bin/env bash
# Local audit components, without an installed auditor or native audit claim.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/../.."
bash ops/ci/audit-test.sh
python3 -I -S ops/ci/jankurai-tool-test.py
python3 -I -S ops/ci/audit-observation-test.py
printf '[ci] audit components passed (local fixtures; installed auditor unqualified)\n'
