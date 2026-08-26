#!/usr/bin/env bash
# Workspace line-coverage floor for the BulletGit coverage lane.
#
# Reads the LCOV report that ops/ci/coverage.sh writes
# (.ci-artifacts/reports/coverage.lcov) and refuses when measured line coverage
# (sum LH / sum LF over every source record) is below COVERAGE_LINE_FLOOR. The
# floor is a ratchet: it may only rise. It was introduced at measured-1
# (80.24 % lines on 2026-08-25 -> 79). A missing, symlinked, empty, truncated,
# or malformed report is a refusal, never a pass.
#
# The optional argument names another LCOV file and exists only so hostile
# fixtures can be proven; the coverage lane always calls this with no argument.
set -euo pipefail
# shellcheck source=ops/ci/lib.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
cd "$REPO_ROOT"

COVERAGE_LINE_FLOOR=79
report="${1:-.ci-artifacts/reports/coverage.lcov}"

refuse() { printf '[ci] %s: %s\n' "$1" "$2" >&2; return 1; }
require_tool awk || exit 1
[[ "$COVERAGE_LINE_FLOOR" =~ ^[0-9]+$ && "$COVERAGE_LINE_FLOOR" -le 100 ]] \
  || { refuse COVERAGE_FLOOR_INVALID "$COVERAGE_LINE_FLOOR"; exit 1; }
[[ -f "$report" && ! -L "$report" && -s "$report" ]] \
  || { refuse COVERAGE_ARTIFACT_MISSING "$report"; exit 1; }

# Strict LCOV walk: every record opens with SF:, carries exactly one integer LF
# and one integer LH with LH <= LF, and closes with end_of_record. Only the
# keys llvm-cov emits are admitted; any other line is a malformed report.
totals="$(awk '
  function fail(reason) { printf "INVALID %s (line %d)\n", reason, NR > "/dev/stderr"; exit 2 }
  /^TN:/ { next }
  /^SF:/ {
    if (in_record) fail("SF inside an open record")
    if ($0 == "SF:") fail("empty SF path")
    in_record = 1; lf_seen = 0; lh_seen = 0; lf = 0; lh = 0
    next
  }
  $0 == "end_of_record" {
    if (!in_record) fail("end_of_record without SF")
    if (!lf_seen || !lh_seen) fail("record without LF and LH")
    if (lh > lf) fail("LH exceeds LF")
    records++; total_lf += lf; total_lh += lh; in_record = 0
    next
  }
  /^LF:[0-9]+$/ { if (!in_record || lf_seen) fail("misplaced or duplicate LF"); lf = substr($0, 4) + 0; lf_seen = 1; next }
  /^LH:[0-9]+$/ { if (!in_record || lh_seen) fail("misplaced or duplicate LH"); lh = substr($0, 4) + 0; lh_seen = 1; next }
  /^(FN|FNDA|DA|BRDA):/ { if (!in_record) fail("detail line outside a record"); next }
  /^(FNF|FNH|BRF|BRH):[0-9]+$/ { if (!in_record) fail("counter outside a record"); next }
  { fail("unrecognised line") }
  END {
    if (in_record) fail("report ends inside an open record")
    if (records == 0) fail("no source records")
    if (total_lf == 0) fail("zero instrumented lines")
    printf "%d %d %d\n", records, total_lf, total_lh
  }
' "$report")" \
  || { refuse COVERAGE_ARTIFACT_INVALID "$report is not a well-formed LCOV report"; exit 1; }
read -r record_count line_count line_covered <<<"$totals"

measured="$(awk -v count="$line_count" -v covered="$line_covered" \
  'BEGIN { printf "%.2f", (covered * 100) / count }')"
log "workspace line coverage measured=${measured}% (${line_covered}/${line_count} lines, ${record_count} files) floor=${COVERAGE_LINE_FLOOR}%"
awk -v measured="$measured" -v floor="$COVERAGE_LINE_FLOOR" \
  'BEGIN { exit (measured + 0 >= floor + 0) ? 0 : 1 }' \
  || { refuse COVERAGE_BELOW_FLOOR "measured ${measured}% < floor ${COVERAGE_LINE_FLOOR}% lines"; exit 1; }
log "coverage floor passed"
