# Jankurai Standard Binding

ChangeId never authorizes integration. Only an exact CandidateId or integration
subject may satisfy proof or merge policy. No raw Git CLI in agent sandboxes.

The repository binding is this file plus `agent/standard-version.toml`,
`agent/owner-map.json`, `agent/test-map.json`, `agent/proof-lanes.toml`,
`agent/generated-zones.toml`, `agent/boundaries.toml`,
`agent/security-policy.toml`, `agent/tool-adoption.toml`, and
`agent/audit-policy.toml`.

Hard rules for this repository:

- Keep files small. Split before 500 LOC; prefer under 300.
- Do not hand-edit generated zones: `contracts/generated/rust/schema_bundle.rs`
  is hub-synced (`agent/generated-zones.toml`).
- Do not create Git worktrees.
- `bash scripts/ci-local.sh fast` and `bash scripts/ci-local.sh required` are the
  one-command validation lanes; every lane is declared in `agent/proof-lanes.toml`.
- Never skip-green: a missing tool, an exit 78 nightly, or an `UNKNOWN` result is
  never success (`ops/AGENTS.md`).
- `AUDIT_FLOOR` in `ops/ci/audit.sh` is an upward-only ratchet.

No ZYAL runbooks live here. A ZYAL v1 runbook is a `RUN_FOREVER` daemon
envelope; this component has no run-forever agent loop, so its proof surface is
`agent/proof-lanes.toml` and the `ops/ci/<lane>.sh` scripts instead. Do not add a
`.zyal` file to satisfy a checker.

Accepted audit exceptions are declared where the auditor reads them, never as a
silent suppression: `agent/audit-policy.toml` (`[dead_language] allow_terms`) and
inline `jankurai:allow <detector> reason=… expires=…` comments carrying an owner,
a reason, and an expiry.
