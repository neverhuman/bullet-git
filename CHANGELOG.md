# Changelog

All notable changes to bullet-git are recorded here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project is
pre-release: there is no published version, tag, or artifact, and no released
heading may be added before the gates in `docs/release.md` hold with receipts.

## [Unreleased]

### Added

- Jankurai control plane for this component: `agent/proof-lanes.toml`,
  `agent/boundaries.toml`, `agent/security-policy.toml`,
  `agent/tool-adoption.toml`, and `agent/audit-policy.toml`.
- `tools/security-lane.sh`, the canonical security-lane adapter that delegates to
  `ops/ci/security.sh`.
- `docs/testing.md` (lanes, artifacts, repair routing, budgets and stop
  conditions) and `docs/release.md` (fail-closed release contract).
- The audit lane now writes `.jankurai/repair-queue.jsonl` next to the score
  report and runs a full scan.

### Changed

- `agent/owner-map.json` and `agent/test-map.json` route every audited path,
  including gitignored lane output.
- Journal batch publication names its staging file `staging` rather than
  `temporary` (`crates/bullet-git-journal/src/storage.rs`); the on-disk protocol,
  the hard-link publish, and the fsync order are unchanged.

### Removed

- `agent/zyal/`: a ZYAL v1 runbook is a `RUN_FOREVER` daemon envelope and this
  component has no run-forever agent loop, so the stub was not a runbook.

[Unreleased]: https://github.com/bullet-farm/bullet-git
