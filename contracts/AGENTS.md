# Contract boundary

Read the repository `AGENTS.md` first. This cell owns the Hub-synced
schema bundle listed in `agent/generated-zones.toml`.

- Owns: `contracts/generated/rust/schema_bundle.rs` after
  `bash ../bullet-farm/scripts/sync-family-contracts.sh`.
- Forbidden: hand-editing generated bindings, renaming wire vocabulary to
  silence auditors, or treating the bundle as an owned product module.
- Proof: `just contract` / `bash scripts/ci-local.sh contract`.
