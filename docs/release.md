# Release contract

Status: **no release exists; every release gate is BLOCKED**
Owner: bullet-git maintainers (`agent/owner-map.json`)
Last reviewed: 2026-08-25
Applies to: bullet-git

This page is a fail-closed contract, not a plan of record. Nothing in this
repository has been released, and no lane in `ops/ci/` may publish, tag, mirror,
sign, or otherwise mutate forge state. A green component lane is never a release.

## Version source

`agent/standard-version.toml` binds the standard, paper, auditor, and schema
versions this component claims. Crate versions live in `Cargo.toml` and the
locked graph in `Cargo.lock`; every lane runs `--locked`. There is no published
crate, tag, or artifact, so there is no version to consume yet.

## Change record

`CHANGELOG.md` carries the unreleased change record. It may never gain a released
version heading before the gates below hold with receipts.

## Launch gate inventory

A release gate closes only with an artifact-backed receipt from an independent
checker. Today every gate is BLOCKED, and the honest status of each is:

| Release gate | Required evidence | Status |
| --- | --- | --- |
| Frozen authority contract | operator-published frozen contract and verified lock; the component Kernel checker exists, but an unconfigured daemon refuses `clone` with `AUTHORITY_CONTRACT_UNAVAILABLE` and no signed immutable release subject or live authority receipt exists | BLOCKED: no operator contract exists |
| Component proof | `bash scripts/ci-local.sh required` plus the contract lane green on the release commit | available locally, not release evidence on its own |
| Conformance score | `bash ops/ci/audit.sh` at or above the `AUDIT_FLOOR` ratchet | local gate only; the pinned auditor is a machine-local build and is not registered in hosted CI |
| Secret and dependency scan | `bash scripts/ci-local.sh security` (`gitleaks detect`, `cargo deny check bans`) | runs; no release artifact is produced |
| Integrity and provenance | checksums, signatures, and SBOM for a published artifact | BLOCKED: nothing is built for publication, so nothing is signed |
| Backup and restore | the CAS plus the append-only journal are the durable record; a restore drill against a real repository | BLOCKED: no drill has been run |
| Rollback | immutable workspace generations with one durable active-pointer switch, sealed preservation receipts, receipt-gated cleanup, and receipt-bound tombstones (`crates/bullet-git-workspace/src/{generation,cas,preservation}.rs`) | implemented in code, unproven as a release procedure |
| Monitoring | typed reason codes and the fsynced JSONL mutation ledger (`crates/bullet-gitd/src/mutation_ledger.rs`); an in-flight reservation that survives restart is `MUTATION_OUTCOME_UNKNOWN` and freezes further mutation | no telemetry pipeline, dashboard, or alert exists |
| Abuse and rate limits | bounded stdio frames refused before JSON parsing, scope enforcement, and no forge-facing or public network surface; the only current transport is the peer-authenticated local Kernel UDS | no forge-facing surface exists to rate limit yet |
| Live oracle | a versioned `jeryu-gitd` from a separately reviewed immutable Jeryu tag | BLOCKED: `ops/ci/nightly.sh` exits 78 (unregistered) and never green |

## Rules

- Release builds depend on immutable tags, not branches. No local tag, copied
  source, or positive test checker may stand in for the operator-published
  frozen contract (`SPLIT.md`, `docs/architecture.md`).
- Lanes never publish, mirror, tag, push, or touch Jeryu.
- A skipped, missing, unsupported, flaky, or `UNKNOWN` result is never success,
  and exit 78 is not green (`docs/testing.md`).
