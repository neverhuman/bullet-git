# bullet-git

Agent-first repository kernel for Bullet Farm. Agents start at [`AGENTS.md`](AGENTS.md).

```text
ChangeId     stable engineering intention (chg_ + 64 lowercase hex)
CandidateId  exact immutable implementation (can_ + 64 lowercase hex)
GitOid       ordinary Git object (sha1:<40> or sha256:<64> lowercase hex)
```

This crate family owns the change graph. `bullet-gitd` (this repo) is the
capability daemon and the sole workspace writer; pack protocol, refs, and
protected updates belong to the forge (Jeryu/GitHub). GitHub remains
ordinary Git.

See `docs/architecture.md` for the daemon protocol and trust model.

## Quick start

```bash
just setup
just fast
```

## Readiness

This repository currently proves component primitives: private dissociated clones, scoped writes
and deletes, exact Candidates, journals, preservation checks, and daemon protocol behavior. Its
legacy authority token is not a signed production grant. `Candidate` carries the spec §6.13
fields except `toolchain_digest`, but `lineage_subject` and `environment_digest` are not yet
populated by the daemon and do not bind `CandidateId` or `ProofRoot`, so these are not the
canonical transaction records.

There is no five-plane transaction receipt or production-readiness claim here. Protected refs,
checks, integration, and observation remain forge/control-plane responsibilities and are not
simulated inside BulletGit.

## Lanes

| Lane | Command | Contents |
| --- | --- | --- |
| fast | `just fast` | fmt check plus nextest `fast` profile |
| required | `just check` | local parity controls (`ops/ci/local-parity-test.sh`), fast, then clippy `-D warnings` |
| contract | `just contract` | nextest `contract` profile: real local Git suites and the daemon round trip, in-process |
| security | `just security` | gitleaks (no-git) plus `cargo deny check bans`; a missing tool fails |
| audit | `bash ops/ci/audit.sh` | Jankurai audit against a committed ratchet floor (`AUDIT_FLOOR=56`); artifacts under `.jankurai/` |
| nightly | `bash ops/ci/nightly.sh` | explicit local entrypoint for a future live `jeryu-gitd` oracle: with `BULLET_LIVE_GITD` unset it logs that no live gitd lane is registered and exits 78 (unregistered, not success); with it set it exits 1 because no oracle adapter is registered; no hosted schedule exists |

`.github/workflows/ci.yml` runs the fast, required, contract, and security
scripts unchanged with pinned rustc 1.97.1, cargo-nextest 0.9.137, cargo-deny
0.19.8, and gitleaks 8.21.2; audit and nightly are local-only lanes. Local
runners must provide `cargo-nextest`, `gitleaks`, `cargo-deny`, and
`jankurai`; `scripts/ci-doctor.sh <lane>` checks the pinned versions. Lane
rules are in [`ops/AGENTS.md`](ops/AGENTS.md).
