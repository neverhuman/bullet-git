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
just fast
```

Run `just setup` once only if this checkout has not had dependencies prepared.

## Readiness

This repository currently proves component primitives: private reflink-or-bounded-copy clones, scoped writes
and deletes, exact Candidates, journals, preservation checks, daemon protocol behavior, and a
Rust-owned reflink-or-byte-copy materialization path. Its legacy authority token is not a signed production
grant. `CandidateProvenance` and `CandidateManifest` require exact environment and toolchain
digests plus ordered parent-Candidate lineage; the full manifest binds `CandidateId`, and
`ProofRoot` binds that Candidate plus its Change/parent lineage. `PrivateClone::create` uses the
Rust-owned materializer. The workspace manifest records whether it used `reflink` or `fallback`; both paths create a
remote-free store with no alternates and are verified by checkout plus strict `git fsck` before publication.

The schema-1 `PatchProposal` wire validator and workspace execution policy share one fixed contract:
at most 128 unique changed paths, 1 MiB per replacement body, and 32 MiB of replacement content in
aggregate. Oversized proposals are refused by the typed wire validator before workspace mutation.

There is no five-plane transaction receipt or production-readiness claim here. Protected refs,
checks, integration, and observation remain forge/control-plane responsibilities and are not
simulated inside BulletGit.

## Lanes

| Lane | Command | Contents |
| --- | --- | --- |
| source-scan | `bash scripts/ci-local.sh source-scan` | gitleaks 8.21.2 admission over current source and lockfiles before dependency installation |
| fast | `just fast` | exactly 43 types/journal cases through the nextest `fast` profile; nonzero assertion and sanitized JUnit |
| lint | `just lint` | formatting, strict Clippy, actionlint 1.7.8, zizmor 1.25.2, ShellCheck 0.10.0, and CI/inventory meta-guards |
| contract | `just contract` | exactly 126 workspace/daemon cases through the nextest `contract` profile, including real local Git suites and the daemon round trip |
| security | `just security` | secret-shaped detector canary; fresh RustSec database; `cargo deny --locked check licenses advisories bans sources` against committed policy |
| docs | `just docs` | relative Markdown links, warning-denied rustdoc, and doctests |
| required | `just check` | source admission followed by fast, lint, contract, security, and docs sequentially, exactly once |
| audit | `bash ops/ci/audit.sh` | Jankurai audit against the executable upward-only wrapper floor (`AUDIT_FLOOR=65`); artifacts under `.jankurai/` |
| nightly | `bash ops/ci/nightly.sh` | explicit local entrypoint for a future live `jeryu-gitd` oracle: with `BULLET_LIVE_GITD` unset it logs that no live gitd lane is registered and exits 78 (unregistered, not success); with it set it exits 1 because no oracle adapter is registered; no hosted schedule exists |
| toolchain-msrv | `just toolchain-msrv` | builds and tests the whole workspace under rustup toolchain 1.95.0, the family MSRV named by the Hub release contract, while `rust-toolchain.toml`, `scripts/ci-doctor.sh`, and hosted CI stay pinned to 1.97.1. Runs the exact receipt argv from the Hub MSRV schema (`cargo build --workspace --all-targets --locked`, then `cargo test --workspace --all-targets --locked --no-fail-fast`, with `CARGO_INCREMENTAL=0`, `CARGO_NET_OFFLINE=true`, `RUSTC=<absolute 1.95.0 rustc>`, `RUSTUP_TOOLCHAIN=1.95.0`) in the isolated `target/toolchain-1.95.0/`, then writes the ignored machine-local observation `.bullet-family/toolchain-1.95.0-bullet-git.json` beside its two raw output logs. A missing rustup toolchain, `b3sum` 1.8.2, or `jq` is a typed refusal (exit 1), never a skip; a red build or test fails the lane after the observation is written. Compile and test only: no fmt or clippy. The observation is an input for a future operator-signed `release.rust-msrv-1-95` receipt, never itself a receipt |

`.github/workflows/ci.yml` runs source admission first, then the five atomic
lanes in parallel, and converges their exact-run observations and sanitized
reports at `CI / required`; it never reruns the local `required` wrapper.
Hosted tools pin rustc 1.97.1, cargo-nextest 0.9.137, cargo-deny 0.19.8,
gitleaks 8.21.2, actionlint 1.7.8, zizmor 1.25.2, and ShellCheck 0.10.0.
Audit, nightly, and `toolchain-msrv` remain local-only lanes. Local runners use
`scripts/ci-doctor.sh <lane>` for exact tool admission. Lane rules are in
[`ops/AGENTS.md`](ops/AGENTS.md).
