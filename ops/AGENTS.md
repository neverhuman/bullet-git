# bullet-git operations

CI entrypoints live in `ops/ci/<lane>.sh`. They are exposed only through
`bash scripts/ci-local.sh <lane>` and the matching `just` recipe, and
`.github/workflows/ci.yml` calls the same scripts. Change a lane by changing
its script; the workflow and the Justfile stay thin.

## Lanes

| Lane | Script | Runs | Prerequisites (`scripts/ci-doctor.sh <lane>`) |
| --- | --- | --- | --- |
| fast | `ops/ci/fast.sh` | `cargo fmt --all --check`; `cargo nextest run --locked --workspace --profile fast` (`.config/nextest.toml`: fail-fast, 20 s slow-timeout, terminate after 2) | rustc 1.97.1 (`rust-toolchain.toml`), rustfmt, cargo-nextest 0.9.137 |
| required | `ops/ci/required.sh` | `ops/ci/local-parity-test.sh` (asserts the pre-push hook, `quality-gates.sh`, `ci-doctor.sh`, and Justfile controls); fast; `cargo clippy --locked --workspace --all-targets -- -D warnings` | fast plus clippy |
| contract | `ops/ci/contract.sh` | nextest `contract` profile over the whole workspace: the real local Git suites and the spawned daemon round trip; 45 s slow-timeout, no fail-fast, `num-cpus` threads; local processes only, no network | rustc, cargo-nextest, and a `git` binary on `PATH` (not checked by ci-doctor) |
| security | `ops/ci/security.sh` | `gitleaks detect --source . --no-git --redact`; `cargo deny fetch db` and a lane-side freshness proof of the RustSec database; `cargo deny --locked check licenses advisories bans sources` against the committed `deny.toml`; `zizmor .` | gitleaks 8.21.2, cargo-deny 0.19.8, zizmor 1.25.2, `cargo`, `git` |
| audit | `ops/ci/audit.sh` | `jankurai audit . --no-score-history --fail-under $AUDIT_FLOOR --fail-on critical` with `AUDIT_FLOOR=56`; artifacts in `.jankurai/` | jankurai 1.6.11; local/release only, not in `ci.yml` |
| nightly | `ops/ci/nightly.sh` | see the next section | bash only |

## Security lane policy

`deny.toml` at the repository root is the committed supply-chain policy and is
the only place a license, advisory, ban, or source exception may be written;
each entry carries the crate that justifies it. The lane runs
`cargo deny --locked check licenses advisories bans sources`, so all four
checks fail closed together. There is no separate "licenses are not gated yet"
state any more.

The advisory database is cloned into `target/advisory-db` (ignored) rather than
into the ambient `CARGO_HOME`, and the lane proves its freshness itself: it
reads the database's newest commit and refuses at 14 days
(`ADVISORY_DB_ABSENT` / `ADVISORY_DB_UNREADABLE` / `ADVISORY_DB_STALE`, exit 1).
That check exists because cargo-deny 0.19.8 fetches through the git CLI and
reads a non-zero `git` exit as success, so a failed fetch alone cannot fail the
check on a host that already has a database, and `maximum-db-staleness` cannot
see it either because a failed `git fetch` still rewrites `FETCH_HEAD`. Never
replace that gate with a `|| true`, a skip, or a wider age limit to get a green
run on an offline host: an unrefreshed database means the scan is not trusted.

`zizmor .` audits the workflow bytes. Without a GitHub API token it skips its
five online audits (impostor-commit, ref-confusion, known-vulnerable-actions,
stale-action-refs, ref-version-mismatch) and prints that it is doing so; the
offline audits still fail the lane on a finding. Do not add a token to make the
online audits run from a proof lane.

Hosted `ci.yml` runs fast, required, contract, and security with pinned
installs (`dtolnay/rust-toolchain` 1.97.1, `taiki-e/install-action` for
cargo-nextest 0.9.137, cargo-deny 0.19.8 and zizmor 1.25.2, sha256-checked
gitleaks 8.21.2);
every action is pinned to a full commit SHA and checkouts use
`persist-credentials: false`. It never installs Playwright and never reaches
a forge.

## `BULLET_LIVE_GITD` and the nightly lane

`ops/ci/nightly.sh` is the explicit local entrypoint for a future live
`jeryu-gitd` oracle. Its behaviour is exactly:

- `BULLET_LIVE_GITD` unset or empty: logs
  `BULLET_LIVE_GITD unset; no live gitd lane registered` and exits **78**.
  That exit code distinguishes "unregistered" from success; it is not green
  and must never be mapped to 0.
- `BULLET_LIVE_GITD` set to any value: prints
  `[ci] BULLET_LIVE_GITD requested but no live jeryu-gitd oracle lane is
  registered` to stderr and exits **1**, because no oracle adapter exists and
  a lane that ran nothing must not pass.

No hosted schedule is registered. Do not add an oracle stub, a mock daemon, a
conditional skip, or an environment switch that turns either branch green. The
lane becomes real only when a versioned `jeryu-gitd` from a separately
reviewed immutable Jeryu tag is consumed (`docs/architecture.md`, trust
model).

## Hostile-repository suites

The contract profile runs against real Git repositories created per test in
private temporary directories (`crates/bullet-git-workspace/tests/support/`).
These suites are the negative evidence for spec §20 and must keep running
unmodified:

- `crates/bullet-git-workspace/tests/real_repository.rs`: hostile hooks and
  home config never execute; a repository-local clean filter is refused before
  execution (`HOSTILE_GIT_CONFIG`); worktree-shaped directories, sequencer
  state, unclassified untracked files, symlink writes, duplicate and
  out-of-scope paths, oversized preimages, and deletes of absent paths are
  refused before any mutation; stale proposal subjects leave generation,
  journal, tree, and CAS unchanged.
- `clone_safety.rs` and `mirror_clone.rs`: no remote survives the clone, the
  manifest lives outside the tree, invalid base SHAs fail closed, mirror
  fetches run under the exclusive lock with dead-holder lock recovery.
- `cas.rs`: writable or symlinked roots and ancestors are refused, oversize is
  refused before allocation, existing and read bytes are rehashed.
- `preservation_authority.rs`: forged, stale, or mutated receipts, artifact or
  destination mutation, and symlinked destinations never clean; a post-delete
  tombstone failure is typed UNKNOWN with the preservation artifact intact.
- `crates/bullet-gitd/tests/authority_gateway.rs`: exact terminal replay,
  replay conflicts, restart-with-reservation is UNKNOWN, global freeze
  persistence, and malformed, oversized, duplicate-key, non-regular, or
  symlinked ledger records fail closed.
- `crates/bullet-gitd/tests/daemon_roundtrip.rs`: a self-authored token cannot
  create a workspace; oversized stdio frames are refused before JSON parsing.
- `crates/bullet-git-journal/tests/durable.rs`: corruption, sequence gaps,
  unknown fields, and symlinked journal directories fail closed.

Rules for these suites: no shared or pre-existing repository, no network
(`ops/ci/lib.sh` exports `GIT_TERMINAL_PROMPT=0`), and no `#[ignore]` to get
past a platform gap — when a primitive is missing the code returns a typed
unsupported error and the test asserts that error.

## Rules

- Never skip-green. `require_tool` fails a lane when a tool is missing,
  `ci-doctor.sh` fails on a wrong pinned version, and exit 78 from nightly is
  not success. Do not add `|| true`, `continue-on-error`, or fallbacks.
- Git binary and configuration hardening is never bypassed. `SafeGit`
  (`crates/bullet-git-workspace/src/safe_git.rs`) clears the child
  environment and forces `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`,
  `GIT_TERMINAL_PROMPT=0`, a deny `GIT_ASKPASS`, `GIT_SSH_COMMAND=false`, an
  empty `core.hooksPath`, an empty `credential.helper`,
  `include.path=/dev/null`, and `protocol.file.allow=never` (`user` only for
  the single mirror-to-clone call); `git_config.rs` refuses command-bearing or
  truth-redirecting local configuration with `HOSTILE_GIT_CONFIG`. No lane,
  test, or fixture may set `GIT_*` overrides, widen `protocol.file.allow`, or
  call raw `git` outside `SafeGit` to make a case pass.
- No worktrees, anywhere: not in lanes, not in fixtures, not in the checkout.
  `.git` as a file is `WORKTREE_FORBIDDEN` in the daemon and forbidden for
  agents by the family rule.
- Lanes never publish, mirror, tag, push, or otherwise mutate forge state, and
  never touch Jeryu.
- `AUDIT_FLOOR` in `ops/ci/audit.sh` is a ratchet: it may only rise.
- Generated files are never hand-edited:
  `crates/bullet-git-types/src/schema_bundle.rs` (`agent/generated-zones.toml`)
  comes from the hub sync script; `Cargo.lock` changes come from `cargo`, and
  every lane runs `--locked`; `.jankurai/` is lane output.
- Local hooks: `just hooks-install` sets `core.hooksPath ops/git-hooks`; the
  pre-push hook runs `ops/ci/quality-gates.sh`, which is exactly the fast
  lane. `ops/ci/local-parity-test.sh` asserts that wiring inside the required
  lane.
