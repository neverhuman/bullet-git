# bullet-git

Status: first-build BulletGit kernel; component primitives, not release-ready
Owner: Bullet Farm maintainers
Last reviewed: 2026-08-26
Applies to: bullet-git

## Role

BulletGit: the change graph — ChangeId versus CandidateId, EvolutionEdge,
Checkpoint, ProofRoot — with its typed IDs, framed digests, and the schema-1
proposal (`crates/bullet-git-types`); the append-only CAS-first workspace
journal and checkpoints (`crates/bullet-git-journal`); the sole-writer
workspace daemon `bullet-gitd` behind a fail-closed authority gateway
(`crates/bullet-gitd/src/authority_gateway.rs`: `Daemon::new()` installs the
production Kernel checker; Linux mutation requires an explicitly configured,
peer-authenticated Kernel UDS plus a one-use permit and exact online check and
settlement. Missing required environment, malformed numeric UID/GID,
non-Linux builds, and unsigned or legacy input refuse with
`AUTHORITY_CONTRACT_UNAVAILABLE`; inadmissible configured sockets, peer
mismatches, and transport or protocol failures refuse with
`AUTHORITY_REFUSED`), a
durable fsynced JSONL mutation ledger and bounded read-only recovery
(`crates/bullet-gitd/src/mutation_ledger.rs`, `mutation_recovery.rs`: a
reservation left in flight across restart is `MUTATION_OUTCOME_UNKNOWN` and
freezes further mutation, never re-authorized); immutable workspace
generations with one durable active-pointer switch, an immutable CAS, sealed
preservation receipts, receipt-gated cleanup, and receipt-bound tombstones
(`crates/bullet-git-workspace/src/{generation,cas,preservation}.rs`);
`SafeGit` hostile-git hardening and checkpoint-bound `apply_proposal` with
exact path preimages (`safe_git.rs`, `git_config.rs`, `repository.rs`). Pack
protocol, refs, and protected updates belong to the forge (Jeryu/GitHub).

## Repositories

- Initial source authority: Jeryu repository `root/bullet-git`
  (`repos.manifest.toml`, family root)
- Public GitHub index: `https://github.com/neverhuman/bulletfarm` (hub only;
  not `neverhuman/bullet-farm` and not a `neverhuman/bullet-git` mirror); this
  member has no separate GitHub publication remote and is never source
  authority
- Family lock entry: `bullet-git` at tag `v0.1.0-alpha.4` in
  `bullet-farm/family.lock`; no newer BulletGit tag is published

## Split Rules

- Jeryu is the initial source forge; GitHub is a configurable effect adapter,
  not source authority. GitHub never sees custom object types: at the forge
  boundary everything is ordinary blobs, trees, commits, and refs.
- Do not reimplement pack protocol. `bullet-gitd` is the capability daemon and
  the only workspace writer; no raw Git CLI in agent sandboxes
  (`agent/JANKURAI_STANDARD.md`).
- Consume Jeryu and `bullet-wire` only through pinned immutable tags. No
  committed `path = "../…"` dependency; workspace members reference only
  in-repo `crates/…` paths (`Cargo.toml`).
- `contracts/generated/rust/schema_bundle.rs` is a generated zone
  (`agent/generated-zones.toml`) synced from the hub's
  `contracts/generated/rust/schema_bundle.rs` by
  `bullet-farm/scripts/sync-family-contracts.sh`; never hand-edit.
- Release builds depend on immutable tags, not branches. Authority enablement
  waits for the operator-published frozen contract and verified lock
  (`docs/architecture.md`, trust model); no local tag, copied source, or
  positive test checker may stand in for it.
- Zero new worktrees anywhere: the daemon refuses a `.git` file as
  `WORKTREE_FORBIDDEN`, and agents edit only the claimed canonical checkout.
- Jeryu tags observed today are not annotated signed tags. `bullet-family
  forge pin` refuses `UNSIGNED_FORGE_TAG` until they are (J-5 / OD-D). Do not
  write "signed Jeryu tags" as a current fact.

## Required Local Check

```bash
bash scripts/ci-local.sh required
```
