# BulletGit architecture

Status: component primitives (workspace daemon); no transaction or production claim
Owner: Bullet Farm maintainers
Last reviewed: 2026-08-25
Applies to: bullet-git

## Role split

Internally BulletGit owns the change graph: Change, Candidate, EvolutionEdge,
Checkpoint, ProofRoot. `bullet-gitd` (this repo) is the capability daemon and
the **sole writer** of the private workspace (ADR 0001 in bullet-farm: the
model proposes, the kernel applies patches through this daemon). Pack
protocol, refs, and protected updates belong to the forge (Jeryu/GitHub). At
that boundary everything is ordinary blobs, trees, commits, and refs.

## Crate map

| Crate | Role |
|---|---|
| `bullet-git-types` | full 256-bit lowercase ChangeId/CandidateId/CheckpointId, validated algorithm-tagged `GitOid` (`sha1:<40 lowercase hex>` or `sha256:<64 lowercase hex>`), strict `CandidateProvenance`/`CandidateManifest` with mandatory environment, toolchain, snapshot, and ordered parent-Candidate lineage subjects, `ProofRoot`, framed digests, `WireAuthorityToken` |
| `bullet-git-journal` | append-only workspace journal and checkpoints |
| `bullet-git-workspace` | `SafeGit` hardened command builder and local-config admission, mirror-under-lock source fetch, `PrivateClone` lifecycle (§20.2), `ScopeGrant`, `RealRepository` capability API over real Git |
| `bullet-gitd` | the stdio daemon binary plus `MemoryRepository`, an in-process fake with the same authority and scope rules |

Identity compatibility is intentionally absent before 1.0. Legacy 32-hex
Change/Checkpoint/Candidate IDs, untagged Git OIDs, uppercase hex, unknown
algorithms, and wrong widths fail decoding; no stored subject is upgraded or
silently reinterpreted. Exact serde goldens pin all three typed-ID prefixes and
both supported Git OID algorithms.

## Workspace layout (spec §20.1)

```text
<root>/work/<attempt_id>/repo      private clone (no remote survives)
<root>/runtime/<attempt_id>/       manifest.json, isolation dirs, tombstone.json,
                                   transient tmp-index-<n> files during checkpoints
<root>/mirrors/<digest>.git        bare mirror per source repository
                                   (digest = BLAKE3 of the canonical source path)
<root>/mirrors/<digest>.git.lock   exclusive mirror lock; holder pid inside
branch                             bullet/<variant_id>/<attempt_id>
```

The `WorkspaceManifest` (attempt and variant ids, algorithm-tagged base OID, branch,
created_at from the caller's clock, 32-byte nonce hex, repo, source and
mirror paths) is recorded in the runtime dir, never inside the repository
tree.

## Trust model

- **Authority is fail-closed.** `Daemon::new()` installs the production
  `KernelPermitCheck`. On Linux, mutation requires an explicit absolute Kernel
  UDS, admitted server UID and socket GID, exact socket and peer revalidation,
  a Kernel-issued one-use permit, and the matching bounded online check and
  settlement. Missing or malformed transport configuration, non-Linux builds,
  unsigned or legacy input, denial, drift, timeout, and ambiguous replies all
  refuse; an unconfigured fresh daemon returns
  `AUTHORITY_CONTRACT_UNAVAILABLE` before repository, journal, or preservation
  I/O. Without a successful `clone`, `apply_change`, `checkpoint`,
  `prepare_candidate`, and `cleanup` fail their earlier local prerequisite with
  `NOT_CLONED`; they do not reserve authority for an impossible local session.
  A display name, PID, branch name, path, local token, or test checker grants
  nothing. This component path is not release or live authority: production
  admission still requires the pinned `bullet-wire` source, protected runtime
  trust roots, signed immutable family subjects, distinct workload custody,
  and exact live receipts.
  No current Hub checkout or commit is an admitted immutable contract subject.
  The checked `family.lock` is schema 2, names only a historical alpha.4
  family, and is diagnostic-only: every installer path refuses it by design.
  BulletGit must not copy the source, treat that historical member OID as
  authority, invent a tag, or configure or credit the installed component
  checker as admitted live/release authority until an operator publishes the
  frozen shared contract under signed immutable member tags and a verified
  schema-3 family lock admits their exact subjects.
- **Durable replay prerequisite.** The local mutation ledger records the exact
  Mutation/reservation/operation/request digest, authority-envelope digest and
  token nonce, repository, Workspace/generation/nonce, Attempt/fence,
  authority epoch, freeze generation, permit nonce, and permit digest in an
  append-only, fsynced JSONL file. These fields mirror the frozen permit
  subject plus the workspace nonce from its verified authority envelope. The
  production component checker matches those subjects and the exact request
  fingerprint before constructing the private daemon decision. The gateway also compares that decision's
  request digest with the exact operation/authority/parameters fingerprint,
  and its Attempt, fence, and workspace nonce with the already-parsed writer
  target before reading trusted time or writing a reservation. The legacy token
  does not expose typed repository/Workspace IDs or generation and cannot by
  itself grant authority. The component path instead requires the Kernel-issued
  permit and exact online decision to bind the full mutation request; those
  bytes are not admitted live/release subjects. Every
  field is replay-sensitive and malformed IDs, digests, or generations are
  refused before reservation. A consumed permit becomes a non-cloneable
  pending mutation. Every daemon mutation reports success only after its exact
  result digest receives an online settlement acknowledgment matching the
  Mutation and reservation IDs plus a domain-separated fingerprint over every
  reservation field, outcome, result, and completion time, and is appended to
  the local ledger. A repository error is settled as `UNKNOWN`; any
  post-execution authority outage, response mismatch, clock failure, or local
  settlement failure is also `MUTATION_OUTCOME_UNKNOWN`, never a proven abort
  or success. The daemon then freezes all further mutation in-process while
  retaining read-only inspection for salvage. On open, the ledger performs a
  bounded scan of record files opened final-component no-follow/close-on-exec,
  validates regular type and total size from the opened descriptor, rejects
  duplicate JSON keys recursively, validates filename-to-Mutation identity and
  full event bytes, and exposes exact pending or terminal-UNKNOWN subjects
  through read-only recovery status. Persisted recovery is unsupported and
  therefore frozen off Unix until an equivalent no-follow primitive exists.
  Any such subject, corruption,
  unexpected entry, scan-limit breach, or ambiguous append/fsync globally
  freezes later reservation and settlement; committed or proven-aborted
  history alone does not. The gateway checks this recovered freeze before an
  online final check. Exact successful terminal results replay without another
  reservation; changed subjects conflict. A restart with only an in-flight
  reservation, a partial write, or corrupt state is
  `MUTATION_OUTCOME_UNKNOWN`, never permission to retry. This ledger records
  evidence only and cannot mint authority or clear a freeze. The production
  `KernelPermitCheck` is the bounded online client for final check and
  settlement. Authenticated cross-process exact-replay adoption, signed
  immutable family admission, protected live workload custody, and live/release
  receipts remain absent.
- **No remote, no credential.** `git remote remove origin` runs immediately
  after clone; `credential.helper=` is forced empty, `GIT_ASKPASS` points at
  a deny script, `GIT_TERMINAL_PROMPT=0`, `GIT_SSH_COMMAND=false`. A
  model-issued push has no destination and no way to authenticate.
- **Mirror fetch under lock (spec §20.2).** Workspaces never clone the
  source repository directly. The source is mirrored into
  `mirrors/<digest>.git` under the workspace root; the mirror is created
  (`git clone --mirror`) or refreshed (`git fetch --prune origin`) under an
  exclusive lock file taken create-exclusive with the holder pid inside. A
  lock whose recorded holder is dead is broken immediately; a lock without
  a readable pid is broken once older than 60s; waiting is bounded (120s),
  then typed `MIRROR_LOCK_TIMEOUT`. The base SHA is verified against the
  mirror, and the private clone runs
  a remote-free `git init` with the mirror's exact object format, then uses
  the Rust-owned reflink-or-bounded-copy path while the lock is still held.
  The copied store is installed atomically inside the unpublished generation;
  checkout plus strict `git fsck` must pass, so no alternates file survives
  and a later mirror GC cannot corrupt a workspace.
- **GC-under-load proof (WI-30).** `tests/gc_safety.rs` pins that boundary
  with a hostile `git gc --prune=now --aggressive` plus `prune --expire=now`
  on the mirror after clone creation (the mirror's packs are proven
  rewritten), deletion of the whole mirror, and a GC loop concurrent with
  clone creation and with commits inside existing workspaces: every private
  clone stays `fsck --full --strict` clean, every reachable object is
  readable from its own store, and checkout plus commit still work. The
  Rust-owned `reflink.rs` copy primitive is implemented: on Linux it attempts
  `FICLONE` against opened regular-file descriptors, checks source descriptor
  identity, and otherwise copies at most the admitted source length before
  requiring the exact byte count. It rejects symlinks and special entries,
  removes a partial destination on failure, and never resolves an ambient
  `cp`; `tests/reflink.rs` proves the fallback bytes and hostile-`PATH` case.
  `PrivateClone::create` now calls this primitive under the mirror lock and
  records `reflink` or `fallback` in the strict workspace manifest. Native
  certification that the reflink branch executes on each supported CoW
  filesystem remains release evidence; the credential-free fallback proof
  does not claim host-level CoW support.
- **Hostile-git controls (spec §20.3).** The child environment is cleared
  (strips every inherited `GIT_*` variable) and rebuilt with per-workspace
  `HOME`/`XDG_CONFIG_HOME`/`XDG_CACHE_HOME`, `GIT_CONFIG_NOSYSTEM=1`,
  `GIT_CONFIG_GLOBAL=/dev/null`. Every invocation disables paging, hooks,
  credentials, filesystem monitors, external attribute/exclude files, and
  commit/tag signing, and passes
  `-c core.hooksPath=<empty dir> -c credential.helper=
  -c include.path=/dev/null -c protocol.file.allow=never` — `user` is scoped
  to exactly the one local clone call that needs the file transport. Before
  every repository-scoped invocation, BulletGit parses the exact local config
  with includes disabled. A non-regular config or any command-bearing or
  truth-redirecting filter, include, alias, pager, URL rewrite, remote helper,
  diff/textconv, merge driver, submodule update, credential, signing, editor,
  sparse, SSH, hook, worktree, or external attribute/exclude setting fails
  closed with `HOSTILE_GIT_CONFIG`. A real-repository test plants a clean
  filter and canary behind `.gitattributes` and proves refusal before execution.
- **Scope.** `apply_change` validates every path against the `ScopeGrant`
  prefixes before writing anything: segment-wise prefix match on normalized
  paths. Normalization applies Unicode NFC and refuses `..`, `.` or empty
  segments, any `.git` component (ASCII case-insensitive), absolute paths,
  backslashes, NUL bytes, `:` inside a segment (alternate data streams),
  segments ending in `.` or a space, and symlink traversal or symlink
  targets. Validation is all-or-nothing — one bad path leaves the tree
  untouched.
- **Batch admission.** Execution is refused before any mutation when two
  entries normalize to the same path (`DUPLICATE_PATH`) or fold to the same
  case-insensitive key (`PATH_COLLISION`); multi-step sequences on one path
  must be collapsed by the proposal producer. The workspace execution policy
  accepts 1..=128 unique paths, at most 1 MiB per replacement body, and at
  most 32 MiB of replacement content across the batch. Exceeding the last
  bound returns `AGGREGATE_CONTENT_TOO_LARGE`.
  The strict schema-1 `PatchProposal` wire validator imports the same fixed
  limits and refuses an oversized proposal before workspace admission. The
  wire format therefore does not advertise a capability the writer cannot
  execute.
- **Deletes.** A patch entry may carry `"op": "delete"`. The target must
  be an existing regular file on disk when the batch is validated (else
  typed `PATH_ABSENT`), scope rules apply exactly as for writes, and the
  whole batch is validated before any mutation. The journal records the
  digest of the destroyed contents
  (before-state), and the deletion reaches checkpoints and the prepared
  Candidate through the same porcelain scan and commit as writes, so
  deleted files never linger in the tree or the candidate.
- **Checkpoints never touch the live index (R7).** `git write-tree` runs
  against a temporary `GIT_INDEX_FILE` in the runtime dir.
- **Candidate preparation (spec §20.7).** A fresh `git status --porcelain=v2`
  scan classifies every entry; unclassified untracked files outside scope
  refuse preparation. The commit uses the fixed identity
  `Bullet Farm <farm@bullet.local>` and a caller-fixed date on the private
  branch. The caller must provide the strict `CandidateProvenance`, including
  exact repository/Attempt/fence/work-package/variant/plan/graph/checkpoint
  subjects, ordered `parent_candidate_ids`, granted scope, four snapshot IDs,
  `environment_digest`, and `toolchain_digest`; missing or unknown fields are
  refused. BulletGit derives actual scope and exact algorithm-tagged
  `base_commit`/`head_commit`/`tree_oid`, plus `patch_digest` = BLAKE3 of the
  `git diff base..head` bytes. `CandidateId` hashes the complete canonical
  manifest, so environment, toolchain, and lineage changes produce a new
  identity. The separate reusable content ID hashes only repository/base/head/
  tree/patch content. `ProofRoot` binds the Candidate ID and content ID and
  also derives Change/ordered-parent lineage from the manifest.
- **Structural fail-closed checks.** `.git` as a file (the on-disk shape of
  a worktree) → `WORKTREE_FORBIDDEN`; `rev-parse --show-toplevel` mismatch →
  `WRONG_REPOSITORY`; sequencer files (`CHERRY_PICK_HEAD`/`MERGE_HEAD`/
  `REBASE_HEAD`) at checkpoint/prepare time → `SEQUENCER_ACTIVE`. Detached
  HEAD is detected via the `symbolic-ref -q HEAD` exit status, never by
  comparing a branch name to the string "HEAD"; detached is the expected
  state between base checkout and private-branch creation.
- **Preservation before cleanup (spec §20.8).** `preserve` accepts only a new,
  absolute, canonical external directory outside the exact work/runtime
  targets. It copies and fsyncs the complete active generation (private repo,
  generation manifest, and durable journal), immutable CAS, workspace
  manifest, and a verified Git bundle. A daemon-held 256-bit seal persisted
  outside the provider-visible repository authenticates an opaque receipt
  binding Attempt, fence, workspace nonce, active generation/tree and full
  generation digest, exact dirty/untracked manifest, journal range/root,
  complete artifact digest, destination device/inode, and cleanup target.
  `cleanup` accepts only that opaque receipt. It repeats source, destination,
  subject, journal/CAS, bundle, and full-artifact verification immediately
  before deleting exactly the sealed work directory; missing or changed
  bytes, forged/stale receipts, and destination swaps leave the workspace
  intact. Runtime state, the private seal, external artifact, and a receipt-
  bound tombstone survive cleanup. Name/path reuse waits for the tombstone.

## bullet-gitd stdio protocol

Line-delimited JSON: one request object per line on stdin, one response
object per line on stdout. Input is read through a bounded frame reader;
frames above 65 MiB fail with `FRAME_TOO_LARGE` and terminate the session,
invalid UTF-8 fails with `INVALID_UTF8`, and request/parameter objects reject
unknown fields before dispatch.

```text
request:  {"id": <any>, "method": <name>, "token": <AuthorityToken JSON>, "params": {...}}
response: {"id": <same>, "ok": <result>}
          {"id": <same>, "err": {"code": <REASON_CODE>, "message": <text>}}
```

The legacy `token` field accepts the old Kernel JSON shape as opaque input to
the gateway. Its local Attempt/fence/nonce comparison is not a signature or
final authority check and cannot make a mutation succeed. Only a top-level
Kernel permit that passes the online checker can contribute authority. Empty
or malformed values can fail earlier as `UNAUTHORIZED`.

`clone` remains the first possible workspace call, but the production daemon
cannot create that session until admitted online Kernel authority is supplied.

| Method | Params | Result |
|---|---|---|
| `clone` | `source_repo`, algorithm-tagged `base_sha`, `root`, `created_at`, `allowed_prefixes`, `commit_date` (variant/attempt/nonce come from the token) | `repo_dir`, `runtime_dir`, `branch`, tagged `base_sha` |
| `read_tree` | — | `files`: tracked paths |
| `apply_change` | `patches`: `[{path, op?, contents_hex?}]` — `op` is `write` (default; full-file `contents_hex` required, hex) or `delete` (must omit `contents_hex`) | `applied`: count |
| `apply_proposal` | `proposal`: strict schema-1 `PatchProposal` (shared maximum 128 paths, 1 MiB/body, 32 MiB aggregate) | `applied`: count; oversized proposals refuse before mutation |
| `checkpoint` | — | Checkpoint JSON incl. `git_tree` |
| `prepare_candidate` | strict `change`, complete `provenance` (`environment_digest`, `toolchain_digest`, ordered `parent_candidate_ids`, and every other field are mandatory), plus the generated non-optional `candidate_preparation_grant`; BulletGit only decodes its closed shape and presents the raw params unchanged to Kernel final check | provenance-bound Candidate JSON with exact tagged Git OIDs and patch digest |
| `preserve` | `destination` (new absolute canonical external directory) | opaque `preservation_receipt`, receipt/artifact digests, canonical destination |
| `cleanup` | `preservation_receipt`, `deleted_at` | `tombstone`, receipt digest, `verified` |

Current unconfigured production conversation:

```text
→ {"id":1,"method":"clone","token":{...},"params":{"source_repo":"/mirrors/repo.git","base_sha":"sha1:d6d3b35c8e418f44db2264c04548dafd009a934a","root":"/farm","created_at":"2026-08-24T00:00:00Z","allowed_prefixes":["src"],"commit_date":"2026-08-24T00:00:00+00:00"}}
← {"id":1,"err":{"code":"AUTHORITY_CONTRACT_UNAVAILABLE","message":"…"}}
→ {"id":2,"method":"apply_change","token":{...},"params":{"patches":[]}}
← {"id":2,"err":{"code":"NOT_CLONED","message":"clone must be the first call"}}
```

The second refusal is a local session precondition, not evidence that
authority was accepted. The same fresh-daemon ordering applies to
`checkpoint`, `prepare_candidate`, and `cleanup`.

Error codes: `AUTHORITY_CONTRACT_UNAVAILABLE`, `AUTHORITY_REFUSED`,
`AUTHORITY_SUBJECT_MISMATCH`, `MUTATION_PERMIT_EXPIRED`,
`INVALID_MUTATION_PERMIT_WINDOW`, `AUTHORITY_REPLAY_CONFLICT`,
`MUTATION_OUTCOME_UNKNOWN`, `MUTATION_LEDGER_IO_FAILED`, `UNAUTHORIZED`,
`STALE_AUTHORITY`, `OUT_OF_SCOPE`,
`PATH_ABSENT`, `DUPLICATE_PATH`, `PATH_COLLISION`, `INVALID_OPERATION_COUNT`,
`CONTENT_TOO_LARGE`, `AGGREGATE_CONTENT_TOO_LARGE`, `SYMLINK_FORBIDDEN`,
`WORKTREE_FORBIDDEN`, `WRONG_REPOSITORY`, `WRONG_BRANCH`,
`SEQUENCER_ACTIVE`, `UNCLASSIFIED_UNTRACKED`, `BASE_MISSING`,
`MIRROR_LOCK_TIMEOUT`, `PRESERVATION_INVALID_DESTINATION`,
`PRESERVATION_CORRUPT`, `PRESERVATION_RECEIPT_REFUSED`,
`PRESERVATION_UNSUPPORTED`, `PRESERVATION_IO_FAILED`,
`HOSTILE_GIT_CONFIG`, `GIT_FAILED`, `IO_FAILED`, `INVALID_TYPES`, plus protocol-level
`BAD_REQUEST`, `FRAME_TOO_LARGE`, `INVALID_UTF8`, `PROTOCOL_IO_FAILED`,
`NOT_CLONED`, `ALREADY_CLONED`, `UNKNOWN_METHOD`, `ENCODING`.
The authority and replay codes are additive and fail closed. They do not claim
that the unpublished signed-authority consumer exists.

## Hash framing

Every digest over more than one variable-length field length-prefixes each
field (u64 LE length + bytes) via `bullet_git_types::frame`, so
`["ab","c"]` and `["a","bc"]` can never collide. This applies to
`ProofRoot`, journal checkpoints, the canonical Candidate content/provenance
identities, and the MemoryRepository preimage.
