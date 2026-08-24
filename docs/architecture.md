# BulletGit architecture

Status: component primitives (workspace daemon); no transaction or production claim
Owner: Bullet Farm maintainers
Last reviewed: 2026-08-24
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
| `bullet-git-types` | ChangeId/CandidateId/CheckpointId, validated `GitOid` (40 lowercase hex), `Candidate` (spec §6.13 minus `toolchain_digest`; `lineage_subject` and `environment_digest` are optional and outside `CandidateId`/`ProofRoot`), `ProofRoot`, framed digests, `WireAuthorityToken` |
| `bullet-git-journal` | append-only workspace journal and checkpoints |
| `bullet-git-workspace` | `SafeGit` hardened command builder and local-config admission, mirror-under-lock source fetch, `PrivateClone` lifecycle (§20.2), `ScopeGrant`, `RealRepository` capability API over real Git |
| `bullet-gitd` | the stdio daemon binary plus `MemoryRepository`, an in-process fake with the same authority and scope rules |

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

The `WorkspaceManifest` (attempt and variant ids, base sha, branch,
created_at from the caller's clock, 32-byte nonce hex, repo, source and
mirror paths) is recorded in the runtime dir, never inside the repository
tree.

## Trust model

- **Authority.** Every call carries the kernel `AuthorityToken` JSON. The
  daemon captures `attempt_id`/`attempt_fence`/`workspace_nonce` from the
  initial `clone` token and verifies every subsequent token against them
  (`RealRepository` re-verifies as defence in depth). Empty or unparseable
  token → `UNAUTHORIZED`; attempt/fence/nonce mismatch → `STALE_AUTHORITY`.
  A display name, PID, branch name, or path grants nothing.
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
  `git clone --reference-if-able <mirror> --dissociate` from the mirror
  while the lock is still held — objects are shared during the clone and
  copied before it completes, so no alternates file survives and a mirror
  GC can never corrupt a workspace.
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
- **Batch admission.** A batch is refused before any mutation when two
  entries normalize to the same path (`DUPLICATE_PATH`) or fold to the same
  case-insensitive key (`PATH_COLLISION`); multi-step sequences on one path
  must be collapsed by the proposal producer.
  Empty batches and batches above 1,024 operations fail with
  `INVALID_OPERATION_COUNT`; a replacement body above 1 MiB fails with
  `CONTENT_TOO_LARGE`. These values are identical to the frozen
  `bullet-wire` proposal defaults.
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
  branch. The result carries exact `base_commit`/`head_commit`/`tree_hash`
  (`git rev-parse HEAD^{tree}`) and `patch_hash` = BLAKE3 of the
  `git diff base..head` bytes. `CandidateId` is content-derived from
  change + tree + head, so two different trees under one Change can never
  share an id.
- **Structural fail-closed checks.** `.git` as a file (the on-disk shape of
  a worktree) → `WORKTREE_FORBIDDEN`; `rev-parse --show-toplevel` mismatch →
  `WRONG_REPOSITORY`; sequencer files (`CHERRY_PICK_HEAD`/`MERGE_HEAD`/
  `REBASE_HEAD`) at checkpoint/prepare time → `SEQUENCER_ACTIVE`. Detached
  HEAD is detected via the `symbolic-ref -q HEAD` exit status, never by
  comparing a branch name to the string "HEAD"; detached is the expected
  state between base checkout and private-branch creation.
- **Cleanup (spec §20.8).** Deletion requires a nonce match against the
  manifest plus a verified preservation receipt (`git bundle create` then
  `git bundle verify`), and writes a tombstone JSON in the runtime dir.
  Name/path reuse waits for the tombstone.

## bullet-gitd stdio protocol

Line-delimited JSON: one request object per line on stdin, one response
object per line on stdout. Input is read through a bounded frame reader;
frames above 4 MiB fail with `FRAME_TOO_LARGE` and terminate the session,
invalid UTF-8 fails with `INVALID_UTF8`, and request/parameter objects reject
unknown fields before dispatch.

```text
request:  {"id": <any>, "method": <name>, "token": <AuthorityToken JSON>, "params": {...}}
response: {"id": <same>, "ok": <result>}
          {"id": <same>, "err": {"code": <REASON_CODE>, "message": <text>}}
```

The `token` field carries the kernel `AuthorityToken` as a JSON object
(unknown fields ignored; `variant_id`, `attempt_id`, `attempt_fence`,
`workspace_nonce` required). A string token is parsed as JSON text and a
missing/null token as empty; anything that does not parse to a valid token
fails closed as `UNAUTHORIZED`.

`clone` must be the first call; the daemon then serves exactly one workspace
session and fences every subsequent call with the clone-time token values.

| Method | Params | Result |
|---|---|---|
| `clone` | `source_repo`, `base_sha`, `root`, `created_at`, `allowed_prefixes`, `commit_date` (variant/attempt/nonce come from the token) | `repo_dir`, `runtime_dir`, `branch`, `base_sha` |
| `read_tree` | — | `files`: tracked paths |
| `apply_change` | `patches`: `[{path, op?, contents_hex?}]` — `op` is `write` (default; full-file `contents_hex` required, hex) or `delete` (must omit `contents_hex`) | `applied`: count |
| `checkpoint` | — | Checkpoint JSON incl. `git_tree` |
| `prepare_candidate` | `change_seed`, `mission` | Candidate JSON (exact SHAs, `patch_hash`; `lineage_subject`/`environment_digest` are `null` until a producer populates them) |
| `cleanup` | `bundle_path` (required receipt target), `deleted_at` | `tombstone`, `bundle`, `verified` |

Example conversation:

```text
→ {"id":1,"method":"clone","token":{...},"params":{"source_repo":"/mirrors/repo.git","base_sha":"d6d3…","root":"/farm","created_at":"2026-08-24T00:00:00Z","allowed_prefixes":["src"],"commit_date":"2026-08-24T00:00:00+00:00"}}
← {"id":1,"ok":{"repo_dir":"/farm/work/atm_1/repo","branch":"bullet/var_1/atm_1","base_sha":"d6d3…","runtime_dir":"/farm/runtime/atm_1"}}
→ {"id":2,"method":"apply_change","token":{...},"params":{"patches":[{"path":"src/lib.rs","contents_hex":"7075…"}]}}
← {"id":2,"ok":{"applied":1}}
→ {"id":3,"method":"apply_change","token":{...},"params":{"patches":[{"path":"src/old.rs","op":"delete"}]}}
← {"id":3,"ok":{"applied":1}}
→ {"id":4,"method":"prepare_candidate","token":{...},"params":{"change_seed":"feat","mission":"demo"}}
← {"id":4,"ok":{"id":"can_…","base_commit":"d6d3…","head_commit":"9f2c…","tree_hash":"41ab…","patch_hash":"…", ...}}
```

Error codes: `UNAUTHORIZED`, `STALE_AUTHORITY`, `OUT_OF_SCOPE`,
`PATH_ABSENT`, `DUPLICATE_PATH`, `PATH_COLLISION`, `INVALID_OPERATION_COUNT`,
`CONTENT_TOO_LARGE`, `SYMLINK_FORBIDDEN`,
`WORKTREE_FORBIDDEN`, `WRONG_REPOSITORY`, `WRONG_BRANCH`,
`SEQUENCER_ACTIVE`, `UNCLASSIFIED_UNTRACKED`, `BASE_MISSING`,
`MIRROR_LOCK_TIMEOUT`, `CLEANUP_NONCE_MISMATCH`, `CLEANUP_RECEIPT_REQUIRED`,
`HOSTILE_GIT_CONFIG`, `GIT_FAILED`, `IO_FAILED`, `INVALID_TYPES`, plus protocol-level
`BAD_REQUEST`, `FRAME_TOO_LARGE`, `INVALID_UTF8`, `PROTOCOL_IO_FAILED`,
`NOT_CLONED`, `ALREADY_CLONED`, `UNKNOWN_METHOD`, `ENCODING`.
All v1 codes are unchanged; `PATH_ABSENT`, `DUPLICATE_PATH`,
`PATH_COLLISION`, and `MIRROR_LOCK_TIMEOUT` are additive, as is the optional
patch `op` field.

## Hash framing

Every digest over more than one variable-length field length-prefixes each
field (u64 LE length + bytes) via `bullet_git_types::frame`, so
`["ab","c"]` and `["a","bc"]` can never collide. This applies to
`ProofRoot::compute`, journal checkpoints, `CandidateId::from_content`, and
the MemoryRepository preimage.
