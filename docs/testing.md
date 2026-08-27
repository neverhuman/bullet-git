# Test and proof strategy

Status: normative for this component; pre-release gaps remain
Owner: bullet-git maintainers (`agent/owner-map.json`)
Last reviewed: 2026-08-25
Applies to: bullet-git

Tests here establish bounded facts about exact subjects. A green lane proves the
checks this repository currently implements; it never authorizes a forge, a
release, or a production mutation. Authority enablement stays blocked until the
operator publishes the frozen contract (`SPLIT.md`, `docs/architecture.md`).

## Lanes

Every lane is one script in `ops/ci/`, exposed through `bash scripts/ci-local.sh
<lane>`. Hosted jobs invoke that dispatcher too. The local `required` gate runs
the source admission and five atomic lanes sequentially; hosted CI runs the five
lanes in parallel after source admission and converges through `CI / required`.

| Lane | Command | What it proves | Rerun command |
| --- | --- | --- | --- |
| source-scan | `ops/ci/source-scan.sh` | gitleaks 8.21.2 scans the current source and lockfiles before project dependencies are installed | `bash scripts/ci-local.sh source-scan` |
| fast | `ops/ci/fast.sh` | exactly 43 types/journal cases; nonzero assertion and sanitized JUnit | `bash scripts/ci-local.sh fast` |
| lint | `ops/ci/lint.sh` | format, strict Clippy, actionlint 1.7.8, zizmor 1.25.2, ShellCheck 0.10.0, and meta-guards proving 43 + 126 = all 169 tests | `bash scripts/ci-local.sh lint` |
| contract | `ops/ci/contract.sh` | exactly 126 workspace/daemon cases, including real local Git and the daemon round trip; nonzero assertion and sanitized JUnit | `bash scripts/ci-local.sh contract` |
| security | `ops/ci/security.sh` | synthetic finding canary plus all cargo-deny license, advisory, ban, and source policies against a fresh RustSec database | `bash scripts/ci-local.sh security` |
| docs | `ops/ci/docs.sh` | relative links, warning-denied rustdoc, and doctests | `bash scripts/ci-local.sh docs` |
| required | `ops/ci/required.sh` | source admission followed by fast, lint, contract, security, and docs exactly once | `bash scripts/ci-local.sh required` |
| audit | `ops/ci/audit.sh` | the local Jankurai full score against the upward-only `AUDIT_FLOOR` ratchet, failing on critical findings | `bash ops/ci/audit.sh` |
| nightly | `ops/ci/nightly.sh` | nothing yet: unset `BULLET_LIVE_GITD` exits **78** (unregistered, not green); set, it exits **1** because no live `jeryu-gitd` oracle adapter exists | `bash scripts/ci-local.sh nightly` |

Local hooks: `just hooks-install` points `core.hooksPath` at `ops/git-hooks`, and
`ops/git-hooks/pre-push` runs `ops/ci/quality-gates.sh`, which is exactly the fast
lane. `ops/ci/local-parity-test.sh` asserts that wiring inside the required lane,
so hosted CI, the local lanes, and the hook can never drift apart.

## Artifacts, receipts, and repair routing

| Artifact | Producer | Use |
| --- | --- | --- |
| `.jankurai/repo-score.json` | audit lane | machine-readable score, caps, and findings; each finding carries its own `rerun_command` and `docs_url` |
| `.jankurai/repo-score.md` | audit lane | the same report for humans |
| `.jankurai/repair-queue.jsonl` | audit lane | one repair task per finding, so the next agent starts from the exact path and lane instead of re-deriving it |
| `.ci-artifacts/observations/<lane>.json` | hosted/local dispatcher | unsigned `bullet.ci-observation.v1` diagnostic with commit/tree, cleanliness, commands, versions, outcome, and artifact hashes; never Bullet Evidence |
| `.ci-artifacts/reports/{fast,contract}.junit.xml` | nextest | sanitized test report uploaded only with its matching observation |
| `.ci-artifacts/reports/coverage.lcov` | scheduled coverage | scheduled diagnostic only; no release or mutation authority |

`.jankurai/` is gitignored lane output, never source: recreate it with
`bash ops/ci/audit.sh`. Failures are typed, not free text — every refusal carries
a stable reason code (`AUTHORITY_CONTRACT_UNAVAILABLE`, `HOSTILE_GIT_CONFIG`,
`MUTATION_OUTCOME_UNKNOWN`, `STALE_AUTHORITY`, `WORKTREE_FORBIDDEN`) that names
the subject that refused and the lane that reproduces it. Those codes are wire
contract: they are consumed by bullet-kernel and the daemon protocol and must not
be renamed to satisfy a linter (`agent/audit-policy.toml` records that exception
with its reason).

### Typed failure contract

Every refusal an agent has to act on carries the same four things, so a failure is
routable without reading the implementation first:

- **purpose** — what the refusing subject was protecting, as named in
  `agent/test-map.json` (`purpose`) for the path and in `agent/proof-lanes.toml`
  for the lane;
- **reason** — the stable machine reason code (see above), never free text;
- **common fixes** — the paragraph below, per lane;
- **docs_url / repair_hint** — the audit report carries `docs_url` and
  `rerun_command` per finding, and `.jankurai/repair-queue.jsonl` carries the
  repair task; in code the equivalent is the typed `thiserror` variant plus the
  lane that reproduces it.

Common fixes, by lane: a red fast lane is a types/journal fact; a red lint lane
is format, Clippy, workflow policy, or inventory drift; a red contract lane is a real-Git or daemon
behavior and must never be repaired by widening `SafeGit`, `protocol.file.allow`,
or the hostile-config refusals; security can refuse an absent/stale advisory DB
and requires network to refresh it; a red audit lane is a score regression below
`AUDIT_FLOOR` and is repaired from `.jankurai/repair-queue.jsonl`, never by
lowering the floor.

## Hostile suites

The contract profile runs against real Git repositories created per test in
private temporary directories (`crates/bullet-git-workspace/tests/support/`).
These suites are the negative evidence for the daemon trust boundary and must
keep running unmodified: `real_repository.rs` (hostile hooks and home config
never execute, repository-local clean filters are refused, worktree-shaped
directories, sequencer state, symlink writes, duplicate and out-of-scope paths,
oversized preimages, and deletes of absent paths are refused before any
mutation), `clone_safety.rs` and `mirror_clone.rs`, `cas.rs`,
`preservation_authority.rs`, `crates/bullet-gitd/tests/authority_gateway.rs`,
`crates/bullet-gitd/tests/daemon_roundtrip.rs`, and
`crates/bullet-git-journal/tests/durable.rs`. Full detail lives in `ops/AGENTS.md`.

## No skip-green

- A missing tool fails its lane (`require_tool` in `ops/ci/lib.sh`,
  `scripts/ci-doctor.sh` for pinned versions). Do not add `|| true`,
  `continue-on-error`, or a fallback.
- Exit 78 from the nightly lane is "unregistered", never success.
- `ops/ci/aggregate.sh` rejects failed, skipped, cancelled, or missing jobs and
  missing observations; `aggregate-test.sh` proves every branch.
- No `#[ignore]` to get past a platform gap: when a primitive is missing the code
  returns a typed unsupported error and the test asserts that error.
- `AUDIT_FLOOR` in `ops/ci/audit.sh` only ever rises.

## Budgets and stop conditions

The component has no paid or metered surface. Test, lint, docs, coverage, and
platform-refusal behavior is local; security/advisory refresh and scheduled
external-link checks use outbound network and fail red when truth is unavailable.

- Time budget: nextest slow-timeout terminates a test after 2 periods (20 s fast,
  30 s default, 45 s contract). Hosted jobs carry a 5-25 minute timeout.
- Quota: no provider, model, or metered API is called from any lane. The word
  "token" in this repository means an authority token, never an API billing unit;
  `agent/audit-policy.toml` declares the empty cost surface explicitly.
- Network stop condition: no lane mutates a forge. RustSec refresh and scheduled
  link checks are read-only exceptions. `ops/ci/lib.sh` exports
  `GIT_TERMINAL_PROMPT=0` and `SafeGit` forces `protocol.file.allow=never`
  (`user` only for the single mirror-to-clone call), an empty `core.hooksPath`,
  an empty `credential.helper`, and a denying `GIT_ASKPASS`.
- Kill switch: absent or invalid Kernel transport, permit, check, or settlement
  authority makes a fresh daemon refuse `clone`; an unconfigured daemon reports
  `AUTHORITY_CONTRACT_UNAVAILABLE`. An in-flight reservation that survives a
  restart freezes further mutation as `MUTATION_OUTCOME_UNKNOWN` instead of
  being re-authorized.
