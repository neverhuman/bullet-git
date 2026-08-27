//! Private-clone lifecycle and the sole workspace writer for BulletGit.
//!
//! Every Git invocation goes through [`SafeGit`], which isolates the process
//! environment (spec §20.3). [`PrivateClone`] implements the §20.2 creation
//! steps; [`RealRepository`] implements the capability API over a real clone.

mod advisers;
mod apply;
mod cas;
mod clone;
mod fsync;
mod gc;
mod generation;
#[cfg(test)]
mod generation_tests;
mod git_config;
mod lineage;
mod mirror;
mod patch;
mod preservation;
mod preservation_io;
mod reflink;
mod repository;
mod safe_git;
mod scope;
mod status;
mod tree_copy;

pub use advisers::{forecast_conflicts, intent_aware_revert, patch_algebra_disjoint, Advice};
pub use cas::{cas_digest, CasError, CasPut, ImmutableCas, PutDisposition, MAX_CAS_OBJECT_BYTES};
pub use clone::{CloneRequest, PrivateClone, WorkspaceManifest};
pub use gc::{pin_retained_object, retention_ref_exists, RetentionClass, RetentionPin};
pub use generation::{ActiveGenerationBinding, GenerationError, GenerationParentBinding};
#[cfg(feature = "fuzzing")]
pub use git_config::validate_repo_config;
pub use lineage::WorkspaceLineage;
pub use mirror::{mirror_dir, MirrorLock, LOCK_MAX_WAIT, LOCK_STALE_AFTER};
pub use patch::{
    validate_batch, PatchHunk, PatchOp, MAX_AGGREGATE_CONTENT_BYTES, MAX_CONTENT_BYTES,
    MAX_PATCH_OPERATIONS,
};
pub use preservation::{PreservationAuthority, PreservationError, PreservationReceipt};
pub use reflink::{copy_tree_byte_identical, copy_tree_prefers_reflink, CopyMode};
pub use repository::{AgentRepository, CommitIdentity, ExpectedAuthority, RealRepository};
pub use safe_git::{
    FileProtocol, GitBounds, GitOutput, HeadState, PinSource, PinnedGit, SafeGit,
    SYSTEM_GIT_CANDIDATES,
};
pub use scope::{normalize_rel_path, ScopeGrant};

use bullet_git_types::{
    AuthorityError, CandidateManifestError, LineageError, ProposalError, TypesError,
};
use thiserror::Error;

/// Capability error with stable reason codes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CapabilityError {
    /// Missing, empty, or unparseable authority token.
    #[error("authority required: {0}")]
    Unauthorized(String),
    /// Token names a different attempt, fence, or workspace nonce.
    #[error("stale authority: {0}")]
    StaleAuthority(String),
    /// Proposal attempt does not name the active writer incarnation.
    #[error("proposal attempt mismatch: expected {expected}, found {found}")]
    ProposalAttemptMismatch {
        /// Active writer attempt.
        expected: String,
        /// Proposal-producing attempt.
        found: String,
    },
    /// Candidate provenance differs from an active writer or repository fact.
    #[error("candidate subject mismatch at {field}: expected {expected}, found {found}")]
    CandidateSubjectMismatch {
        /// Exact field that differed.
        field: &'static str,
        /// Active local subject.
        expected: String,
        /// Caller-supplied subject.
        found: String,
    },
    /// Proposal base checkpoint does not equal the active checkpoint.
    #[error("stale proposal checkpoint: {0}")]
    StaleCheckpoint(String),
    /// Proposal path precondition does not equal current bytes/absence.
    #[error("stale proposal preimage at {0}")]
    StalePreimage(String),
    /// Path is outside the granted scope.
    #[error("path out of scope: {0}")]
    OutOfScope(String),
    /// A delete patch targeted a path with no regular file behind it.
    #[error("no regular file to delete at: {0}")]
    PathAbsent(String),
    /// A batch named the same normalized path more than once.
    #[error("duplicate or conflicting patch path: {0}")]
    DuplicatePath(String),
    /// A patch batch was empty or exceeded the admitted operation bound.
    #[error("patch operation count is outside 1..={max}: {actual}")]
    InvalidOperationCount {
        /// Admitted upper bound.
        max: usize,
        /// Received operation count.
        actual: usize,
    },
    /// One write exceeded the admitted byte bound.
    #[error("patch contents too large at {path}: {actual} bytes exceeds {max}")]
    ContentTooLarge {
        /// Refused normalized path.
        path: String,
        /// Admitted upper bound.
        max: usize,
        /// Received content length.
        actual: usize,
    },
    /// The sum of all write bodies exceeded the admitted byte bound.
    #[error("aggregate patch contents too large: {actual} bytes exceeds {max}")]
    AggregateContentTooLarge {
        /// Admitted aggregate upper bound.
        max: usize,
        /// Received aggregate content length.
        actual: usize,
    },
    /// Two paths collide after portable case folding.
    #[error("portable path collision: {first} conflicts with {second}")]
    PathCollision {
        /// First admitted spelling.
        first: String,
        /// Conflicting spelling.
        second: String,
    },
    /// Path traverses or targets a symlink.
    #[error("symlink writes are forbidden: {0}")]
    SymlinkForbidden(String),
    /// Workspace is a Git worktree (`.git` is a file).
    #[error("writable worktrees are forbidden: {0}")]
    WorktreeForbidden(String),
    /// Repository toplevel does not match the expected workspace.
    #[error("repository toplevel mismatch: {0}")]
    WrongRepository(String),
    /// HEAD is not on the expected private branch.
    #[error("expected branch {expected}, found {found}")]
    WrongBranch {
        /// The private branch the workspace was created with.
        expected: String,
        /// What HEAD actually points at.
        found: String,
    },
    /// A cherry-pick, merge, or rebase is in flight.
    #[error("sequencer state present: {0}")]
    SequencerActive(String),
    /// An untracked file outside the granted scope was found at prepare time.
    #[error("unclassified untracked file outside scope: {0}")]
    UnclassifiedUntracked(String),
    /// Requested base SHA does not exist in the source repository.
    #[error("base sha not found in source: {0}")]
    BaseMissing(String),
    /// The exclusive mirror lock could not be acquired within the bound.
    #[error("mirror lock wait timed out: {0}")]
    MirrorLockTimeout(String),
    /// A git command exited unsuccessfully.
    #[error("git command failed: {0}")]
    Git(String),
    /// Durable workspace journal could not append or recover safely.
    #[error("workspace journal failed: {0}")]
    Journal(String),
    /// Immutable content storage failed or has an indeterminate publication.
    #[error(transparent)]
    ContentStore(#[from] CasError),
    /// Immutable workspace generation failed or has an indeterminate switch.
    #[error(transparent)]
    Generation(#[from] GenerationError),
    /// Preservation or sealed cleanup authorization failed.
    #[error(transparent)]
    Preservation(#[from] PreservationError),
    /// Repository-local Git configuration could execute code or redirect truth.
    #[error("hostile repository-local git config: {0}")]
    HostileGitConfig(String),
    /// Pinned Git binary verification, staging, or bounded execution failed.
    #[error(transparent)]
    GitBinary(#[from] GitBinaryError),
    /// Filesystem or process failure.
    #[error("workspace io failure: {0}")]
    Io(String),
    /// Identity or object-id validation failure.
    #[error("invalid identity or oid: {0}")]
    Types(String),
    /// Canonical proposal validation failed.
    #[error(transparent)]
    Proposal(#[from] ProposalError),
    /// Canonical Candidate manifest validation failed.
    #[error(transparent)]
    CandidateManifest(#[from] CandidateManifestError),
    /// Change lineage query or record failed.
    #[error(transparent)]
    Lineage(#[from] LineageError),
}

impl CapabilityError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Unauthorized(_) => "UNAUTHORIZED",
            Self::StaleAuthority(_) => "STALE_AUTHORITY",
            Self::ProposalAttemptMismatch { .. } => "PROPOSAL_ATTEMPT_MISMATCH",
            Self::CandidateSubjectMismatch { .. } => "CANDIDATE_SUBJECT_MISMATCH",
            Self::StaleCheckpoint(_) => "STALE_CHECKPOINT",
            Self::StalePreimage(_) => "STALE_PREIMAGE",
            Self::OutOfScope(_) => "OUT_OF_SCOPE",
            Self::PathAbsent(_) => "PATH_ABSENT",
            Self::DuplicatePath(_) => "DUPLICATE_PATH",
            Self::InvalidOperationCount { .. } => "INVALID_OPERATION_COUNT",
            Self::ContentTooLarge { .. } => "CONTENT_TOO_LARGE",
            Self::AggregateContentTooLarge { .. } => "AGGREGATE_CONTENT_TOO_LARGE",
            Self::PathCollision { .. } => "PATH_COLLISION",
            Self::SymlinkForbidden(_) => "SYMLINK_FORBIDDEN",
            Self::WorktreeForbidden(_) => "WORKTREE_FORBIDDEN",
            Self::WrongRepository(_) => "WRONG_REPOSITORY",
            Self::WrongBranch { .. } => "WRONG_BRANCH",
            Self::SequencerActive(_) => "SEQUENCER_ACTIVE",
            Self::UnclassifiedUntracked(_) => "UNCLASSIFIED_UNTRACKED",
            Self::BaseMissing(_) => "BASE_MISSING",
            Self::MirrorLockTimeout(_) => "MIRROR_LOCK_TIMEOUT",
            Self::Git(_) => "GIT_FAILED",
            Self::Journal(_) => "JOURNAL_FAILED",
            Self::ContentStore(error) => error.reason_code(),
            Self::Generation(error) => error.reason_code(),
            Self::Preservation(error) => error.reason_code(),
            Self::HostileGitConfig(_) => "HOSTILE_GIT_CONFIG",
            Self::GitBinary(error) => error.reason_code(),
            Self::Io(_) => "IO_FAILED",
            Self::Types(_) => "INVALID_TYPES",
            Self::Proposal(error) => error.reason_code(),
            Self::CandidateManifest(error) => error.reason_code(),
            Self::Lineage(error) => error.reason_code(),
        }
    }
}

impl From<bullet_git_journal::JournalError> for CapabilityError {
    fn from(error: bullet_git_journal::JournalError) -> Self {
        Self::Journal(format!("{}: {error}", error.reason_code()))
    }
}

impl From<AuthorityError> for CapabilityError {
    fn from(err: AuthorityError) -> Self {
        match err {
            AuthorityError::Unauthorized(msg) => Self::Unauthorized(msg),
            AuthorityError::StaleAuthority(msg) => Self::StaleAuthority(msg),
        }
    }
}

impl From<TypesError> for CapabilityError {
    fn from(err: TypesError) -> Self {
        Self::Types(err.to_string())
    }
}

pub(crate) fn io_err(context: &str, err: &std::io::Error) -> CapabilityError {
    CapabilityError::Io(format!("{context}: {err}"))
}

/// Typed refusal from Git binary pinning, staging, or bounded execution.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GitBinaryError {
    /// The pin path is not absolute.
    #[error("git binary path must be absolute: {0}")]
    PathNotAbsolute(String),
    /// The pin path is missing or its metadata/bytes cannot be read.
    #[error("git binary unreadable at {path}: {reason}")]
    Unreadable {
        /// Refused path.
        path: String,
        /// Operating-system reason.
        reason: String,
    },
    /// The pin path is a symbolic link.
    #[error("git binary is a symlink: {0}")]
    Symlink(String),
    /// The pin path is not a regular file.
    #[error("git binary is not a regular file: {0}")]
    NotRegular(String),
    /// The pin path has no execute bit.
    #[error("git binary is not executable: {0}")]
    NotExecutable(String),
    /// The file bytes hash to a different digest than expected.
    #[error("git binary digest mismatch at {path}: expected {expected}, found {actual}")]
    DigestMismatch {
        /// Refused path.
        path: String,
        /// Caller-expected digest hex.
        expected: String,
        /// Digest hex actually observed.
        actual: String,
    },
    /// The verified bytes could not be staged into a sealed memfd or the
    /// staged descriptor could not be prepared for execution.
    #[error("git binary staging failed for {path}: {reason}")]
    Staging {
        /// Pinned path.
        path: String,
        /// Operating-system reason.
        reason: String,
    },
    /// A different default binary is already installed for this process.
    #[error("a different git binary is already pinned for this process: {0}")]
    AlreadyPinned(String),
    /// No fixed candidate location holds an admissible binary.
    #[error("no admissible system git at any of {SYSTEM_GIT_CANDIDATES:?}: {0}")]
    NotFound(String),
    /// The child ran past its wall-clock deadline and was killed.
    #[error("git {verb} exceeded the {limit_ms} ms deadline")]
    DeadlineExceeded {
        /// Git subcommand.
        verb: String,
        /// Configured deadline in milliseconds.
        limit_ms: u128,
    },
    /// The child produced more bytes on one stream than admitted.
    #[error("git {verb} exceeded the {limit} byte {stream} bound")]
    OutputBoundExceeded {
        /// Git subcommand.
        verb: String,
        /// `stdout` or `stderr`.
        stream: &'static str,
        /// Configured bound in bytes.
        limit: usize,
    },
}

impl GitBinaryError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::PathNotAbsolute(_) => "GIT_BINARY_PATH_NOT_ABSOLUTE",
            Self::Unreadable { .. } => "GIT_BINARY_UNREADABLE",
            Self::Symlink(_) => "GIT_BINARY_SYMLINK",
            Self::NotRegular(_) => "GIT_BINARY_NOT_REGULAR",
            Self::NotExecutable(_) => "GIT_BINARY_NOT_EXECUTABLE",
            Self::DigestMismatch { .. } => "GIT_BINARY_DIGEST_MISMATCH",
            Self::Staging { .. } => "GIT_BINARY_STAGING_FAILED",
            Self::AlreadyPinned(_) => "GIT_BINARY_ALREADY_PINNED",
            Self::NotFound(_) => "GIT_BINARY_NOT_FOUND",
            Self::DeadlineExceeded { .. } => "GIT_DEADLINE_EXCEEDED",
            Self::OutputBoundExceeded { .. } => "GIT_OUTPUT_BOUND_EXCEEDED",
        }
    }
}
