//! Private-clone lifecycle and the sole workspace writer for BulletGit.
//!
//! Every Git invocation goes through [`SafeGit`], which isolates the process
//! environment (spec §20.3). [`PrivateClone`] implements the §20.2 creation
//! steps; [`RealRepository`] implements the capability API over a real clone.

mod apply;
mod clone;
mod git_config;
mod mirror;
mod patch;
mod repository;
mod safe_git;
mod scope;
mod status;

pub use clone::{CloneRequest, PreservationReceipt, PrivateClone, WorkspaceManifest};
pub use mirror::{mirror_dir, MirrorLock, LOCK_MAX_WAIT, LOCK_STALE_AFTER};
pub use patch::{validate_batch, PatchHunk, PatchOp};
pub use repository::{AgentRepository, CommitIdentity, ExpectedAuthority, RealRepository};
pub use safe_git::{FileProtocol, GitOutput, HeadState, SafeGit};
pub use scope::{normalize_rel_path, ScopeGrant};

use bullet_git_types::{AuthorityError, TypesError};
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
    /// Path is outside the granted scope.
    #[error("path out of scope: {0}")]
    OutOfScope(String),
    /// A delete patch targeted a path with no regular file behind it.
    #[error("no regular file to delete at: {0}")]
    PathAbsent(String),
    /// A batch named the same normalized path more than once.
    #[error("duplicate or conflicting patch path: {0}")]
    DuplicatePath(String),
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
    /// Cleanup was requested with a nonce that does not match the manifest.
    #[error("cleanup nonce mismatch")]
    CleanupNonceMismatch,
    /// Cleanup was requested without a verified preservation receipt.
    #[error("cleanup requires a verified preservation receipt: {0}")]
    CleanupReceiptRequired(String),
    /// A git command exited unsuccessfully.
    #[error("git command failed: {0}")]
    Git(String),
    /// Durable workspace journal could not append or recover safely.
    #[error("workspace journal failed: {0}")]
    Journal(String),
    /// Repository-local Git configuration could execute code or redirect truth.
    #[error("hostile repository-local git config: {0}")]
    HostileGitConfig(String),
    /// Filesystem or process failure.
    #[error("workspace io failure: {0}")]
    Io(String),
    /// Identity or object-id validation failure.
    #[error("invalid identity or oid: {0}")]
    Types(String),
}

impl CapabilityError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Unauthorized(_) => "UNAUTHORIZED",
            Self::StaleAuthority(_) => "STALE_AUTHORITY",
            Self::OutOfScope(_) => "OUT_OF_SCOPE",
            Self::PathAbsent(_) => "PATH_ABSENT",
            Self::DuplicatePath(_) => "DUPLICATE_PATH",
            Self::PathCollision { .. } => "PATH_COLLISION",
            Self::SymlinkForbidden(_) => "SYMLINK_FORBIDDEN",
            Self::WorktreeForbidden(_) => "WORKTREE_FORBIDDEN",
            Self::WrongRepository(_) => "WRONG_REPOSITORY",
            Self::WrongBranch { .. } => "WRONG_BRANCH",
            Self::SequencerActive(_) => "SEQUENCER_ACTIVE",
            Self::UnclassifiedUntracked(_) => "UNCLASSIFIED_UNTRACKED",
            Self::BaseMissing(_) => "BASE_MISSING",
            Self::MirrorLockTimeout(_) => "MIRROR_LOCK_TIMEOUT",
            Self::CleanupNonceMismatch => "CLEANUP_NONCE_MISMATCH",
            Self::CleanupReceiptRequired(_) => "CLEANUP_RECEIPT_REQUIRED",
            Self::Git(_) => "GIT_FAILED",
            Self::Journal(_) => "JOURNAL_FAILED",
            Self::HostileGitConfig(_) => "HOSTILE_GIT_CONFIG",
            Self::Io(_) => "IO_FAILED",
            Self::Types(_) => "INVALID_TYPES",
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
