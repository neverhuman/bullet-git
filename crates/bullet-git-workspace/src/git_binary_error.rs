//! Typed Git binary pinning refusals.

use super::*;

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
