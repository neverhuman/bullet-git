//! Descriptor-relative mutation of one staged generation root.
//!
//! Every directory creation, open-create, read, and unlink is resolved by the
//! kernel strictly beneath one directory descriptor opened on the staged
//! generation root, using `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
//! RESOLVE_NO_MAGICLINKS)` with `O_NOFOLLOW | O_CLOEXEC`. A symlink swapped
//! into any component after validation is refused at the open itself rather
//! than detected by a racy pre-check. Every written file is fsynced before the
//! generation tree sync.
//!
//! This module depends only on `std` and `rustix` so the integration suite
//! can compile the exact same source against a hostile fixture tree.

#[path = "dirfd_stage.rs"]
mod stage;

use rustix::fs::{
    fstat, ftruncate, mkdirat, open, openat2, statat, unlinkat, AtFlags, FileType, Mode, OFlags,
    ResolveFlags,
};
use rustix::io::Errno;
use std::fmt;
use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

/// Kernel-enforced resolution policy for every descriptor-relative open.
const RESOLVE: ResolveFlags = ResolveFlags::BENEATH
    .union(ResolveFlags::NO_SYMLINKS)
    .union(ResolveFlags::NO_MAGICLINKS);

/// Bounded retries for `EAGAIN`, which `RESOLVE_BENEATH` reports when a
/// concurrent rename interrupted safe resolution.
const RESOLUTION_RETRIES: u8 = 16;

/// One path that a rollback could not restore.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RestoreFailure {
    /// Root-relative path that stayed unrestored.
    pub(crate) path: String,
    /// Stable reason code of the underlying refusal.
    pub(crate) reason_code: &'static str,
    /// Human-readable refusal.
    pub(crate) message: String,
}

/// Typed refusal from the descriptor-relative write path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DirfdError {
    /// Path shape is not a plain root-relative path.
    InvalidPath {
        /// Refused path exactly as received.
        path: String,
        /// Which rule refused it.
        reason: &'static str,
    },
    /// A component or the target is a symlink or magic link.
    Symlink {
        /// Refused root-relative path.
        path: String,
    },
    /// A directory component is backed by a non-directory.
    NotDirectory {
        /// Refused root-relative path.
        path: String,
    },
    /// The delete target does not exist.
    Absent {
        /// Refused root-relative path.
        path: String,
    },
    /// The delete target exists but is not a regular file.
    NotRegularFile {
        /// Refused root-relative path.
        path: String,
    },
    /// Another filesystem failure at the named path.
    Io {
        /// Root-relative path (or the root itself).
        path: String,
        /// Operation that failed.
        context: &'static str,
        /// Operating-system message.
        message: String,
    },
    /// Rollback could not restore every path; every failure is listed.
    Restore {
        /// Every path that stayed unrestored, in rollback order.
        failures: Vec<RestoreFailure>,
    },
}

impl DirfdError {
    /// Stable machine-readable reason code, aligned with `CapabilityError`.
    pub(crate) fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidPath { .. } => "OUT_OF_SCOPE",
            Self::Symlink { .. } => "SYMLINK_FORBIDDEN",
            Self::NotDirectory { .. } | Self::Io { .. } => "IO_FAILED",
            Self::Absent { .. } | Self::NotRegularFile { .. } => "PATH_ABSENT",
            Self::Restore { .. } => "GENERATION_IO_FAILED",
        }
    }
}

impl fmt::Display for DirfdError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPath { path, reason } => write!(formatter, "{reason}: {path:?}"),
            Self::Symlink { path } => write!(formatter, "symlink component or target: {path}"),
            Self::NotDirectory { path } => {
                write!(formatter, "directory component is not a directory: {path}")
            }
            Self::Absent { path } => write!(formatter, "no file to delete at: {path}"),
            Self::NotRegularFile { path } => write!(formatter, "not a regular file: {path}"),
            Self::Io {
                path,
                context,
                message,
            } => write!(formatter, "{context} at {path}: {message}"),
            Self::Restore { failures } => {
                write!(
                    formatter,
                    "rollback refused for {} path(s):",
                    failures.len()
                )?;
                for failure in failures {
                    write!(
                        formatter,
                        " {} [{}: {}];",
                        failure.path, failure.reason_code, failure.message
                    )?;
                }
                Ok(())
            }
        }
    }
}

/// Refuse every path shape that could name something outside the root.
///
/// Returns the slash-separated components on success.
pub(crate) fn validate_path(path: &str) -> Result<Vec<&str>, DirfdError> {
    let refuse = |reason| DirfdError::InvalidPath {
        path: path.to_owned(),
        reason,
    };
    if path.is_empty() {
        return Err(refuse("empty path"));
    }
    if path.starts_with('/') {
        return Err(refuse("absolute path"));
    }
    if path.contains('\\') {
        return Err(refuse("backslash component separator"));
    }
    if path.contains('\0') {
        return Err(refuse("NUL byte"));
    }
    let mut components = Vec::new();
    for component in path.split('/') {
        match component {
            "" => return Err(refuse("empty component")),
            "." => return Err(refuse("dot component")),
            ".." => return Err(refuse("parent traversal component")),
            _ if component.eq_ignore_ascii_case(".git") => {
                return Err(refuse("git metadata component"));
            }
            _ => components.push(component),
        }
    }
    Ok(components)
}

/// The staged generation root, held open for the whole batch.
pub(crate) struct StagedRoot {
    fd: OwnedFd,
}

fn open_directory(parent: BorrowedFd<'_>, relative: &str) -> Result<OwnedFd, Errno> {
    open_beneath(
        parent,
        relative,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
}

fn open_beneath(
    parent: BorrowedFd<'_>,
    relative: &str,
    flags: OFlags,
    mode: Mode,
) -> Result<OwnedFd, Errno> {
    let mut attempt = 0_u8;
    loop {
        match openat2(parent, relative, flags, mode, RESOLVE) {
            Err(Errno::AGAIN) if attempt < RESOLUTION_RETRIES => attempt += 1,
            outcome => return outcome,
        }
    }
}

fn require_regular(fd: &OwnedFd, path: &str, context: &'static str) -> Result<(), DirfdError> {
    let stat = fstat(fd).map_err(|errno| classify(errno, path, context))?;
    if FileType::from_raw_mode(stat.st_mode) == FileType::RegularFile {
        Ok(())
    } else {
        Err(DirfdError::Io {
            path: path.to_owned(),
            context,
            message: "not a regular file".into(),
        })
    }
}

fn classify(errno: Errno, path: &str, context: &'static str) -> DirfdError {
    match errno {
        Errno::LOOP => DirfdError::Symlink {
            path: path.to_owned(),
        },
        Errno::XDEV => DirfdError::InvalidPath {
            path: path.to_owned(),
            reason: "resolution left the staged root",
        },
        Errno::NOTDIR => DirfdError::NotDirectory {
            path: path.to_owned(),
        },
        _ => DirfdError::Io {
            path: path.to_owned(),
            context,
            message: errno.to_string(),
        },
    }
}

fn io(path: &str, context: &'static str, error: &std::io::Error) -> DirfdError {
    DirfdError::Io {
        path: path.to_owned(),
        context,
        message: error.to_string(),
    }
}
