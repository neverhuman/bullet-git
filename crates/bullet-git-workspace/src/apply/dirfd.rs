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

impl StagedRoot {
    /// Open `root` as a directory without following a final-component symlink.
    pub(crate) fn open(root: &Path) -> Result<Self, DirfdError> {
        let fd = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| classify(errno, &root.display().to_string(), "open staged root"))?;
        Ok(Self { fd })
    }

    /// Read the regular file at `path`; `Ok(None)` when nothing exists there.
    pub(crate) fn read(&self, path: &str) -> Result<Option<Vec<u8>>, DirfdError> {
        validate_path(path)?;
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let fd = match open_beneath(self.fd.as_fd(), path, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(errno) => return Err(self.diagnose(errno, path, "open prior bytes")),
        };
        require_regular(&fd, path, "inspect prior bytes")?;
        let mut bytes = Vec::new();
        File::from(fd)
            .read_to_end(&mut bytes)
            .map_err(|error| io(path, "read prior bytes", &error))?;
        Ok(Some(bytes))
    }

    /// Create or truncate the regular file at `path`, write `bytes`, fsync.
    pub(crate) fn write(&self, path: &str, bytes: &[u8]) -> Result<(), DirfdError> {
        let components = validate_path(path)?;
        let Some((leaf, directories)) = components.split_last() else {
            return Err(DirfdError::InvalidPath {
                path: path.to_owned(),
                reason: "empty path",
            });
        };
        let parent = self.ensure_directories(path, directories)?;
        let parent = parent.as_ref().map_or(self.fd.as_fd(), AsFd::as_fd);
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let fd = open_beneath(parent, leaf, flags, Mode::from_raw_mode(0o666))
            .map_err(|errno| self.diagnose(errno, path, "open patch target"))?;
        require_regular(&fd, path, "inspect patch target")?;
        ftruncate(&fd, 0).map_err(|errno| classify(errno, path, "truncate patch target"))?;
        let mut file = File::from(fd);
        file.write_all(bytes)
            .map_err(|error| io(path, "write patch target", &error))?;
        file.sync_all()
            .map_err(|error| io(path, "fsync patch target", &error))
    }

    /// Unlink the regular file at `path`; symlinks and non-files are refused.
    pub(crate) fn unlink(&self, path: &str) -> Result<(), DirfdError> {
        let components = validate_path(path)?;
        let Some((leaf, directories)) = components.split_last() else {
            return Err(DirfdError::InvalidPath {
                path: path.to_owned(),
                reason: "empty path",
            });
        };
        let parent = self.open_parent(path, directories)?;
        let parent = parent.as_ref().map_or(self.fd.as_fd(), AsFd::as_fd);
        let stat = match statat(parent, *leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => {
                return Err(DirfdError::Absent {
                    path: path.to_owned(),
                })
            }
            Err(errno) => return Err(self.diagnose(errno, path, "inspect delete target")),
        };
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => {}
            FileType::Symlink => {
                return Err(DirfdError::Symlink {
                    path: path.to_owned(),
                })
            }
            _ => {
                return Err(DirfdError::NotRegularFile {
                    path: path.to_owned(),
                })
            }
        }
        unlinkat(parent, *leaf, AtFlags::empty())
            .map_err(|errno| self.diagnose(errno, path, "unlink delete target"))
    }

    /// Restore prior states in reverse order; every failure is aggregated.
    ///
    /// `Some(bytes)` rewrites the file; `None` removes it, and an already
    /// absent file counts as restored.
    pub(crate) fn restore<'a>(
        &self,
        entries: impl Iterator<Item = (&'a str, Option<&'a [u8]>)>,
    ) -> Result<(), DirfdError> {
        let mut failures = Vec::new();
        for (path, prior) in entries {
            let outcome = match prior {
                Some(bytes) => self.write(path, bytes),
                None => match self.unlink(path) {
                    Err(DirfdError::Absent { .. }) => Ok(()),
                    other => other,
                },
            };
            if let Err(error) = outcome {
                failures.push(RestoreFailure {
                    path: path.to_owned(),
                    reason_code: error.reason_code(),
                    message: error.to_string(),
                });
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(DirfdError::Restore { failures })
        }
    }

    /// Open the directory holding the leaf without creating anything.
    fn open_parent(&self, path: &str, directories: &[&str]) -> Result<Option<OwnedFd>, DirfdError> {
        if directories.is_empty() {
            return Ok(None);
        }
        open_directory(self.fd.as_fd(), &directories.join("/"))
            .map(Some)
            .map_err(|errno| self.diagnose(errno, path, "open delete directory"))
    }

    /// Turn a kernel refusal into the exact typed reason. `openat2` reports a
    /// forbidden symlink component as `ELOOP` or, when `O_DIRECTORY` or a later
    /// component is involved, as `ENOTDIR`; a no-follow walk over the components
    /// tells the two apart. The walk is diagnostic only: safety came from the
    /// refused open itself.
    fn diagnose(&self, errno: Errno, path: &str, context: &'static str) -> DirfdError {
        if matches!(errno, Errno::NOTDIR | Errno::LOOP) {
            if let Some(found) = self.locate_offender(path) {
                return found;
            }
        }
        classify(errno, path, context)
    }

    fn locate_offender(&self, path: &str) -> Option<DirfdError> {
        let components = validate_path(path).ok()?;
        let last = components.len().checked_sub(1)?;
        let mut current: Option<OwnedFd> = None;
        for (index, component) in components.iter().enumerate() {
            let parent = current.as_ref().map_or(self.fd.as_fd(), AsFd::as_fd);
            let stat = statat(parent, *component, AtFlags::SYMLINK_NOFOLLOW).ok()?;
            match FileType::from_raw_mode(stat.st_mode) {
                FileType::Symlink => {
                    return Some(DirfdError::Symlink {
                        path: path.to_owned(),
                    })
                }
                FileType::Directory => {}
                _ if index < last => {
                    return Some(DirfdError::NotDirectory {
                        path: path.to_owned(),
                    })
                }
                _ => return None,
            }
            current = Some(open_directory(parent, component).ok()?);
        }
        None
    }

    /// Walk (and create when absent) each directory component one level at
    /// a time so no `mkdir` ever crosses a symlink.
    fn ensure_directories(
        &self,
        path: &str,
        directories: &[&str],
    ) -> Result<Option<OwnedFd>, DirfdError> {
        let mut current: Option<OwnedFd> = None;
        for component in directories {
            let parent = current.as_ref().map_or(self.fd.as_fd(), AsFd::as_fd);
            let next = match open_directory(parent, component) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => {
                    match mkdirat(parent, *component, Mode::from_raw_mode(0o777)) {
                        Ok(()) | Err(Errno::EXIST) => {}
                        Err(errno) => {
                            return Err(self.diagnose(errno, path, "create patch directory"))
                        }
                    }
                    open_directory(parent, component).map_err(|errno| {
                        self.diagnose(errno, path, "open created patch directory")
                    })?
                }
                Err(errno) => return Err(self.diagnose(errno, path, "open patch directory")),
            };
            current = Some(next);
        }
        Ok(current)
    }
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
