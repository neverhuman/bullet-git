//! Snapshot-rollback apply for a validated patch batch.
//!
//! Every mutation is descriptor-relative to the staged generation root (see
//! [`dirfd`]): the root is opened once and each directory creation, write,
//! and unlink is resolved by the kernel beneath that descriptor with symlinks
//! forbidden, so a symlink swapped in after validation is refused instead of
//! followed. A failed batch is rolled back through the same descriptor.

#[cfg(target_os = "linux")]
mod dirfd;

use crate::patch::{PatchHunk, PatchOp};
use crate::{CapabilityError, GenerationError};
use std::path::{Path, PathBuf};

/// Apply every hunk beneath `root`, fsyncing each written file.
///
/// On success `undo` receives every prior state, oldest first. On failure the
/// batch has already been rolled back through the root descriptor and the
/// typed error names the exact refused path; only entries whose rollback was
/// itself refused are left in `undo` for [`restore_all`].
///
/// # Errors
///
/// `OUT_OF_SCOPE` for a malformed path, `SYMLINK_FORBIDDEN` for any symlink
/// component or target, `PATH_ABSENT` for a delete without a regular file,
/// `IO_FAILED` otherwise.
#[cfg(target_os = "linux")]
pub fn apply_all(
    root: &Path,
    patches: &[PatchHunk],
    normalized: &[String],
    undo: &mut Vec<(PathBuf, Option<Vec<u8>>)>,
) -> Result<(), CapabilityError> {
    let staged = dirfd::StagedRoot::open(root).map_err(refusal)?;
    let mut applied: Vec<(String, Option<Vec<u8>>)> = Vec::with_capacity(patches.len());
    if let Err(error) = apply_each(&staged, patches, normalized, &mut applied) {
        let rollback = staged.restore(
            applied
                .iter()
                .rev()
                .map(|(path, prior)| (path.as_str(), prior.as_deref())),
        );
        if let Err(dirfd::DirfdError::Restore { failures }) = rollback {
            for failure in failures {
                if let Some((path, prior)) = applied.iter().find(|(path, _)| *path == failure.path)
                {
                    undo.push((root.join(path), prior.clone()));
                }
            }
        }
        return Err(error);
    }
    undo.extend(
        applied
            .into_iter()
            .map(|(path, prior)| (root.join(path), prior)),
    );
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_each(
    staged: &dirfd::StagedRoot,
    patches: &[PatchHunk],
    normalized: &[String],
    applied: &mut Vec<(String, Option<Vec<u8>>)>,
) -> Result<(), CapabilityError> {
    for (patch, path) in patches.iter().zip(normalized) {
        let prior = staged.read(path).map_err(refusal)?;
        applied.push((path.clone(), prior));
        match &patch.op {
            PatchOp::Write(contents) => staged.write(path, contents).map_err(refusal)?,
            PatchOp::Delete => staged.unlink(path).map_err(refusal)?,
        }
    }
    Ok(())
}

/// Restore prior states that [`apply_all`] could not roll back itself.
///
/// Entries are absolute paths beneath a staged root. Each is resolved from the
/// filesystem root with the same no-symlink policy as the apply path, so this
/// fallback can refuse but never write through a symlink. Returns `None` when
/// every entry was restored, otherwise one aggregated `GENERATION_IO_FAILED`
/// refusal naming every path that stayed unrestored.
#[cfg(target_os = "linux")]
pub fn restore_all(undo: &[(PathBuf, Option<Vec<u8>>)]) -> Option<CapabilityError> {
    if undo.is_empty() {
        return None;
    }
    let filesystem_root = match dirfd::StagedRoot::open(Path::new("/")) {
        Ok(root) => root,
        Err(error) => return Some(refusal(error)),
    };
    let entries: Vec<(String, Option<&[u8]>)> = undo
        .iter()
        .rev()
        .map(|(target, prior)| {
            let relative = target.to_string_lossy();
            (
                relative.trim_start_matches('/').to_owned(),
                prior.as_deref(),
            )
        })
        .collect();
    filesystem_root
        .restore(entries.iter().map(|(path, prior)| (path.as_str(), *prior)))
        .err()
        .map(refusal)
}

impl CapabilityError {
    /// Compose a refused apply with a refused rollback of that same batch.
    ///
    /// The result is `GENERATION_IO_FAILED` because the staged generation is
    /// no longer in a known state; its message carries the original refusal
    /// with its reason code and the aggregated list of every unrestored path.
    #[must_use]
    pub fn with_failed_rollback(self, rollback: &CapabilityError) -> CapabilityError {
        CapabilityError::Generation(GenerationError::Io(format!(
            "apply refused with {}: {self}; {rollback}",
            self.reason_code()
        )))
    }
}

#[cfg(target_os = "linux")]
fn refusal(error: dirfd::DirfdError) -> CapabilityError {
    use dirfd::DirfdError;
    match error {
        DirfdError::InvalidPath { path, reason } => {
            CapabilityError::OutOfScope(format!("{path}: {reason}"))
        }
        DirfdError::Symlink { path } => CapabilityError::SymlinkForbidden(path),
        DirfdError::Absent { path } | DirfdError::NotRegularFile { path } => {
            CapabilityError::PathAbsent(path)
        }
        DirfdError::Restore { .. } => {
            CapabilityError::Generation(GenerationError::Io(error.to_string()))
        }
        DirfdError::NotDirectory { .. } | DirfdError::Io { .. } => {
            CapabilityError::Io(error.to_string())
        }
    }
}

/// Descriptor-relative writes require the admitted Linux `openat2` backend.
#[cfg(not(target_os = "linux"))]
pub fn apply_all(
    _root: &Path,
    _patches: &[PatchHunk],
    _normalized: &[String],
    _undo: &mut Vec<(PathBuf, Option<Vec<u8>>)>,
) -> Result<(), CapabilityError> {
    Err(CapabilityError::Io(
        "descriptor-relative patch writes require the admitted Linux openat2 backend".into(),
    ))
}

/// Nothing can have been applied without the Linux backend, so only a
/// non-empty undo list is reportable.
#[cfg(not(target_os = "linux"))]
pub fn restore_all(undo: &[(PathBuf, Option<Vec<u8>>)]) -> Option<CapabilityError> {
    (!undo.is_empty()).then(|| {
        CapabilityError::Io(
            "descriptor-relative rollback requires the admitted Linux openat2 backend".into(),
        )
    })
}
