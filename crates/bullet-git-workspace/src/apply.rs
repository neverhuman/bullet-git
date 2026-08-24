//! Snapshot-rollback apply for a validated patch batch.

use crate::patch::{PatchHunk, PatchOp};
use crate::{io_err, CapabilityError};
use std::fs;
use std::path::{Path, PathBuf};

/// Apply every hunk. On error the caller must [`restore_all`].
pub fn apply_all(
    root: &Path,
    patches: &[PatchHunk],
    normalized: &[String],
    undo: &mut Vec<(PathBuf, Option<Vec<u8>>)>,
) -> Result<(), CapabilityError> {
    for (patch, path) in patches.iter().zip(normalized) {
        let target = root.join(path);
        let prior = if target.exists() {
            Some(fs::read(&target).map_err(|err| io_err("snapshot patch target", &err))?)
        } else {
            None
        };
        undo.push((target.clone(), prior));
        match &patch.op {
            PatchOp::Write(contents) => {
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent).map_err(|err| io_err("create patch dir", &err))?;
                }
                fs::write(&target, contents).map_err(|err| io_err("write patch", &err))?;
            }
            PatchOp::Delete => {
                fs::remove_file(&target).map_err(|err| io_err("delete patch target", &err))?;
            }
        }
    }
    Ok(())
}

/// Restore prior file bytes after a failed apply.
pub fn restore_all(undo: &[(PathBuf, Option<Vec<u8>>)]) {
    for (target, prior) in undo.iter().rev() {
        match prior {
            Some(bytes) => {
                let _ = fs::write(target, bytes);
            }
            None => {
                let _ = fs::remove_file(target);
            }
        }
    }
}
