//! Reflink-or-fallback tree copy for private clone materialization.
//!
//! On a CoW filesystem, `cp --reflink=always` is the fast path. Anywhere that
//! command cannot prove a reflink, the fallback walks regular files so the
//! destination is byte-identical and later mirror GC cannot reach it.

use crate::{io_err, CapabilityError};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Which copy path produced the destination tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyMode {
    /// `cp --reflink=always` succeeded.
    Reflink,
    /// Byte-identical walk copy after reflink was refused.
    Fallback,
}

/// Copy `source` to an absent `destination`, preferring CoW.
///
/// # Errors
///
/// `IO_FAILED` when the source is not a directory, the destination exists, or
/// both copy paths fail.
pub fn copy_tree_prefers_reflink(
    source: &Path,
    destination: &Path,
) -> Result<CopyMode, CapabilityError> {
    require_copy_pair(source, destination)?;
    if try_reflink(source, destination)? {
        return Ok(CopyMode::Reflink);
    }
    copy_tree_byte_identical(source, destination)?;
    Ok(CopyMode::Fallback)
}

/// Walk-copy regular files and directories so destination bytes equal source.
///
/// # Errors
///
/// `IO_FAILED` on a missing source, existing destination, symlink, or special.
pub fn copy_tree_byte_identical(source: &Path, destination: &Path) -> Result<(), CapabilityError> {
    require_copy_pair(source, destination)?;
    copy_entries(source, destination)
}

fn require_copy_pair(source: &Path, destination: &Path) -> Result<(), CapabilityError> {
    let metadata =
        fs::symlink_metadata(source).map_err(|err| io_err("inspect copy source", &err))?;
    if !metadata.file_type().is_dir() {
        return Err(CapabilityError::Io(format!(
            "copy source is not a directory: {}",
            source.display()
        )));
    }
    if destination.exists() {
        return Err(CapabilityError::Io(format!(
            "copy destination already exists: {}",
            destination.display()
        )));
    }
    Ok(())
}

fn try_reflink(source: &Path, destination: &Path) -> Result<bool, CapabilityError> {
    let status = Command::new("cp")
        .args(["-a", "--reflink=always"])
        .arg(source)
        .arg(destination)
        .status()
        .map_err(|err| io_err("spawn cp --reflink=always", &err))?;
    if status.success() {
        return Ok(true);
    }
    if destination.exists() {
        fs::remove_dir_all(destination)
            .map_err(|err| io_err("remove failed reflink dest", &err))?;
    }
    Ok(false)
}

fn copy_entries(source: &Path, destination: &Path) -> Result<(), CapabilityError> {
    fs::create_dir(destination).map_err(|err| io_err("create fallback directory", &err))?;
    for entry in fs::read_dir(source).map_err(|err| io_err("read copy source", &err))? {
        let entry = entry.map_err(|err| io_err("read copy entry", &err))?;
        let from = entry.path();
        let to = destination.join(entry.file_name());
        let metadata =
            fs::symlink_metadata(&from).map_err(|err| io_err("inspect copy entry", &err))?;
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            copy_entries(&from, &to)?;
        } else if file_type.is_file() {
            fs::copy(&from, &to).map_err(|err| io_err("copy fallback file", &err))?;
        } else {
            return Err(CapabilityError::Io(format!(
                "special filesystem entry is forbidden in fallback copy: {}",
                from.display()
            )));
        }
    }
    Ok(())
}
