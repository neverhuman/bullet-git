//! Reflink-or-fallback tree copy for private clone materialization.
//!
//! On a CoW filesystem, Linux `FICLONE` is the fast path. Anywhere that
//! primitive cannot prove a reflink, the fallback walks regular files so the
//! destination is byte-identical and later mirror GC cannot reach it.

use crate::{io_err, CapabilityError};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt as _;

/// Which copy path produced the destination tree.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CopyMode {
    /// Linux `FICLONE` succeeded for every regular file.
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
    let summary = copy_with_cleanup(source, destination, true)?;
    Ok(if summary.files > 0 && summary.all_reflink {
        CopyMode::Reflink
    } else {
        CopyMode::Fallback
    })
}

/// Walk-copy regular files and directories so destination bytes equal source.
///
/// # Errors
///
/// `IO_FAILED` on a missing source, existing destination, symlink, or special.
pub fn copy_tree_byte_identical(source: &Path, destination: &Path) -> Result<(), CapabilityError> {
    require_copy_pair(source, destination)?;
    copy_with_cleanup(source, destination, false).map(|_| ())
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

#[derive(Clone, Copy, Debug)]
struct CopySummary {
    files: u64,
    all_reflink: bool,
}

fn copy_with_cleanup(
    source: &Path,
    destination: &Path,
    prefer_reflink: bool,
) -> Result<CopySummary, CapabilityError> {
    match copy_entries(source, destination, prefer_reflink) {
        Ok(summary) => Ok(summary),
        Err(error) => {
            if destination.exists() {
                fs::remove_dir_all(destination)
                    .map_err(|cleanup| io_err("remove failed copy destination", &cleanup))?;
            }
            Err(error)
        }
    }
}

fn copy_entries(
    source: &Path,
    destination: &Path,
    prefer_reflink: bool,
) -> Result<CopySummary, CapabilityError> {
    let source_metadata =
        fs::symlink_metadata(source).map_err(|err| io_err("inspect copy directory", &err))?;
    fs::create_dir(destination).map_err(|err| io_err("create fallback directory", &err))?;
    fs::set_permissions(destination, source_metadata.permissions())
        .map_err(|err| io_err("set copy directory permissions", &err))?;
    let mut summary = CopySummary {
        files: 0,
        all_reflink: true,
    };
    for entry in fs::read_dir(source).map_err(|err| io_err("read copy source", &err))? {
        let entry = entry.map_err(|err| io_err("read copy entry", &err))?;
        let from = entry.path();
        let to = destination.join(entry.file_name());
        let metadata =
            fs::symlink_metadata(&from).map_err(|err| io_err("inspect copy entry", &err))?;
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            let nested = copy_entries(&from, &to, prefer_reflink)?;
            summary.files = summary.files.saturating_add(nested.files);
            summary.all_reflink &= nested.all_reflink;
        } else if file_type.is_file() {
            summary.files = summary.files.saturating_add(1);
            let reflinked = copy_regular_file(&from, &to, &metadata, prefer_reflink)?;
            if !reflinked {
                summary.all_reflink = false;
            }
        } else {
            return Err(CapabilityError::Io(format!(
                "special filesystem entry is forbidden in fallback copy: {}",
                from.display()
            )));
        }
    }
    Ok(summary)
}

fn copy_regular_file(
    source: &Path,
    destination: &Path,
    path_metadata: &fs::Metadata,
    prefer_reflink: bool,
) -> Result<bool, CapabilityError> {
    let mut source_file = File::open(source).map_err(|err| io_err("open copy source", &err))?;
    let opened_metadata = source_file
        .metadata()
        .map_err(|err| io_err("inspect opened copy source", &err))?;
    if !opened_metadata.file_type().is_file()
        || !same_file_identity(path_metadata, &opened_metadata)
    {
        return Err(CapabilityError::Io(format!(
            "copy source changed during admission: {}",
            source.display()
        )));
    }
    let mut destination_file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(destination)
        .map_err(|err| io_err("create copy destination", &err))?;

    #[cfg(target_os = "linux")]
    if prefer_reflink && rustix::fs::ioctl_ficlone(&destination_file, &source_file).is_ok() {
        destination_file
            .set_permissions(path_metadata.permissions())
            .map_err(|err| io_err("set reflink permissions", &err))?;
        return Ok(true);
    }

    let _ = prefer_reflink;
    destination_file
        .set_len(0)
        .map_err(|err| io_err("reset copy destination", &err))?;
    source_file
        .seek(SeekFrom::Start(0))
        .map_err(|err| io_err("seek copy source", &err))?;
    destination_file
        .seek(SeekFrom::Start(0))
        .map_err(|err| io_err("seek copy destination", &err))?;
    copy_bounded(
        &mut source_file,
        &mut destination_file,
        opened_metadata.len(),
    )?;
    destination_file
        .set_permissions(path_metadata.permissions())
        .map_err(|err| io_err("set copy permissions", &err))?;
    Ok(false)
}

fn copy_bounded(
    source: &mut File,
    destination: &mut File,
    expected_len: u64,
) -> Result<(), CapabilityError> {
    let copied = std::io::copy(
        &mut source.take(expected_len.saturating_add(1)),
        destination,
    )
    .map_err(|err| io_err("copy regular file", &err))?;
    if copied != expected_len {
        return Err(CapabilityError::Io(
            "copy source length changed during read".into(),
        ));
    }
    destination
        .flush()
        .map_err(|err| io_err("flush copy destination", &err))
}

#[cfg(unix)]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.dev() == right.dev() && left.ino() == right.ino() && left.len() == right.len()
}

#[cfg(not(unix))]
fn same_file_identity(left: &fs::Metadata, right: &fs::Metadata) -> bool {
    left.len() == right.len() && left.modified().ok() == right.modified().ok()
}
