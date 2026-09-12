//! Descriptor-relative lookup, never canonicalize through symlinks.
use super::{io, Result};
use rustix::fs::{open, openat, Mode, OFlags};
use serde::Serialize;
use std::fs::{File, Metadata};
use std::os::unix::fs::MetadataExt;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct Identity {
    device: String,
    inode: String,
    mode: u32,
    uid: u32,
    gid: u32,
    size: u64,
    links: u64,
    mtime_ns: String,
    ctime_ns: String,
}

impl Identity {
    pub(super) fn of(value: &Metadata) -> Self {
        Self {
            device: value.dev().to_string(),
            inode: value.ino().to_string(),
            mode: value.mode(),
            uid: value.uid(),
            gid: value.gid(),
            size: value.size(),
            links: value.nlink(),
            mtime_ns: (i128::from(value.mtime()) * 1_000_000_000 + i128::from(value.mtime_nsec()))
                .to_string(),
            ctime_ns: (i128::from(value.ctime()) * 1_000_000_000 + i128::from(value.ctime_nsec()))
                .to_string(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub(super) struct Ancestor {
    device: String,
    inode: String,
    mode: u32,
    uid: u32,
    gid: u32,
}

pub(super) fn absolute_parts(path: &str) -> Result<Vec<&str>> {
    if !path.starts_with('/') || path.len() > 4096 || path.contains('\0') {
        return Err("NONNORMAL_ABSOLUTE_PATH".into());
    }
    let parts: Vec<_> = path.split('/').skip(1).collect();
    if parts.iter().any(|part| ["", ".", ".."].contains(part)) {
        return Err("NONNORMAL_ABSOLUTE_PATH".into());
    }
    Ok(parts)
}

pub(super) fn open_parent(path: &str) -> Result<(File, String, Vec<Ancestor>)> {
    let parts = absolute_parts(path)?;
    let directory = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let mut parent = File::from(open("/", directory, Mode::empty()).map_err(io)?);
    let mut lookups = Vec::new();
    for part in &parts[..parts.len() - 1] {
        parent = File::from(openat(&parent, *part, directory, Mode::empty()).map_err(io)?);
        let value = parent.metadata().map_err(io)?;
        lookups.push(Ancestor {
            device: value.dev().to_string(),
            inode: value.ino().to_string(),
            mode: value.mode(),
            uid: value.uid(),
            gid: value.gid(),
        });
    }
    Ok((parent, parts[parts.len() - 1].to_owned(), lookups))
}

pub(super) fn open_candidate(path: &str) -> Result<(File, Vec<Ancestor>)> {
    let (parent, name, lookups) = open_parent(path)?;
    let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC;
    let file = File::from(openat(&parent, name.as_str(), flags, Mode::empty()).map_err(io)?);
    Ok((file, lookups))
}
