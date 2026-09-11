//! Bounded descriptor-safe reads and exclusive durable diagnostic outputs.
#[cfg(test)]
#[path = "artifacts_tests.rs"]
mod tests;

use super::{io, paths, Result};
use rustix::fs::{mkdirat, openat, Mode, OFlags};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Write};

pub(super) const MAX_FILE: u64 = 64 * 1024 * 1024;

pub(super) struct Artifact {
    pub(super) bytes: Vec<u8>,
    pub(super) subject: Value,
    path: String,
}

impl Artifact {
    pub(super) fn recheck(&self) -> Result<()> {
        let current = read(&self.path)?;
        if self.subject != current.subject || self.bytes != current.bytes {
            return Err("ARTIFACT_DRIFT".into());
        }
        Ok(())
    }
}

pub(super) fn read(path: &str) -> Result<Artifact> {
    read_with(path, |_| Ok(()))
}

fn read_with(path: &str, after_read: impl FnOnce(&File) -> Result<()>) -> Result<Artifact> {
    let (mut file, ancestors) = paths::open_candidate(path)?;
    let metadata = file.metadata().map_err(io)?;
    if !metadata.is_file() || metadata.len() > MAX_FILE {
        return Err("ARTIFACT_KIND_OR_LIMIT".into());
    }
    let before = paths::Identity::of(&metadata);
    let mut bytes = Vec::new();
    (&mut file)
        .take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(io)?;
    if bytes.len() as u64 > MAX_FILE {
        return Err("ARTIFACT_LIMIT".into());
    }
    after_read(&file)?;
    if before != paths::Identity::of(&file.metadata().map_err(io)?) {
        return Err("ARTIFACT_CHANGED_DURING_READ".into());
    }
    let (current, current_ancestors) = paths::open_candidate(path)?;
    if before != paths::Identity::of(&current.metadata().map_err(io)?)
        || ancestors != current_ancestors
    {
        return Err("ARTIFACT_LOOKUP_CHANGED".into());
    }
    Ok(Artifact {
        subject: json!({"sha256": hex::encode(Sha256::digest(&bytes)),
            "size": bytes.len(), "identity": before}),
        bytes,
        path: path.into(),
    })
}

pub(super) fn publish(path: &str, bytes: &[u8]) -> Result<()> {
    if bytes.len() as u64 > MAX_FILE {
        return Err("OUTPUT_LIMIT".into());
    }
    let (parent, leaf, ancestors) = paths::open_parent(path)?;
    let flags = OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let mut output =
        File::from(openat(&parent, leaf.as_str(), flags, Mode::from_raw_mode(0o600)).map_err(io)?);
    output.write_all(bytes).map_err(io)?;
    output.sync_all().map_err(io)?;
    parent.sync_all().map_err(io)?;
    let (_, _, current) = paths::open_parent(path)?;
    if current != ancestors || read(path)?.bytes != bytes {
        return Err("OUTPUT_READBACK_MISMATCH".into());
    }
    Ok(())
}

/// A caller-selected scratch leaf must be new. Never reuse or clean another run.
pub(super) fn new_directory(path: &str) -> Result<()> {
    let (parent, leaf, ancestors) = paths::open_parent(path)?;
    mkdirat(&parent, leaf.as_str(), Mode::from_raw_mode(0o700)).map_err(io)?;
    parent.sync_all().map_err(io)?;
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let created = File::from(openat(&parent, leaf.as_str(), flags, Mode::empty()).map_err(io)?);
    let identity = paths::Identity::of(&created.metadata().map_err(io)?);
    let (current_parent, _, current_ancestors) = paths::open_parent(path)?;
    let current =
        File::from(openat(&current_parent, leaf.as_str(), flags, Mode::empty()).map_err(io)?);
    if current_ancestors != ancestors
        || paths::Identity::of(&current.metadata().map_err(io)?) != identity
    {
        return Err("RUNTIME_DIRECTORY_LOOKUP_CHANGED".into());
    }
    Ok(())
}
