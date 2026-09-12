//! Exact local build input readback; this does not replace the source monitor.
use super::super::{artifacts, io, paths, Result};
use super::common::require;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::os::fd::AsRawFd;

pub(super) const SOURCE_ROOTS: [&str; 13] = [
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    "ops/ci/jankurai-bootstrap.sh",
    "crates/bullet-git-types/Cargo.toml",
    "crates/bullet-git-types/src",
    "crates/bullet-git-journal/Cargo.toml",
    "crates/bullet-git-journal/src",
    "crates/bullet-git-workspace/Cargo.toml",
    "crates/bullet-git-workspace/src",
    "crates/bullet-gitd/Cargo.toml",
    "crates/bullet-gitd/src",
    "contracts/generated/rust",
];

pub(super) fn current(root: &str) -> Result<(Vec<u8>, Vec<artifacts::Artifact>)> {
    let mut pending: Vec<String> = SOURCE_ROOTS.iter().map(|p| (*p).into()).collect();
    let cargo_present = match std::fs::symlink_metadata(format!("{root}/.cargo")) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => return Err(io(error)),
    };
    if cargo_present {
        pending.push(".cargo".into());
    }
    let mut result = if cargo_present {
        b"PRESENT .cargo\0".to_vec()
    } else {
        b"ABSENT .cargo\0".to_vec()
    };
    let mut files = BTreeMap::new();
    let (mut entries, mut total) = (0usize, 0usize);
    while let Some(relative) = pending.pop() {
        entries += 1;
        require(entries <= 4096, "BOOTSTRAP_SOURCE_ENTRY_LIMIT")?;
        let absolute = format!("{root}/{relative}");
        let metadata = std::fs::symlink_metadata(&absolute).map_err(io)?;
        if metadata.is_dir() {
            let (descriptor, _, _) = paths::open_parent(&format!("{absolute}/.lookup"))?;
            for child in std::fs::read_dir(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
                .map_err(io)?
            {
                require(
                    pending.len() + entries < 4096,
                    "BOOTSTRAP_SOURCE_ENTRY_LIMIT",
                )?;
                let name = child
                    .map_err(io)?
                    .file_name()
                    .into_string()
                    .map_err(|_| "BOOTSTRAP_NON_UTF8_SOURCE")?;
                pending.push(format!("{relative}/{name}"));
            }
        } else {
            require(metadata.is_file(), "BOOTSTRAP_SOURCE_NOT_REGULAR")?;
            let artifact = artifacts::read(&absolute)?;
            total += artifact.bytes.len();
            require(total <= 64 * 1024 * 1024, "BOOTSTRAP_SOURCE_BYTE_LIMIT")?;
            require(
                files.insert(relative, artifact).is_none(),
                "BOOTSTRAP_DUPLICATE_SOURCE",
            )?;
        }
    }
    for (relative, artifact) in &files {
        result.extend_from_slice(
            format!(
                "{}  {relative}\0",
                hex::encode(Sha256::digest(&artifact.bytes))
            )
            .as_bytes(),
        );
        artifact.recheck()?;
    }
    Ok((result, files.into_values().collect()))
}

pub(super) fn checksum_line(name: &str, bytes: &[u8]) -> Vec<u8> {
    // GNU sha256sum escapes newline/backslash names unless -z is selected.
    let escaped = name.contains('\\') || name.contains('\n');
    let path = name.replace('\\', "\\\\").replace('\n', "\\n");
    format!(
        "{}{}  {path}\n",
        if escaped { "\\" } else { "" },
        hex::encode(Sha256::digest(bytes))
    )
    .into_bytes()
}
