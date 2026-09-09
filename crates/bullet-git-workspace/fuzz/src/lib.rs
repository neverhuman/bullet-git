//! Byte oracles for the patch applier and local Git config.
//!
//! This crate is not a workspace member. A panic is a defect; a typed
//! refusal is a successful closed run.

use bullet_git_workspace::{
    validate_batch, validate_repo_config, CapabilityError, PatchHunk, ScopeGrant,
};
use std::fs;
use std::path::Path;
use std::process::Command;

/// Decode one patch batch from a compact seed and run `validate_batch`.
///
/// Encoding: `count:u8` then `count` records of
/// `delete:u8`, `path_len:u8`, `path`, and when `delete == 0`
/// `content_len:u8` plus that many content bytes.
pub fn fuzz_patch(data: &[u8]) -> Result<Vec<String>, CapabilityError> {
    let grant = ScopeGrant::new(&["src".into()]).expect("grant");
    let patches = decode_patches(data);
    validate_batch(&grant, &patches, |_| false)
}

/// Write `data` as a local config and run the isolated Git inspector.
///
/// # Errors
///
/// Typed `HOSTILE_GIT_CONFIG` or I/O from the fixture.
pub fn fuzz_git_config(data: &[u8]) -> Result<(), CapabilityError> {
    let root = tempfile::tempdir()
        .map_err(|err| CapabilityError::Io(format!("create config fixture: {err}")))?;
    init_repo(root.path())?;
    fs::write(root.path().join(".git/config"), data)
        .map_err(|err| CapabilityError::Io(format!("write config seed: {err}")))?;
    validate_repo_config(root.path())
}

fn init_repo(root: &Path) -> Result<(), CapabilityError> {
    let status = Command::new("git")
        .args(["init", "-q", "-b", "main"])
        .current_dir(root)
        .status()
        .map_err(|err| CapabilityError::Io(format!("git init: {err}")))?;
    if !status.success() {
        return Err(CapabilityError::Io(format!("git init: {status}")));
    }
    Ok(())
}

fn decode_patches(data: &[u8]) -> Vec<PatchHunk> {
    if data.is_empty() {
        return Vec::new();
    }
    let count = usize::from(data[0]);
    let mut rest = &data[1..];
    let mut patches = Vec::new();
    for _ in 0..count {
        if rest.is_empty() {
            break;
        }
        let delete = rest[0] != 0;
        rest = &rest[1..];
        if rest.is_empty() {
            break;
        }
        let path_len = usize::from(rest[0]).min(rest.len().saturating_sub(1));
        rest = &rest[1..];
        if rest.len() < path_len {
            break;
        }
        let raw = &rest[..path_len];
        rest = &rest[path_len..];
        let name = String::from_utf8_lossy(raw)
            .chars()
            .filter(|ch| ch.is_ascii_alphanumeric() || *ch == '/' || *ch == '.' || *ch == '_')
            .collect::<String>();
        let path = if name.starts_with("src/") {
            name
        } else if name.is_empty() {
            "src/x".into()
        } else {
            format!("src/{name}")
        };
        if delete {
            patches.push(PatchHunk::delete(path));
            continue;
        }
        if rest.is_empty() {
            patches.push(PatchHunk::write(path, Vec::new()));
            break;
        }
        let content_len = usize::from(rest[0]).min(rest.len().saturating_sub(1));
        rest = &rest[1..];
        if rest.len() < content_len {
            patches.push(PatchHunk::write(path, rest.to_vec()));
            break;
        }
        patches.push(PatchHunk::write(path, rest[..content_len].to_vec()));
        rest = &rest[content_len..];
    }
    patches
}
