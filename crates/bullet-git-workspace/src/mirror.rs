//! Per-repository bare mirrors updated under an exclusive file lock
//! (spec §20.2).
//!
//! Workspaces never clone the source repository directly. The source is
//! mirrored into `<root>/mirrors/<digest>.git` where the digest is BLAKE3 of
//! the canonical source path; the mirror is created or fetched under an
//! exclusive lock, the base SHA is verified against the mirror, and the
//! private clone independently materializes the mirror object store through
//! the Rust reflink-or-bounded-copy path, so no alternates file survives and
//! a later mirror GC can never corrupt a workspace.

use crate::safe_git::{FileProtocol, SafeGit};
use crate::{io_err, CapabilityError};
use bullet_git_types::Digest;
use std::fs;
use std::io::Write as _;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

/// A lock without a readable holder pid is broken once older than this.
pub const LOCK_STALE_AFTER: Duration = Duration::from_secs(60);
/// Waiting for the mirror lock gives up after this long.
pub const LOCK_MAX_WAIT: Duration = Duration::from_secs(120);
const LOCK_POLL: Duration = Duration::from_millis(25);

/// Mirror directory for a source repository.
///
/// # Errors
///
/// Returns `IO_FAILED` when the source path cannot be canonicalized.
pub fn mirror_dir(root: &Path, source: &Path) -> Result<PathBuf, CapabilityError> {
    let canon = fs::canonicalize(source).map_err(|err| io_err("canonicalize source", &err))?;
    let digest = Digest::of(canon.as_os_str().as_bytes());
    Ok(root
        .join("mirrors")
        .join(format!("{}.git", digest.to_hex())))
}

/// Held exclusive mirror lock. Dropping releases it.
pub struct MirrorLock {
    path: PathBuf,
}

impl MirrorLock {
    /// Acquire `<mirror>.lock` via create-exclusive with a bounded wait.
    ///
    /// The lock file records the holder pid. A lock whose recorded holder is
    /// dead is broken immediately; a lock without a readable pid is broken
    /// once it is older than [`LOCK_STALE_AFTER`].
    ///
    /// # Errors
    ///
    /// Returns `MIRROR_LOCK_TIMEOUT` when the wait exceeds `max_wait` and
    /// `IO_FAILED` when the lock file cannot be created.
    pub fn acquire(mirror: &Path, max_wait: Duration) -> Result<Self, CapabilityError> {
        let path = lock_path(mirror);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|err| io_err("create mirrors dir", &err))?;
        }
        let deadline = Instant::now() + max_wait;
        loop {
            let attempt = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path);
            match attempt {
                Ok(mut file) => {
                    let _ = write!(file, "{}", std::process::id());
                    return Ok(Self { path });
                }
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    if lock_is_stale(&path) {
                        let _ = fs::remove_file(&path);
                        continue;
                    }
                    if Instant::now() >= deadline {
                        return Err(CapabilityError::MirrorLockTimeout(
                            path.display().to_string(),
                        ));
                    }
                    std::thread::sleep(LOCK_POLL);
                }
                Err(err) => return Err(io_err("create mirror lock", &err)),
            }
        }
    }
}

impl Drop for MirrorLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

fn lock_path(mirror: &Path) -> PathBuf {
    let name = mirror.file_name().map_or_else(
        || "mirror".to_string(),
        |n| n.to_string_lossy().into_owned(),
    );
    mirror.with_file_name(format!("{name}.lock"))
}

fn lock_is_stale(path: &Path) -> bool {
    if let Ok(text) = fs::read_to_string(path) {
        if let Ok(pid) = text.trim().parse::<u32>() {
            return !Path::new(&format!("/proc/{pid}")).exists();
        }
    }
    match fs::metadata(path).and_then(|meta| meta.modified()) {
        Ok(modified) => SystemTime::now()
            .duration_since(modified)
            .is_ok_and(|age| age > LOCK_STALE_AFTER),
        Err(_) => false,
    }
}

/// A mirror synchronized with its source, with the exclusive lock still held.
///
/// The caller keeps this alive until the workspace clone from the mirror is
/// complete, so a concurrent fetch can never race the clone.
pub(crate) struct SyncedMirror {
    /// The bare mirror directory.
    pub dir: PathBuf,
    lock: MirrorLock,
}

impl SyncedMirror {
    /// Release the lock explicitly once the clone from the mirror is done.
    pub fn release(self) {
        drop(self.lock);
    }
}

/// Create or update the bare mirror for `source` under the exclusive lock.
///
/// A missing mirror is created with `git clone --mirror`; a directory without
/// a `HEAD` (a crashed half-created mirror) is removed and recreated; an
/// existing mirror is refreshed with `git fetch --prune origin`.
///
/// # Errors
///
/// Returns `MIRROR_LOCK_TIMEOUT`, `GIT_FAILED`, or `IO_FAILED`.
pub(crate) fn sync_mirror(
    git: &SafeGit,
    root: &Path,
    source: &Path,
) -> Result<SyncedMirror, CapabilityError> {
    let dir = mirror_dir(root, source)?;
    let lock = MirrorLock::acquire(&dir, LOCK_MAX_WAIT)?;
    if dir.join("HEAD").is_file() {
        git.run(
            Some(&dir),
            FileProtocol::User,
            &["fetch", "--prune", "origin"],
            &[],
        )?;
    } else {
        if dir.exists() {
            fs::remove_dir_all(&dir).map_err(|err| io_err("remove partial mirror", &err))?;
        }
        let source_str = source.to_string_lossy().into_owned();
        let dir_str = dir.to_string_lossy().into_owned();
        git.run(
            None,
            FileProtocol::User,
            &["clone", "--mirror", &source_str, &dir_str],
            &[],
        )?;
    }
    Ok(SyncedMirror { dir, lock })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lock_path_is_a_sibling_of_the_mirror() {
        let mirror = Path::new("/farm/mirrors/abc.git");
        assert_eq!(
            lock_path(mirror),
            Path::new("/farm/mirrors/abc.git.lock").to_path_buf()
        );
    }

    #[test]
    fn dead_holder_is_stale_and_live_holder_is_not() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let lock = tmp.path().join("m.git.lock");
        fs::write(&lock, format!("{}", std::process::id())).expect("live lock");
        assert!(!lock_is_stale(&lock));
        fs::write(&lock, "4294000000").expect("dead lock");
        assert!(lock_is_stale(&lock));
    }

    #[test]
    fn unreadable_pid_is_stale_only_after_the_timeout() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let lock = tmp.path().join("m.git.lock");
        fs::write(&lock, "not a pid").expect("garbage lock");
        assert!(!lock_is_stale(&lock), "fresh garbage lock is not stale");
        let old = SystemTime::now() - (LOCK_STALE_AFTER + Duration::from_secs(5));
        fs::File::options()
            .write(true)
            .open(&lock)
            .expect("open lock")
            .set_modified(old)
            .expect("age lock");
        assert!(lock_is_stale(&lock), "aged garbage lock is stale");
    }
}
