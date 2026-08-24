//! Immutable filesystem content store used by later workspace generations.
//!
//! This module is deliberately independent from journals, repositories, wire
//! manifests, and cleanup. A digest names storage bytes; it grants no
//! authority and is not a `ContentId`.

use bullet_git_types::{framed_digest, Digest};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, MutexGuard};
use thiserror::Error;

#[cfg(test)]
use crate::fsync::private_tempdir;
use crate::fsync::{
    create_new_file, injected, make_read_only, sync_directory, validate_storage_root, Boundary,
    Faults, NoFault,
};

const CAS_DOMAIN: &[u8] = b"bullet-git.cas-object.v1";
const TEMP_ATTEMPTS: u16 = 128;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Maximum bytes admitted into one immutable CAS object.
pub const MAX_CAS_OBJECT_BYTES: usize = 1_048_576;

/// Hash one object using the private storage domain.
///
/// This is a raw storage digest, not a wire identity or authority subject.
#[must_use]
pub fn cas_digest(bytes: &[u8]) -> Digest {
    framed_digest(&[CAS_DOMAIN, bytes])
}

/// Whether a `put` published a new object or adopted exact existing bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PutDisposition {
    /// This call durably published the object.
    Published,
    /// The exact object was already present and was verified before adoption.
    Existing,
}

/// Result of one durable object write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CasPut {
    /// Full domain-separated object digest.
    pub digest: Digest,
    /// New publication or exact idempotent adoption.
    pub disposition: PutDisposition,
}

/// Immutable CAS failure with a stable reason code.
#[derive(Debug, Error, Eq, PartialEq)]
pub enum CasError {
    /// The caller did not provide an existing canonical private directory.
    #[error("invalid CAS root: {0}")]
    InvalidRoot(String),
    /// One object exceeded the fixed admission bound.
    #[error("CAS object is too large: {actual} bytes exceeds {max}")]
    ObjectTooLarge {
        /// Fixed upper bound.
        max: usize,
        /// Supplied byte length.
        actual: usize,
    },
    /// Persisted state is malformed or does not match its digest.
    #[error("corrupt CAS state: {0}")]
    Corrupt(String),
    /// Publication happened, but its durability could not be established.
    #[error("CAS outcome is unknown: {0}")]
    OutcomeUnknown(String),
    /// I/O failed before publication was observed.
    #[error("CAS I/O failed: {0}")]
    Io(String),
}

impl CasError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidRoot(_) => "CAS_ROOT_INVALID",
            Self::ObjectTooLarge { .. } => "CAS_OBJECT_TOO_LARGE",
            Self::Corrupt(_) => "CAS_CORRUPT",
            Self::OutcomeUnknown(_) => "CAS_OUTCOME_UNKNOWN",
            Self::Io(_) => "CAS_IO_FAILED",
        }
    }
}

/// An immutable object store rooted at a server-selected private directory.
///
/// `open` never creates the root. The server must create and own a dedicated
/// directory before passing it here; untrusted request paths are not admitted.
#[derive(Debug)]
pub struct ImmutableCas {
    root: PathBuf,
    operation: Mutex<()>,
    poisoned: AtomicBool,
}

impl ImmutableCas {
    /// Open and fully validate an existing dedicated CAS directory.
    ///
    /// The path must be absolute, canonical, and an ordinary directory. On
    /// Unix, the dedicated root and every ancestor must also pass ownership and
    /// writable-mode checks anchored to the server-selected root owner.
    /// Every authoritative object is rehashed, unknown entries fail closed, and
    /// recognizable staging crash artifacts remain non-authoritative. A
    /// directory fsync establishes the recovery boundary before this instance
    /// becomes usable.
    pub fn open(root: impl AsRef<Path>) -> Result<Self, CasError> {
        let root = validate_storage_root(root.as_ref()).map_err(CasError::InvalidRoot)?;
        let cas = Self {
            root,
            operation: Mutex::new(()),
            poisoned: AtomicBool::new(false),
        };
        cas.validate_entries()?;
        sync_directory(&cas.root).map_err(|error| {
            CasError::OutcomeUnknown(format!(
                "cannot establish recovered directory durability: {error}"
            ))
        })?;
        Ok(cas)
    }

    /// Store bytes immutably, or adopt an exact existing object.
    ///
    /// Publication uses a same-directory create-new staging file, complete
    /// write, file fsync, hard-link/no-replace publication, staging-file unlink,
    /// and directory fsync. Any failure after publication poisons this instance
    /// and returns `CAS_OUTCOME_UNKNOWN`; reopen is required for reconciliation.
    pub fn put(&self, bytes: &[u8]) -> Result<CasPut, CasError> {
        self.put_inner(bytes, &mut NoFault)
    }

    /// Read and rehash an object. Absence is distinct from corruption.
    pub fn get(&self, digest: &Digest) -> Result<Option<Vec<u8>>, CasError> {
        let _guard = self.lock_operation()?;
        self.require_healthy()?;
        let path = self.object_path(digest);
        match fs::symlink_metadata(&path) {
            Ok(_) => verify_object(&path, digest).map(Some),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(io_error("inspect object", error)),
        }
    }

    fn put_inner<F: Faults>(&self, bytes: &[u8], faults: &mut F) -> Result<CasPut, CasError> {
        let _guard = self.lock_operation()?;
        self.require_healthy()?;
        if bytes.len() > MAX_CAS_OBJECT_BYTES {
            return Err(CasError::ObjectTooLarge {
                max: MAX_CAS_OBJECT_BYTES,
                actual: bytes.len(),
            });
        }
        let digest = cas_digest(bytes);
        let destination = self.object_path(&digest);
        if destination.exists() {
            verify_object(&destination, &digest)?;
            self.sync_for_adoption()?;
            return Ok(CasPut {
                digest,
                disposition: PutDisposition::Existing,
            });
        }

        faults.check(Boundary::Allocate)?;
        let (staging, mut file) = self.create_staging_file(&digest)?;
        if faults.trips(Boundary::Write) {
            file.write_all(&bytes[..bytes.len() / 2])
                .map_err(|error| io_error("write partial object", error))?;
            return Err(injected(Boundary::Write));
        }
        file.write_all(bytes)
            .map_err(|error| io_error("write object", error))?;
        make_read_only(&file).map_err(|error| io_error("make object immutable", error))?;
        faults.check(Boundary::FileSync)?;
        file.sync_all()
            .map_err(|error| io_error("sync object", error))?;
        drop(file);
        faults.check(Boundary::Publish)?;

        match fs::hard_link(&staging, &destination) {
            Ok(()) => {
                if let Err(error) = fs::remove_file(&staging) {
                    return Err(self.poison(format!(
                        "object published but staging-file unlink failed: {error}"
                    )));
                }
                if faults.trips(Boundary::DirectorySync) {
                    return Err(self.poison("injected directory-sync failure".into()));
                }
                sync_directory(&self.root).map_err(|error| {
                    self.poison(format!(
                        "object published but directory sync failed: {error}"
                    ))
                })?;
                Ok(CasPut {
                    digest,
                    disposition: PutDisposition::Published,
                })
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                verify_object(&destination, &digest)?;
                let _ = fs::remove_file(&staging);
                self.sync_for_adoption()?;
                Ok(CasPut {
                    digest,
                    disposition: PutDisposition::Existing,
                })
            }
            Err(error) => Err(io_error("publish object", error)),
        }
    }

    fn create_staging_file(&self, digest: &Digest) -> Result<(PathBuf, File), CasError> {
        for _ in 0..TEMP_ATTEMPTS {
            let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let name = format!(
                ".cas-{}-{}-{sequence}.tmp",
                digest.to_hex(),
                std::process::id()
            );
            let path = self.root.join(name);
            match create_new_file(&path) {
                Ok(file) => return Ok((path, file)),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(io_error("allocate object staging file", error)),
            }
        }
        Err(CasError::Io(
            "could not allocate a unique object staging file".into(),
        ))
    }

    fn validate_entries(&self) -> Result<(), CasError> {
        for entry in fs::read_dir(&self.root).map_err(|error| io_error("read CAS root", error))? {
            let entry = entry.map_err(|error| io_error("read CAS entry", error))?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| CasError::Corrupt("CAS entry name is not valid UTF-8".into()))?;
            let file_type = entry
                .file_type()
                .map_err(|error| io_error("inspect CAS entry", error))?;
            if is_digest_name(&name) {
                if !file_type.is_file() {
                    return Err(CasError::Corrupt(format!(
                        "authoritative entry {name:?} is not a regular file"
                    )));
                }
                let digest = Digest::from_hex(&name)
                    .map_err(|error| CasError::Corrupt(error.to_string()))?;
                verify_object(&entry.path(), &digest)?;
            } else if is_staging_name(&name) {
                if !file_type.is_file() {
                    return Err(CasError::Corrupt(format!(
                        "staging entry {name:?} is not a regular file"
                    )));
                }
                let length = entry
                    .metadata()
                    .map_err(|error| io_error("inspect CAS staging file", error))?
                    .len();
                if length > MAX_CAS_OBJECT_BYTES as u64 {
                    return Err(CasError::Corrupt(format!(
                        "staging entry {name:?} exceeds the object bound"
                    )));
                }
            } else {
                return Err(CasError::Corrupt(format!("unknown CAS entry {name:?}")));
            }
        }
        Ok(())
    }

    fn object_path(&self, digest: &Digest) -> PathBuf {
        self.root.join(digest.to_hex())
    }

    fn lock_operation(&self) -> Result<MutexGuard<'_, ()>, CasError> {
        self.operation.lock().map_err(|_| {
            CasError::OutcomeUnknown("operation lock is poisoned; reopen before use".into())
        })
    }

    fn require_healthy(&self) -> Result<(), CasError> {
        if self.poisoned.load(Ordering::Acquire) {
            Err(CasError::OutcomeUnknown(
                "instance is poisoned; reopen and revalidate before use".into(),
            ))
        } else {
            Ok(())
        }
    }

    fn sync_for_adoption(&self) -> Result<(), CasError> {
        sync_directory(&self.root)
            .map_err(|error| self.poison(format!("cannot establish object durability: {error}")))
    }

    fn poison(&self, message: String) -> CasError {
        self.poisoned.store(true, Ordering::Release);
        CasError::OutcomeUnknown(message)
    }
}

fn verify_object(path: &Path, expected: &Digest) -> Result<Vec<u8>, CasError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| io_error("inspect object", error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(CasError::Corrupt(format!(
            "{} is not a regular object",
            path.display()
        )));
    }
    if metadata.len() > MAX_CAS_OBJECT_BYTES as u64 {
        return Err(CasError::Corrupt(format!(
            "{} exceeds the object bound",
            path.display()
        )));
    }
    if !metadata.permissions().readonly() {
        return Err(CasError::Corrupt(format!(
            "{} is a writable authoritative object",
            path.display()
        )));
    }
    let file = File::open(path).map_err(|error| io_error("open object", error))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_CAS_OBJECT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| io_error("read object", error))?;
    if bytes.len() > MAX_CAS_OBJECT_BYTES || cas_digest(&bytes) != *expected {
        return Err(CasError::Corrupt(format!(
            "{} bytes do not match its object name",
            path.display()
        )));
    }
    Ok(bytes)
}

fn is_digest_name(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_staging_name(name: &str) -> bool {
    let Some(stem) = name
        .strip_prefix(".cas-")
        .and_then(|value| value.strip_suffix(".tmp"))
    else {
        return false;
    };
    let fields = stem.split('-').collect::<Vec<_>>();
    fields.len() == 3
        && is_digest_name(fields[0])
        && !fields[1].is_empty()
        && fields[1].bytes().all(|byte| byte.is_ascii_digit())
        && !fields[2].is_empty()
        && fields[2].bytes().all(|byte| byte.is_ascii_digit())
}

fn io_error(context: &str, error: std::io::Error) -> CasError {
    CasError::Io(format!("{context}: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};

    struct FailAt(Boundary);

    impl Faults for FailAt {
        fn trips(&mut self, boundary: Boundary) -> bool {
            self.0 == boundary
        }
    }

    #[test]
    fn prepublication_failures_reopen_as_absent() {
        for boundary in [
            Boundary::Allocate,
            Boundary::Write,
            Boundary::FileSync,
            Boundary::Publish,
        ] {
            let root = private_tempdir();
            let cas = ImmutableCas::open(root.path()).expect("open");
            let bytes = b"boundary payload";
            let digest = cas_digest(bytes);
            let error = cas
                .put_inner(bytes, &mut FailAt(boundary))
                .expect_err("injected failure");
            assert_eq!(error.reason_code(), "CAS_IO_FAILED");
            drop(cas);

            let reopened = ImmutableCas::open(root.path()).expect("reopen");
            assert_eq!(reopened.get(&digest).expect("read"), None, "{boundary:?}");
        }
    }

    #[test]
    fn directory_sync_failure_is_unknown_until_exact_reopen() {
        let root = private_tempdir();
        let cas = ImmutableCas::open(root.path()).expect("open");
        let bytes = b"published payload";
        let digest = cas_digest(bytes);
        let error = cas
            .put_inner(bytes, &mut FailAt(Boundary::DirectorySync))
            .expect_err("directory sync failure");
        assert_eq!(error.reason_code(), "CAS_OUTCOME_UNKNOWN");
        assert_eq!(
            cas.put(bytes).expect_err("poisoned").reason_code(),
            "CAS_OUTCOME_UNKNOWN"
        );
        drop(cas);

        let reopened = ImmutableCas::open(root.path()).expect("reopen exact object");
        assert_eq!(reopened.get(&digest).expect("read"), Some(bytes.to_vec()));
    }

    #[test]
    fn unknown_is_visible_before_a_waiter_can_mutate() {
        let root = private_tempdir();
        let cas = Arc::new(ImmutableCas::open(root.path()).expect("open"));
        let entered = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let worker = Arc::clone(&cas);
        let worker_entered = Arc::clone(&entered);
        let worker_release = Arc::clone(&release);
        let first = std::thread::spawn(move || {
            worker.put_inner(
                b"published first",
                &mut PauseAtSync(worker_entered, worker_release),
            )
        });
        entered.wait();
        let waiter = Arc::clone(&cas);
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let second = std::thread::spawn(move || {
            ready_tx.send(()).expect("signal ready");
            waiter.put(b"must remain absent")
        });
        ready_rx.recv().expect("waiter ready");
        release.wait();
        for outcome in [first.join().expect("first"), second.join().expect("second")] {
            assert_eq!(
                outcome.expect_err("refused").reason_code(),
                "CAS_OUTCOME_UNKNOWN"
            );
        }
        drop(cas);

        let reopened = ImmutableCas::open(root.path()).expect("reopen");
        assert_eq!(
            reopened.get(&cas_digest(b"published first")).expect("read"),
            Some(b"published first".to_vec())
        );
        assert_eq!(
            reopened
                .get(&cas_digest(b"must remain absent"))
                .expect("read"),
            None
        );
    }

    struct PauseAtSync(Arc<Barrier>, Arc<Barrier>);

    impl Faults for PauseAtSync {
        fn trips(&mut self, boundary: Boundary) -> bool {
            if boundary != Boundary::DirectorySync {
                return false;
            }
            self.0.wait();
            self.1.wait();
            true
        }
    }
}
