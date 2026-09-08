//! Shared CAS, journal, and proposal-preimage helpers for [`super::RealRepository`].

use super::*;

#[cfg(target_os = "linux")]
pub(super) fn read_proposal_file_nofollow(
    repo_dir: &Path,
    path: &str,
) -> Result<Option<Vec<u8>>, CapabilityError> {
    use rustix::fs::{open, openat2, Mode, OFlags, ResolveFlags};
    use std::io::Read as _;

    let root = open(
        repo_dir,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::DIRECTORY | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(|error| CapabilityError::Io(format!("open proposal repository root: {error}")))?;
    let descriptor = match openat2(
        &root,
        path,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_SYMLINKS | ResolveFlags::NO_MAGICLINKS,
    ) {
        Ok(descriptor) => descriptor,
        Err(error) if error == rustix::io::Errno::NOENT => return Ok(None),
        Err(_) => return Err(CapabilityError::StalePreimage(path.to_owned())),
    };
    let mut file = File::from(descriptor);
    if !file
        .metadata()
        .map_err(|error| crate::io_err("inspect proposal preimage descriptor", &error))?
        .is_file()
    {
        return Err(CapabilityError::StalePreimage(path.to_owned()));
    }
    let mut bytes = Vec::new();
    file.by_ref()
        .take((crate::MAX_CAS_OBJECT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|error| crate::io_err("read proposal preimage descriptor", &error))?;
    if bytes.len() > crate::MAX_CAS_OBJECT_BYTES {
        return Err(CasError::ObjectTooLarge {
            max: crate::MAX_CAS_OBJECT_BYTES,
            actual: bytes.len(),
        }
        .into());
    }
    Ok(Some(bytes))
}

#[cfg(not(target_os = "linux"))]
pub(super) fn read_proposal_file_nofollow(
    _repo_dir: &Path,
    _path: &str,
) -> Result<Option<Vec<u8>>, CapabilityError> {
    Err(CapabilityError::Io(
        "safe proposal preimage reads require the admitted Linux openat2 backend".into(),
    ))
}

#[cfg(all(test, target_os = "linux"))]
mod proposal_preimage_tests {
    use super::*;

    #[test]
    fn descriptor_relative_read_never_follows_parent_symlink() {
        let temp = tempfile::tempdir().expect("tempdir");
        let repo = temp.path().join("repo");
        let outside = temp.path().join("outside");
        fs::create_dir(&repo).expect("repo");
        fs::create_dir(&outside).expect("outside");
        fs::write(outside.join("secret"), b"outside bytes").expect("outside fixture");
        std::os::unix::fs::symlink(&outside, repo.join("src")).expect("parent symlink");

        let error =
            read_proposal_file_nofollow(&repo, "src/secret").expect_err("parent symlink refused");
        assert_eq!(error.reason_code(), "STALE_PREIMAGE");
    }
}

pub(super) fn require_candidate_field(
    field: &'static str,
    expected: &str,
    found: &str,
) -> Result<(), CapabilityError> {
    if expected == found {
        Ok(())
    } else {
        Err(CapabilityError::CandidateSubjectMismatch {
            field,
            expected: expected.to_owned(),
            found: found.to_owned(),
        })
    }
}

pub(super) fn open_workspace_cas(
    runtime_dir: &std::path::Path,
) -> Result<ImmutableCas, CapabilityError> {
    let root = runtime_dir.join("cas");
    match fs::symlink_metadata(&root) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir(&root).map_err(|error| crate::io_err("create workspace CAS", &error))?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt as _;
                fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                    .map_err(|error| crate::io_err("secure workspace CAS", &error))?;
            }
            File::open(runtime_dir)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| crate::io_err("sync workspace runtime", &error))?;
        }
        Err(error) => return Err(crate::io_err("inspect workspace CAS", &error)),
    }
    ImmutableCas::open(&root).map_err(Into::into)
}

pub(super) fn validate_journal_objects(
    journal: &DurableJournal,
    cas: &ImmutableCas,
) -> Result<(), CapabilityError> {
    for op in journal.ops() {
        for digest in [op.before.as_ref(), op.after.as_ref()]
            .into_iter()
            .flatten()
        {
            if cas.get(digest)?.is_none() {
                return Err(CasError::Corrupt(format!(
                    "journal sequence {} references missing object {}",
                    op.seq,
                    digest.to_hex()
                ))
                .into());
            }
        }
    }
    Ok(())
}
