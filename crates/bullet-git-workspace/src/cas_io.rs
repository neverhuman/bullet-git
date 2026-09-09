//! CAS object verify and name helpers.

use super::*;

pub(super) fn verify_object(path: &Path, expected: &Digest) -> Result<Vec<u8>, CasError> {
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

pub(super) fn is_digest_name(name: &str) -> bool {
    name.len() == 64
        && name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn is_staging_name(name: &str) -> bool {
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

pub(super) fn io_error(context: &str, error: std::io::Error) -> CasError {
    CasError::Io(format!("{context}: {error}"))
}
