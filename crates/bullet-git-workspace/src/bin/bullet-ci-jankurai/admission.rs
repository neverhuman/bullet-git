//! SHA256 from a stable no-follow descriptor, then immutable executable copy.
use super::{
    io,
    paths::{open_candidate, Identity},
    record::Record,
    Profile, Result,
};
use rustix::fs::{fcntl_add_seals, fcntl_get_seals, memfd_create, MemfdFlags, SealFlags};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};

pub(super) fn admit(candidate: &str, record: &mut Record, profile: Profile<'_>) -> Result<File> {
    admit_observed(candidate, record, profile, |_, _| Ok(()))
}

// The callback has no CLI/environment surface. Tests use the same actual reads
// to force source replacement/restoration and a corrupt staged copy.
pub(super) fn admit_observed(
    candidate: &str,
    record: &mut Record,
    profile: Profile<'_>,
    mut copied_chunk: impl FnMut(&File, &File) -> Result<()>,
) -> Result<File> {
    let (mut source, lookups) = open_candidate(candidate)?;
    let before = source.metadata().map_err(io)?;
    let identity = Identity::of(&before);
    record.append(
        "candidate_opened",
        json!({"path": candidate, "identity": identity,
        "ancestor_identities": lookups}),
    )?;
    if !before.is_file() || before.mode() & 0o111 == 0 || before.len() != profile.size {
        return Err("CANDIDATE_KIND_MODE_OR_SIZE_MISMATCH".into());
    }
    let flags = MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING;
    let mut sealed = File::from(memfd_create("bullet-auditor", flags).map_err(io)?);
    let mut digest = Sha256::new();
    let mut copied = 0_u64;
    let mut header = Vec::new();
    let mut buffer = vec![0_u8; 1_048_576];
    loop {
        let count = source.read(&mut buffer).map_err(io)?;
        if count == 0 {
            break;
        }
        if copied == 0 {
            header.extend_from_slice(&buffer[..count.min(20)]);
        }
        copied += count as u64;
        if copied > profile.size {
            return Err("CANDIDATE_SIZE_CHANGED".into());
        }
        digest.update(&buffer[..count]);
        sealed.write_all(&buffer[..count]).map_err(io)?;
        copied_chunk(&source, &sealed)?;
    }
    let observed = hex::encode(digest.finalize());
    record.append(
        "candidate_read",
        json!({"path": candidate, "identity": identity,
        "ancestor_identities": lookups, "sha256": observed, "copied_bytes": copied}),
    )?;
    if copied != profile.size || identity != Identity::of(&source.metadata().map_err(io)?) {
        return Err("CANDIDATE_CHANGED_DURING_READ".into());
    }
    let (current, current_lookups) = open_candidate(candidate)?;
    if identity != Identity::of(&current.metadata().map_err(io)?) || lookups != current_lookups {
        return Err("CANDIDATE_LOOKUP_CHANGED".into());
    }
    if observed != profile.sha256 {
        return Err("CANDIDATE_SHA256_MISMATCH".into());
    }
    if header.get(..7) != Some(b"\x7fELF\x02\x01\x01") || header.get(18..20) != Some(b"\x3e\x00") {
        return Err("CANDIDATE_ELF_PROFILE_MISMATCH".into());
    }
    sealed
        .set_permissions(std::fs::Permissions::from_mode(0o500))
        .map_err(io)?;
    let seals = SealFlags::WRITE | SealFlags::GROW | SealFlags::SHRINK | SealFlags::SEAL;
    fcntl_add_seals(&sealed, seals).map_err(io)?;
    if fcntl_get_seals(&sealed).map_err(io)? != seals {
        return Err("EXECUTABLE_SEAL_MISMATCH".into());
    }
    sealed.seek(SeekFrom::Start(0)).map_err(io)?;
    let mut readback = Sha256::new();
    let mut readback_bytes = 0_u64;
    loop {
        let count = sealed.read(&mut buffer).map_err(io)?;
        if count == 0 {
            break;
        }
        readback_bytes += count as u64;
        if readback_bytes > profile.size {
            return Err("SEALED_ARTIFACT_DIGEST_MISMATCH".into());
        }
        readback.update(&buffer[..count]);
    }
    let readback_hash = hex::encode(readback.finalize());
    if readback_bytes != profile.size || readback_hash != profile.sha256 {
        return Err("SEALED_ARTIFACT_DIGEST_MISMATCH".into());
    }
    record.append("admitted", json!({"sha256": readback_hash, "size": copied,
        "seals": seals.bits(), "executable_identity": Identity::of(&sealed.metadata().map_err(io)?)}))?;
    Ok(sealed)
}
