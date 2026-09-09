//! Exact authority-checked state capture for sealed preservation receipts.

use super::*;
use crate::clone::sequencer_check;
use crate::preservation::{PreservationError, PreservationState, WorkingEntry};
use crate::preservation_io::hash_artifact;
use bullet_git_types::AuthorityEnvelope;
use std::fs::File;
use std::io::Read as _;

const MAX_STATUS_BYTES: usize = 16 * 1024 * 1024;
const MAX_STATUS_ENTRIES: usize = 100_000;

impl RealRepository {
    pub(crate) fn preservation_state(
        &self,
        auth: &AuthorityEnvelope,
    ) -> Result<PreservationState, CapabilityError> {
        self.require_healthy()?;
        self.expected.require(auth)?;
        self.guard()?;
        sequencer_check(self.workspace.repo_dir())?;
        let checkpoint = self.validate_active_checkpoint()?;
        let git_tree = checkpoint.git_tree.clone().ok_or_else(|| {
            PreservationError::Corrupt("active checkpoint has no Git tree".into())
        })?;
        let dirty_untracked = self.working_manifest()?;
        let generation_digest = hash_artifact(&self.workspace.active_generation_dir())?;
        Ok(PreservationState::new(
            &self.expected,
            self.workspace.generation(),
            git_tree,
            generation_digest,
            dirty_untracked,
            checkpoint.through_seq,
            checkpoint.tree,
        ))
    }

    fn working_manifest(&self) -> Result<Vec<WorkingEntry>, CapabilityError> {
        let output = self.workspace.git().run(
            Some(self.workspace.repo_dir()),
            FileProtocol::Never,
            &[
                "status",
                "--porcelain=v1",
                "-z",
                "--untracked-files=all",
                "--ignored=matching",
                "--no-renames",
            ],
            &[],
        )?;
        if output.stdout.len() > MAX_STATUS_BYTES {
            return Err(PreservationError::Unsupported(
                "working-state manifest exceeds the admitted byte bound".into(),
            )
            .into());
        }
        let mut entries = Vec::new();
        for raw in output
            .stdout
            .split(|byte| *byte == 0)
            .filter(|item| !item.is_empty())
        {
            if entries.len() >= MAX_STATUS_ENTRIES {
                return Err(PreservationError::Unsupported(
                    "working-state manifest exceeds the admitted entry bound".into(),
                )
                .into());
            }
            if raw.len() < 4 || raw[2] != b' ' || !raw[..2].is_ascii() {
                return Err(PreservationError::Corrupt(
                    "Git emitted malformed NUL status data".into(),
                )
                .into());
            }
            let status = std::str::from_utf8(&raw[..2])
                .map_err(|error| PreservationError::Corrupt(error.to_string()))?;
            let path = std::str::from_utf8(&raw[3..])
                .map_err(|_| PreservationError::Unsupported("non-UTF-8 working path".into()))?;
            let normalized = crate::scope::normalize_rel_path(path)?;
            let (kind, content_digest) =
                working_entry_identity(&self.workspace.repo_dir().join(&normalized))?;
            entries.push(WorkingEntry {
                path: normalized,
                status: status.to_owned(),
                kind,
                content_digest,
            });
        }
        entries.sort_by(|left, right| left.path.cmp(&right.path));
        if entries.windows(2).any(|pair| pair[0].path == pair[1].path) {
            return Err(PreservationError::Corrupt(
                "working-state manifest contains duplicate paths".into(),
            )
            .into());
        }
        Ok(entries)
    }
}

fn working_entry_identity(path: &Path) -> Result<(String, Option<Digest>), CapabilityError> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(("absent".into(), None)),
        Err(error) => Err(crate::io_err("inspect working-state entry", &error)),
        Ok(metadata) if metadata.is_file() => Ok(("file".into(), Some(hash_file(path)?))),
        Ok(metadata) if metadata.file_type().is_symlink() => {
            #[cfg(unix)]
            {
                use std::os::unix::ffi::OsStrExt as _;
                let target = fs::read_link(path)
                    .map_err(|error| crate::io_err("read working-state symlink", &error))?;
                Ok((
                    "symlink".into(),
                    Some(Digest::of(target.as_os_str().as_bytes())),
                ))
            }
            #[cfg(not(unix))]
            Err(
                PreservationError::Unsupported("this platform lacks exact symlink identity".into())
                    .into(),
            )
        }
        Ok(metadata) if metadata.is_dir() => Ok(("directory".into(), Some(hash_artifact(path)?))),
        Ok(_) => Err(PreservationError::Unsupported(
            "special working-state filesystem entry".into(),
        )
        .into()),
    }
}

fn hash_file(path: &Path) -> Result<Digest, CapabilityError> {
    let mut file = File::open(path).map_err(|error| crate::io_err("open working file", &error))?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| crate::io_err("hash working file", &error))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Digest::from_hex(hasher.finalize().to_hex().as_str()).map_err(Into::into)
}
