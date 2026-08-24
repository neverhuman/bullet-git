//! Final revalidation colocated with the first cleanup delete syscall.

use super::*;
use crate::clone::PrivateClone;

pub(super) fn verify_salvage_objects(
    destination: &Path,
    state: &PreservationState,
) -> Result<(), CapabilityError> {
    if hash_artifact(&destination.join("generation"))? != state.generation_digest {
        return Err(PreservationError::ReceiptRefused(
            "preserved generation differs from the exact source generation".into(),
        )
        .into());
    }
    let journal = DurableJournal::open(destination.join("generation/journal"))?;
    let checkpoint = journal.checkpoint();
    if checkpoint.through_seq != state.journal_end || checkpoint.tree != state.journal_root {
        return Err(PreservationError::ReceiptRefused(
            "preserved journal range or root differs from the receipt subject".into(),
        )
        .into());
    }
    let cas = ImmutableCas::open(destination.join("cas"))?;
    for op in journal.ops() {
        for digest in [op.before.as_ref(), op.after.as_ref()]
            .into_iter()
            .flatten()
        {
            if cas.get(digest)?.is_none() {
                return Err(PreservationError::ReceiptRefused(format!(
                    "artifact journal sequence {} lacks CAS object {}",
                    op.seq,
                    digest.to_hex()
                ))
                .into());
            }
        }
    }
    Ok(())
}

impl CleanupPermit {
    pub(crate) fn revalidate(&self, workspace: &mut PrivateClone) -> Result<(), CapabilityError> {
        workspace.reopen_generation()?;
        if workspace.generation() != self.state.generation
            || hash_artifact(&workspace.active_generation_dir())? != self.state.generation_digest
        {
            return Err(PreservationError::ReceiptRefused(
                "active generation changed after cleanup authorization".into(),
            )
            .into());
        }
        let identity = destination_identity(&self.destination)?;
        if identity.device != self.destination_device || identity.inode != self.destination_inode {
            return Err(PreservationError::ReceiptRefused(
                "destination identity changed before cleanup".into(),
            )
            .into());
        }
        verify_artifact_shape(&self.destination)?;
        let subject: PreservationState = serde_json::from_slice(
            &fs::read(self.destination.join("subject.json")).map_err(|error| {
                PreservationError::ReceiptRefused(format!("read artifact subject: {error}"))
            })?,
        )
        .map_err(|error| {
            PreservationError::ReceiptRefused(format!("decode artifact subject: {error}"))
        })?;
        if subject != self.state {
            return Err(PreservationError::ReceiptRefused(
                "artifact subject changed before cleanup".into(),
            )
            .into());
        }
        verify_salvage_objects(&self.destination, &self.state)?;
        verify_bundle(workspace, &self.destination.join("repository.bundle"))?;
        if hash_artifact(&self.destination)? != self.artifact_digest {
            return Err(PreservationError::ReceiptRefused(
                "artifact digest changed before cleanup".into(),
            )
            .into());
        }
        Ok(())
    }
}

impl PreservationAuthority {
    /// Revalidate the exact source and artifact, then delete only its workspace.
    pub fn cleanup(
        &self,
        repository: &mut RealRepository,
        auth: &AuthorityEnvelope,
        receipt: &str,
        deleted_at: &str,
    ) -> Result<PathBuf, CapabilityError> {
        let permit = self.authorize_cleanup(repository, auth, receipt)?;
        repository.workspace_mut().cleanup(permit, deleted_at)
    }
}
