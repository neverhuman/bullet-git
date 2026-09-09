//! Generation publication and tree-checkpoint writes for [`super::RealRepository`].

use super::*;

impl RealRepository {
    pub(super) fn publish_patches(
        &mut self,
        patches: &[PatchHunk],
        normalized: &[String],
    ) -> Result<Checkpoint, CapabilityError> {
        let mutations = self.prepare_journal_mutations(patches, normalized)?;
        self.publish_prepared_patches(patches, normalized, &mutations)
    }

    pub(super) fn publish_proposal_patches(
        &mut self,
        proposal: &PatchProposal,
        patches: &[PatchHunk],
        normalized: &[String],
        preimages: &[Option<Vec<u8>>],
    ) -> Result<Checkpoint, CapabilityError> {
        let mutations = proposal
            .operations
            .iter()
            .zip(normalized)
            .zip(preimages)
            .map(|((operation, path), prior)| {
                let before = prior
                    .as_deref()
                    .map(|bytes| self.cas.put(bytes).map(|stored| stored.digest))
                    .transpose()?;
                match &operation.mutation {
                    PatchMutation::Write { content_utf8 } => Ok(JournalMutation::write(
                        path,
                        before,
                        self.cas.put(content_utf8.as_bytes())?.digest,
                    )),
                    PatchMutation::Delete => Ok(JournalMutation::delete(
                        path,
                        before.expect("validated delete always has stable preimage bytes"),
                    )),
                }
            })
            .collect::<Result<Vec<_>, CapabilityError>>()?;
        self.publish_prepared_patches(patches, normalized, &mutations)
    }

    fn publish_prepared_patches(
        &mut self,
        patches: &[PatchHunk],
        normalized: &[String],
        mutations: &[JournalMutation],
    ) -> Result<Checkpoint, CapabilityError> {
        let stage = self.workspace.stage_generation()?;
        let stage_repo = stage.repo_dir();
        let mut stage_journal = DurableJournal::open(stage.journal_dir())?;
        let mut unrestored = Vec::new();
        if let Err(error) =
            crate::apply::apply_all(&stage_repo, patches, normalized, &mut unrestored)
        {
            return Err(match crate::apply::restore_all(&unrestored) {
                Some(rollback) => error.with_failed_rollback(&rollback),
                None => error,
            });
        }
        stage_journal.record_batch(mutations)?;
        validate_journal_objects(&stage_journal, &self.cas)?;
        let checkpoint = self.write_tree_checkpoint(&stage_repo, &stage_journal)?;
        self.publish_stage(stage, checkpoint.clone())?;
        Ok(checkpoint)
    }

    fn prepare_journal_mutations(
        &self,
        patches: &[PatchHunk],
        normalized: &[String],
    ) -> Result<Vec<JournalMutation>, CapabilityError> {
        patches
            .iter()
            .zip(normalized)
            .map(|(patch, path)| {
                let target = self.workspace.repo_dir().join(path);
                let prior = match fs::symlink_metadata(&target) {
                    Ok(metadata) if metadata.is_file() => Some(
                        fs::read(&target)
                            .map_err(|error| crate::io_err("read patch preimage", &error))?,
                    ),
                    Ok(_) => None,
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                    Err(error) => return Err(crate::io_err("inspect patch preimage", &error)),
                };
                let before = prior
                    .as_deref()
                    .map(|bytes| self.cas.put(bytes).map(|stored| stored.digest))
                    .transpose()?;
                match &patch.op {
                    PatchOp::Write(contents) => Ok(JournalMutation::write(
                        path,
                        before,
                        self.cas.put(contents)?.digest,
                    )),
                    PatchOp::Delete => Ok(JournalMutation::delete(
                        path,
                        before.expect("validated delete always has before-state bytes"),
                    )),
                }
            })
            .collect()
    }

    pub(super) fn write_tree_checkpoint(
        &self,
        repo: &Path,
        journal: &DurableJournal,
    ) -> Result<Checkpoint, CapabilityError> {
        let checkpoint_count = self
            .checkpoint_count
            .get()
            .checked_add(1)
            .ok_or_else(|| GenerationError::Corrupt("checkpoint counter overflow".into()))?;
        self.checkpoint_count.set(checkpoint_count);
        let index_path = self
            .workspace
            .runtime_dir()
            .join(format!("generation-index-{checkpoint_count}"));
        let env = [("GIT_INDEX_FILE", OsString::from(&index_path))];
        let git = self.workspace.git();
        let result = (|| {
            git.run(
                Some(repo),
                FileProtocol::Never,
                &["read-tree", "HEAD"],
                &env,
            )?;
            git.run(Some(repo), FileProtocol::Never, &["add", "-A"], &env)?;
            let tree = git
                .run(Some(repo), FileProtocol::Never, &["write-tree"], &env)?
                .text();
            Ok(journal
                .checkpoint()
                .bind_git_tree(self.workspace.git_oid(tree)?))
        })();
        let _ = fs::remove_file(&index_path);
        result
    }

    pub(super) fn commit_candidate(
        &self,
        repo: &Path,
        change: &Change,
    ) -> Result<(GitOid, GitOid), CapabilityError> {
        let git = self.workspace.git();
        let env = self.identity.env();
        git.run(Some(repo), FileProtocol::Never, &["add", "-A"], &[])?;
        let message = format!("bullet: candidate for {}", change.id);
        git.run(
            Some(repo),
            FileProtocol::Never,
            &["commit", "--allow-empty", "--no-verify", "-m", &message],
            &env,
        )?;
        let head = git
            .run(Some(repo), FileProtocol::Never, &["rev-parse", "HEAD"], &[])?
            .text();
        let tree = git
            .run(
                Some(repo),
                FileProtocol::Never,
                &["rev-parse", "HEAD^{tree}"],
                &[],
            )?
            .text();
        Ok((self.workspace.git_oid(head)?, self.workspace.git_oid(tree)?))
    }

    pub(super) fn publish_stage(
        &mut self,
        stage: StagedGeneration,
        checkpoint: Checkpoint,
    ) -> Result<(), CapabilityError> {
        if let Err(error) = self.workspace.publish_generation(stage, checkpoint) {
            if matches!(&error, CapabilityError::Generation(inner) if inner.may_have_published()) {
                self.healthy = false;
            }
            return Err(error);
        }
        match DurableJournal::open(self.workspace.journal_dir()) {
            Ok(journal) => {
                if let Err(error) = validate_journal_objects(&journal, &self.cas) {
                    self.healthy = false;
                    return Err(GenerationError::OutcomeUnknown(format!(
                        "published generation CAS validation failed: {error}"
                    ))
                    .into());
                }
                self.journal = journal;
                Ok(())
            }
            Err(error) => {
                self.healthy = false;
                Err(GenerationError::OutcomeUnknown(format!(
                    "published generation journal did not reopen: {error}"
                ))
                .into())
            }
        }
    }
}
