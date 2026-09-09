//! Authority, scope, and checkpoint guards for [`super::RealRepository`].

use super::*;

impl RealRepository {
    pub(super) fn guard(&self) -> Result<(), CapabilityError> {
        guard_repository(self.workspace.git(), self.workspace.repo_dir())
    }

    pub(super) fn require_healthy(&self) -> Result<(), CapabilityError> {
        if self.healthy {
            Ok(())
        } else {
            Err(GenerationError::OutcomeUnknown(
                "writer must reopen after an indeterminate generation switch".into(),
            )
            .into())
        }
    }

    fn symlink_check(&self, normalized: &str) -> Result<(), CapabilityError> {
        let mut current = self.workspace.repo_dir().to_path_buf();
        for segment in normalized.split('/') {
            current.push(segment);
            match fs::symlink_metadata(&current) {
                Ok(meta) if meta.file_type().is_symlink() => {
                    return Err(CapabilityError::SymlinkForbidden(normalized.to_string()));
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
        Ok(())
    }

    pub(super) fn validate_patches(
        &self,
        patches: &[PatchHunk],
    ) -> Result<Vec<String>, CapabilityError> {
        let repo_dir = self.workspace.repo_dir();
        let normalized = validate_batch(&self.grant, patches, |path| {
            fs::symlink_metadata(repo_dir.join(path)).is_ok_and(|meta| meta.is_file())
        })?;
        for path in &normalized {
            self.symlink_check(path)?;
        }
        Ok(normalized)
    }

    pub(super) fn proposal_patches(proposal: &PatchProposal) -> Vec<PatchHunk> {
        proposal
            .operations
            .iter()
            .map(|operation| match &operation.mutation {
                PatchMutation::Write { content_utf8 } => {
                    PatchHunk::write(operation.path.as_str(), content_utf8.as_bytes().to_vec())
                }
                PatchMutation::Delete => PatchHunk::delete(operation.path.as_str()),
            })
            .collect()
    }

    pub(super) fn require_proposal_attempt(
        &self,
        proposal: &PatchProposal,
    ) -> Result<(), CapabilityError> {
        if proposal.producing_attempt_id.as_str() == self.expected.attempt_id {
            Ok(())
        } else {
            Err(CapabilityError::ProposalAttemptMismatch {
                expected: self.expected.attempt_id.clone(),
                found: proposal.producing_attempt_id.to_string(),
            })
        }
    }

    pub(super) fn require_candidate_provenance(
        &self,
        token: &WireAuthorityToken,
        provenance: &CandidateProvenance,
        active_checkpoint: &Checkpoint,
        base_commit: &GitOid,
    ) -> Result<(), CapabilityError> {
        provenance.validate()?;
        require_candidate_field(
            "producing_attempt_id",
            &self.expected.attempt_id,
            provenance.producing_attempt_id.as_str(),
        )?;
        require_candidate_field(
            "attempt_fence",
            &self.expected.attempt_fence.to_string(),
            &provenance.attempt_fence.to_string(),
        )?;
        require_candidate_field(
            "variant_id",
            &self.workspace.manifest().variant_id,
            provenance.variant_id.as_str(),
        )?;
        require_candidate_field(
            "authority_variant_id",
            &token.variant_id,
            provenance.variant_id.as_str(),
        )?;
        require_candidate_field(
            "base_checkpoint_id",
            active_checkpoint.id.as_str(),
            provenance.base_checkpoint_id.as_str(),
        )?;
        require_candidate_field(
            "base_commit",
            base_commit.as_str(),
            provenance.base_commit.as_str(),
        )?;
        let local_grant = self
            .grant
            .allowed_prefixes
            .iter()
            .map(|path| path.parse::<RepoPath>())
            .collect::<Result<Vec<_>, _>>()?;
        if provenance.granted_scope != local_grant {
            return Err(CapabilityError::CandidateSubjectMismatch {
                field: "granted_scope",
                expected: serde_json::to_string(&local_grant)
                    .unwrap_or_else(|_| "<unencodable>".into()),
                found: serde_json::to_string(&provenance.granted_scope)
                    .unwrap_or_else(|_| "<unencodable>".into()),
            });
        }
        Ok(())
    }

    pub(super) fn require_proposal_checkpoint(
        &self,
        proposal: &PatchProposal,
        active: &Checkpoint,
    ) -> Result<(), CapabilityError> {
        if proposal.base_checkpoint_id == active.id
            && proposal.base_checkpoint_digest == active.digest
        {
            Ok(())
        } else {
            Err(CapabilityError::StaleCheckpoint(format!(
                "expected {}:{}, found {}:{}",
                active.id,
                active.digest.to_hex(),
                proposal.base_checkpoint_id,
                proposal.base_checkpoint_digest.to_hex()
            )))
        }
    }

    pub(super) fn require_proposal_preimages(
        &self,
        proposal: &PatchProposal,
        normalized: &[String],
    ) -> Result<Vec<Option<Vec<u8>>>, CapabilityError> {
        let mut verified = Vec::with_capacity(proposal.operations.len());
        for (operation, path) in proposal.operations.iter().zip(normalized) {
            let current = read_proposal_file_nofollow(self.workspace.repo_dir(), path)?;
            match (&operation.preimage, current) {
                (Preimage::Absent, None) => verified.push(None),
                (Preimage::Digest { digest }, Some(bytes)) if Digest::of(&bytes) == *digest => {
                    verified.push(Some(bytes));
                }
                _ => return Err(CapabilityError::StalePreimage(path.clone())),
            }
        }
        Ok(verified)
    }

    pub(super) fn status_scan(&self) -> Result<Vec<StatusEntry>, CapabilityError> {
        let out = self.workspace.git().run(
            Some(self.workspace.repo_dir()),
            FileProtocol::Never,
            &["status", "--porcelain=v2", "--untracked-files=all"],
            &[],
        )?;
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let mut entries = Vec::new();
        for line in text.lines() {
            if let Some(entry) = parse_status_line(line) {
                entries.push(entry);
            }
        }
        Ok(entries)
    }

    pub(super) fn classify_scan(
        &self,
        entries: &[StatusEntry],
    ) -> Result<Vec<String>, CapabilityError> {
        let mut touched = Vec::new();
        for entry in entries {
            match entry {
                StatusEntry::Untracked(path) => {
                    let ok = crate::scope::normalize_rel_path(path)
                        .is_ok_and(|n| self.grant.permits(&n));
                    if !ok {
                        return Err(CapabilityError::UnclassifiedUntracked(path.clone()));
                    }
                    touched.push(path.clone());
                }
                StatusEntry::Tracked(path) => {
                    let normalized = crate::scope::normalize_rel_path(path)?;
                    if !self.grant.permits(&normalized) {
                        return Err(CapabilityError::OutOfScope(path.clone()));
                    }
                    touched.push(normalized);
                }
            }
        }
        touched.sort();
        touched.dedup();
        Ok(touched)
    }

    pub(super) fn require_private_branch(&self) -> Result<(), CapabilityError> {
        match self.workspace.git().head_state(self.workspace.repo_dir())? {
            HeadState::Branch(name) if name == self.workspace.branch() => Ok(()),
            HeadState::Branch(name) => Err(CapabilityError::WrongBranch {
                expected: self.workspace.branch().to_string(),
                found: name,
            }),
            HeadState::Detached => Err(CapabilityError::WrongBranch {
                expected: self.workspace.branch().to_string(),
                found: "(detached)".into(),
            }),
        }
    }

    pub(super) fn validate_active_checkpoint(&self) -> Result<Checkpoint, CapabilityError> {
        let checkpoint = self.write_tree_checkpoint(self.workspace.repo_dir(), &self.journal)?;
        if &checkpoint != self.workspace.generation_checkpoint() {
            return Err(GenerationError::Corrupt(
                "active repository or journal does not match its generation manifest".into(),
            )
            .into());
        }
        Ok(checkpoint)
    }
}
