//! bullet-gitd: capability-secure repository daemon. Agents do not receive a
//! Git binary; every mutation carries an AuthorityToken and is verified here.

mod authority_gateway;
pub mod daemon;
mod kernel_permit;
pub mod mutation_ledger;
pub mod protocol;

use bullet_git_journal::{Checkpoint, Journal};
use bullet_git_types::{
    frame, framed_digest, AuthorityEnvelope, Candidate, CandidateManifest, CandidateProvenance,
    Change, ChangeEvolution, ChangeId, Digest, EvolutionEdge, EvolutionKind, GitOid,
    GitOidAlgorithm, PatchMutation, PatchProposal, Preimage, ProofInputs, ProofRoot, RepoPath,
};
use bullet_git_workspace::{
    validate_batch, AgentRepository, CapabilityError, ExpectedAuthority, PatchHunk, PatchOp,
    ScopeGrant, WorkspaceLineage,
};

fn synth_oid(fields: &[&[u8]]) -> GitOid {
    let hex = framed_digest(fields).to_hex();
    GitOid::from_hex(GitOidAlgorithm::Sha256, hex).expect("BLAKE3 is 64 lowercase hex")
}

/// In-process fake enforcing the same authority and scope rules as
/// `RealRepository`, for unit tests without a Git binary.
pub struct MemoryRepository {
    files: Vec<(String, Vec<u8>)>,
    journal: Journal,
    expected: ExpectedAuthority,
    grant: ScopeGrant,
    base: GitOid,
    is_worktree: bool,
    lineage: WorkspaceLineage,
}

impl MemoryRepository {
    /// Empty private clone bound to expected authority and a scope grant.
    #[must_use]
    pub fn new(expected: ExpectedAuthority, grant: ScopeGrant) -> Self {
        Self {
            files: Vec::new(),
            journal: Journal::new(),
            expected,
            grant,
            base: synth_oid(&[b"memory.base"]),
            is_worktree: false,
            lineage: WorkspaceLineage::new(),
        }
    }

    /// Mark the workspace as a worktree so writes fail closed.
    #[must_use]
    pub fn worktree(expected: ExpectedAuthority, grant: ScopeGrant) -> Self {
        Self {
            is_worktree: true,
            ..Self::new(expected, grant)
        }
    }

    /// Record a typed evolution edge. The ChangeId survives; the CandidateId
    /// never does.
    #[must_use]
    pub fn evolve(from: &Candidate, kind: EvolutionKind, seed: &str) -> (Candidate, EvolutionEdge) {
        let tree = synth_oid(&[b"memory.tree", seed.as_bytes()]);
        let head = synth_oid(&[b"memory.head", seed.as_bytes(), tree.as_str().as_bytes()]);
        let mut manifest = from.manifest.clone();
        manifest.head_commit = head;
        manifest.tree_oid = tree;
        manifest.patch_digest = Digest::of(seed.as_bytes());
        manifest.parent_candidate_ids = vec![from.id.clone()];
        let next = Candidate::from_manifest(manifest, from.prepared_at.clone())
            .expect("evolution from a validated manifest remains valid");
        let edge = EvolutionEdge {
            from: from.id.clone(),
            to: next.id.clone(),
            kind,
        };
        (next, edge)
    }
}

impl AgentRepository for MemoryRepository {
    fn read_tree(&self, auth: &AuthorityEnvelope) -> Result<Vec<String>, CapabilityError> {
        self.expected.require(auth)?;
        Ok(self.files.iter().map(|(p, _)| p.clone()).collect())
    }

    fn apply_change(
        &mut self,
        auth: &AuthorityEnvelope,
        patches: &[PatchHunk],
    ) -> Result<(), CapabilityError> {
        self.expected.require(auth)?;
        if self.is_worktree {
            return Err(CapabilityError::WorktreeForbidden("memory".into()));
        }
        let normalized = validate_batch(&self.grant, patches, |path| {
            self.files.iter().any(|(p, _)| p == path)
        })?;
        for (patch, path) in patches.iter().zip(normalized) {
            match &patch.op {
                PatchOp::Write(contents) => {
                    self.journal.record(&path, contents);
                    if let Some((_, existing)) = self.files.iter_mut().find(|(p, _)| p == &path) {
                        *existing = contents.clone();
                    } else {
                        self.files.push((path, contents.clone()));
                    }
                }
                PatchOp::Delete => {
                    if let Some(pos) = self.files.iter().position(|(p, _)| p == &path) {
                        let (_, before) = self.files.remove(pos);
                        self.journal.record_delete(&path, &before);
                    }
                }
            }
        }
        Ok(())
    }

    fn apply_proposal(
        &mut self,
        auth: &AuthorityEnvelope,
        proposal: &PatchProposal,
    ) -> Result<Checkpoint, CapabilityError> {
        self.expected.require(auth)?;
        if self.is_worktree {
            return Err(CapabilityError::WorktreeForbidden("memory".into()));
        }
        proposal.validate()?;
        if proposal.producing_attempt_id.as_str() != self.expected.attempt_id {
            return Err(CapabilityError::ProposalAttemptMismatch {
                expected: self.expected.attempt_id.clone(),
                found: proposal.producing_attempt_id.to_string(),
            });
        }
        let active = self.journal.checkpoint();
        if proposal.base_checkpoint_id != active.id
            || proposal.base_checkpoint_digest != active.digest
        {
            return Err(CapabilityError::StaleCheckpoint(format!(
                "expected {}:{}, found {}:{}",
                active.id,
                active.digest.to_hex(),
                proposal.base_checkpoint_id,
                proposal.base_checkpoint_digest.to_hex()
            )));
        }
        let patches = proposal
            .operations
            .iter()
            .map(|operation| match &operation.mutation {
                PatchMutation::Write { content_utf8 } => {
                    PatchHunk::write(operation.path.as_str(), content_utf8.as_bytes().to_vec())
                }
                PatchMutation::Delete => PatchHunk::delete(operation.path.as_str()),
            })
            .collect::<Vec<_>>();
        let normalized = validate_batch(&self.grant, &patches, |path| {
            self.files.iter().any(|(candidate, _)| candidate == path)
        })?;
        for (operation, path) in proposal.operations.iter().zip(&normalized) {
            let current = self
                .files
                .iter()
                .find(|(candidate, _)| candidate == path)
                .map(|(_, bytes)| bytes);
            let matches = match (&operation.preimage, current) {
                (Preimage::Absent, None) => true,
                (Preimage::Digest { digest }, Some(bytes)) => Digest::of(bytes) == *digest,
                _ => false,
            };
            if !matches {
                return Err(CapabilityError::StalePreimage(path.clone()));
            }
        }
        self.apply_change(auth, &patches)?;
        Ok(self.journal.checkpoint())
    }

    fn checkpoint(&mut self, auth: &AuthorityEnvelope) -> Result<Checkpoint, CapabilityError> {
        self.expected.require(auth)?;
        Ok(self.journal.checkpoint())
    }

    fn validate_candidate_preparation(
        &self,
        auth: &AuthorityEnvelope,
        provenance: &CandidateProvenance,
    ) -> Result<(), CapabilityError> {
        let token = self.expected.require(auth)?;
        provenance.validate()?;
        require_memory_candidate_field(
            "producing_attempt_id",
            &self.expected.attempt_id,
            provenance.producing_attempt_id.as_str(),
        )?;
        require_memory_candidate_field(
            "attempt_fence",
            &self.expected.attempt_fence.to_string(),
            &provenance.attempt_fence.to_string(),
        )?;
        require_memory_candidate_field(
            "variant_id",
            &token.variant_id,
            provenance.variant_id.as_str(),
        )?;
        let checkpoint = self.journal.checkpoint();
        require_memory_candidate_field(
            "base_checkpoint_id",
            checkpoint.id.as_str(),
            provenance.base_checkpoint_id.as_str(),
        )?;
        require_memory_candidate_field(
            "base_commit",
            self.base.as_str(),
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

    fn prepare_candidate(
        &mut self,
        auth: &AuthorityEnvelope,
        change: &Change,
        provenance: &CandidateProvenance,
    ) -> Result<Candidate, CapabilityError> {
        self.validate_candidate_preparation(auth, provenance)?;
        let mut files = self.files.clone();
        files.sort_by(|a, b| a.0.cmp(&b.0));
        let mut buf = Vec::new();
        frame(&mut buf, b"memory.candidate.v1");
        for (path, bytes) in &files {
            frame(&mut buf, path.as_bytes());
            frame(&mut buf, bytes);
        }
        let content = Digest::of(&buf);
        let tree = synth_oid(&[b"memory.tree", content.as_bytes()]);
        let head = synth_oid(&[
            b"memory.head",
            tree.as_str().as_bytes(),
            self.base.as_str().as_bytes(),
            change.id.as_str().as_bytes(),
        ]);
        let manifest = CandidateManifest {
            schema_version: provenance.schema_version,
            repository_id: provenance.repository_id.clone(),
            change_id: change.id.clone(),
            producing_attempt_id: provenance.producing_attempt_id.clone(),
            attempt_fence: provenance.attempt_fence,
            work_package_id: provenance.work_package_id.clone(),
            variant_id: provenance.variant_id.clone(),
            plan_revision_id: provenance.plan_revision_id.clone(),
            graph_revision_id: provenance.graph_revision_id.clone(),
            base_checkpoint_id: provenance.base_checkpoint_id.clone(),
            base_commit: self.base.clone(),
            head_commit: head,
            tree_oid: tree,
            patch_digest: content,
            parent_candidate_ids: provenance.parent_candidate_ids.clone(),
            granted_scope: provenance.granted_scope.clone(),
            actual_scope: files
                .iter()
                .map(|(path, _)| path.parse::<RepoPath>())
                .collect::<Result<Vec<_>, _>>()?,
            context_capsule_id: provenance.context_capsule_id.clone(),
            configuration_snapshot_id: provenance.configuration_snapshot_id.clone(),
            policy_snapshot_id: provenance.policy_snapshot_id.clone(),
            routing_snapshot_id: provenance.routing_snapshot_id.clone(),
            environment_digest: provenance.environment_digest,
            toolchain_digest: provenance.toolchain_digest,
        };
        Candidate::from_manifest(manifest, "memory".into()).map_err(Into::into)
    }

    fn query_lineage(
        &self,
        auth: &AuthorityEnvelope,
        change_id: &ChangeId,
    ) -> Result<ChangeEvolution, CapabilityError> {
        self.expected.require(auth)?;
        Ok(self.lineage.query(change_id)?)
    }

    fn record_evolution(
        &mut self,
        auth: &AuthorityEnvelope,
        change: &Change,
        edge: EvolutionEdge,
    ) -> Result<(), CapabilityError> {
        self.expected.require(auth)?;
        self.lineage.record_change(change.clone())?;
        self.lineage.record_edge(&change.id, edge)?;
        Ok(())
    }
}

fn require_memory_candidate_field(
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

/// Convenience helper for proof roots after prepare.
#[must_use]
pub fn bind_proof(candidate: &Candidate) -> ProofRoot {
    ProofRoot::bind(
        candidate,
        &ProofInputs {
            scope_and_write_set: b"scope",
            evidence: b"evidence",
            reviews: b"reviews",
            policy: b"policy",
            ..ProofInputs::empty()
        },
    )
}

#[cfg(test)]
#[path = "lib/tests.rs"]
mod tests;
