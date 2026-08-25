//! bullet-gitd: capability-secure repository daemon. Agents do not receive a
//! Git binary; every mutation carries an AuthorityToken and is verified here.

mod authority_gateway;
pub mod daemon;
pub mod mutation_ledger;
pub mod protocol;

use bullet_git_journal::{Checkpoint, Journal};
use bullet_git_types::{
    frame, framed_digest, AuthorityEnvelope, Candidate, CandidateId, Change, Digest, EvolutionEdge,
    EvolutionKind, GitOid, GitOidAlgorithm, PatchMutation, PatchProposal, Preimage, ProofRoot,
};
use bullet_git_workspace::{
    validate_batch, AgentRepository, CapabilityError, ExpectedAuthority, PatchHunk, PatchOp,
    ScopeGrant,
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
        let next = Candidate {
            id: CandidateId::from_content(&from.change, &tree, &head),
            change: from.change.clone(),
            base_commit: from.base_commit.clone(),
            head_commit: head,
            tree_hash: tree,
            patch_hash: Digest::of(seed.as_bytes()),
            variant_id: from.variant_id.clone(),
            attempt_id: from.attempt_id.clone(),
            granted_scope: from.granted_scope.clone(),
            actual_scope: from.actual_scope.clone(),
            parent_candidate_id: Some(from.id.clone()),
            prepared_at: from.prepared_at.clone(),
            lineage_subject: from.lineage_subject.clone(),
            environment_digest: from.environment_digest,
        };
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

    fn prepare_candidate(
        &mut self,
        auth: &AuthorityEnvelope,
        change: &Change,
    ) -> Result<Candidate, CapabilityError> {
        self.expected.require(auth)?;
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
        Ok(Candidate {
            id: CandidateId::from_content(&change.id, &tree, &head),
            change: change.id.clone(),
            base_commit: self.base.clone(),
            head_commit: head,
            tree_hash: tree,
            patch_hash: content,
            variant_id: "memory".into(),
            attempt_id: self.expected.attempt_id.clone(),
            granted_scope: self.grant.allowed_prefixes.clone(),
            actual_scope: files.iter().map(|(p, _)| p.clone()).collect(),
            parent_candidate_id: None,
            prepared_at: "memory".into(),
            lineage_subject: None,
            environment_digest: None,
        })
    }
}

/// Convenience helper for proof roots after prepare.
#[must_use]
pub fn bind_proof(candidate: &Candidate) -> ProofRoot {
    ProofRoot::compute(candidate, b"scope", b"evidence", b"reviews", b"policy")
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_git_types::ChangeId;

    fn expected() -> ExpectedAuthority {
        ExpectedAuthority {
            attempt_id: "atm_1".into(),
            attempt_fence: 3,
            workspace_nonce: [7u8; 32],
        }
    }

    fn token(attempt: &str, fence: u64) -> AuthorityEnvelope {
        let nonce: Vec<u8> = vec![7u8; 32];
        AuthorityEnvelope {
            token: serde_json::to_vec(&serde_json::json!({
                "variant_id": "var_1",
                "attempt_id": attempt,
                "attempt_fence": fence,
                "workspace_nonce": nonce,
            }))
            .expect("token json"),
        }
    }

    fn grant() -> ScopeGrant {
        ScopeGrant::new(&["src".into()]).expect("grant")
    }

    fn change() -> Change {
        Change {
            id: ChangeId::from_seed("feat"),
            mission: "demo".into(),
            acceptance_root: Digest::of(b"acc"),
        }
    }

    #[test]
    fn empty_and_garbage_tokens_are_rejected() {
        let repo = MemoryRepository::new(expected(), grant());
        for bytes in [Vec::new(), b"x".to_vec()] {
            let auth = AuthorityEnvelope { token: bytes };
            let err = repo.read_tree(&auth).expect_err("rejected");
            assert_eq!(err.reason_code(), "UNAUTHORIZED");
        }
    }

    #[test]
    fn wrong_fence_token_is_stale() {
        let repo = MemoryRepository::new(expected(), grant());
        let err = repo.read_tree(&token("atm_1", 4)).expect_err("stale");
        assert_eq!(err.reason_code(), "STALE_AUTHORITY");
    }

    #[test]
    fn worktree_writes_are_blocked() {
        let mut repo = MemoryRepository::worktree(expected(), grant());
        let err = repo
            .apply_change(
                &token("atm_1", 3),
                &[PatchHunk::write("src/lib.rs", b"x".to_vec())],
            )
            .expect_err("blocked");
        assert_eq!(err.reason_code(), "WORKTREE_FORBIDDEN");
    }

    #[test]
    fn out_of_scope_patch_leaves_tree_untouched() {
        let mut repo = MemoryRepository::new(expected(), grant());
        let auth = token("atm_1", 3);
        let err = repo
            .apply_change(
                &auth,
                &[
                    PatchHunk::write("src/ok.rs", b"fine".to_vec()),
                    PatchHunk::write("../escape", b"evil".to_vec()),
                ],
            )
            .expect_err("refused");
        assert_eq!(err.reason_code(), "OUT_OF_SCOPE");
        assert!(err.to_string().contains("../escape"));
        assert!(repo.read_tree(&auth).expect("read").is_empty());
    }

    #[test]
    fn candidate_id_ignores_application_order_but_tracks_content() {
        let auth = token("atm_1", 3);
        let a = PatchHunk::write("src/a.rs", b"alpha".to_vec());
        let b = PatchHunk::write("src/b.rs", b"beta".to_vec());
        let mut one = MemoryRepository::new(expected(), grant());
        one.apply_change(&auth, &[a.clone(), b.clone()])
            .expect("apply");
        let mut two = MemoryRepository::new(expected(), grant());
        two.apply_change(&auth, &[b, a]).expect("apply");
        let c1 = one.prepare_candidate(&auth, &change()).expect("prepare");
        let c2 = two.prepare_candidate(&auth, &change()).expect("prepare");
        assert_eq!(c1.id, c2.id);
        assert_eq!(c1.tree_hash, c2.tree_hash);
        assert_eq!(c1.patch_hash, c2.patch_hash);
        let mut three = MemoryRepository::new(expected(), grant());
        three
            .apply_change(
                &auth,
                &[PatchHunk::write("src/a.rs", b"different".to_vec())],
            )
            .expect("apply");
        let c3 = three.prepare_candidate(&auth, &change()).expect("prepare");
        assert_ne!(c1.id, c3.id);
    }

    #[test]
    fn delete_removes_the_file_and_absent_target_is_typed() {
        let auth = token("atm_1", 3);
        let mut repo = MemoryRepository::new(expected(), grant());
        repo.apply_change(&auth, &[PatchHunk::write("src/lib.rs", b"x".to_vec())])
            .expect("apply");
        let err = repo
            .apply_change(
                &auth,
                &[
                    PatchHunk::write("src/other.rs", b"y".to_vec()),
                    PatchHunk::delete("src/ghost.rs"),
                ],
            )
            .expect_err("refused");
        assert_eq!(err.reason_code(), "PATH_ABSENT");
        assert_eq!(
            repo.read_tree(&auth).expect("read"),
            vec!["src/lib.rs".to_string()],
            "failed batch must not mutate"
        );
        repo.apply_change(&auth, &[PatchHunk::delete("src/lib.rs")])
            .expect("delete");
        assert!(repo.read_tree(&auth).expect("read").is_empty());
        let candidate = repo.prepare_candidate(&auth, &change()).expect("prepare");
        assert!(candidate.actual_scope.is_empty());
    }

    #[test]
    fn evolution_produces_new_candidate_and_proof_binds() {
        let auth = token("atm_1", 3);
        let mut repo = MemoryRepository::new(expected(), grant());
        repo.apply_change(
            &auth,
            &[PatchHunk::write("src/lib.rs", b"fn main() {}".to_vec())],
        )
        .expect("apply");
        let checkpoint = repo.checkpoint(&auth).expect("checkpoint");
        assert_eq!(checkpoint.through_seq, 1);
        let candidate = repo.prepare_candidate(&auth, &change()).expect("prepare");
        let proof = bind_proof(&candidate);
        assert_eq!(proof.candidate, candidate.id);
        let (repaired, edge) = MemoryRepository::evolve(&candidate, EvolutionKind::Repair, "r1");
        assert_eq!(edge.kind, EvolutionKind::Repair);
        assert_ne!(repaired.id, candidate.id);
        assert_eq!(repaired.change, candidate.change);
        assert_eq!(repaired.parent_candidate_id, Some(candidate.id));
    }
}
