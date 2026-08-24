//! Capability-secure repository API. Agents do not receive a Git binary.

use bullet_git_journal::{Checkpoint, Journal};
use bullet_git_types::{
    AuthorityEnvelope, Candidate, CandidateId, Change, Digest, EvolutionEdge, EvolutionKind,
    GitOid, ProofRoot,
};
use thiserror::Error;

/// Capability error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CapabilityError {
    /// Missing or empty authority envelope.
    #[error("authority required")]
    Unauthorized,
    /// Path is outside the granted scope.
    #[error("path out of scope: {0}")]
    OutOfScope(String),
    /// Workspace is a Git worktree.
    #[error("writable worktrees are forbidden")]
    WorktreeForbidden,
}

/// One file patch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatchHunk {
    /// Relative path.
    pub path: String,
    /// Replacement bytes.
    pub contents: Vec<u8>,
}

/// Agent-facing repository capability.
pub trait AgentRepository {
    /// Read a tree listing.
    ///
    /// # Errors
    ///
    /// Returns unauthorized when the envelope is empty.
    fn read_tree(&self, auth: &AuthorityEnvelope) -> Result<Vec<String>, CapabilityError>;

    /// Apply a scoped patch.
    ///
    /// # Errors
    ///
    /// Returns unauthorized or out-of-scope.
    fn apply_change(
        &mut self,
        auth: &AuthorityEnvelope,
        patches: &[PatchHunk],
    ) -> Result<(), CapabilityError>;

    /// Checkpoint the journal.
    ///
    /// # Errors
    ///
    /// Returns unauthorized when the envelope is empty.
    fn checkpoint(&mut self, auth: &AuthorityEnvelope) -> Result<Checkpoint, CapabilityError>;

    /// Prepare an exact Candidate from the current tree.
    ///
    /// # Errors
    ///
    /// Returns unauthorized when the envelope is empty.
    fn prepare_candidate(
        &mut self,
        auth: &AuthorityEnvelope,
        change: &Change,
    ) -> Result<Candidate, CapabilityError>;
}

/// In-process fake used until jeryu-gitd capability sessions land.
#[derive(Default)]
pub struct MemoryRepository {
    files: Vec<(String, Vec<u8>)>,
    journal: Journal,
    is_worktree: bool,
}

impl MemoryRepository {
    /// Empty private clone.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Mark the workspace as a worktree so writes fail closed.
    #[must_use]
    pub fn worktree() -> Self {
        Self {
            is_worktree: true,
            ..Self::default()
        }
    }

    /// Record a typed evolution edge.
    #[must_use]
    pub fn evolve(from: &Candidate, kind: EvolutionKind, seed: &str) -> (Candidate, EvolutionEdge) {
        let next = Candidate {
            id: CandidateId::from_seed(seed),
            change: from.change.clone(),
            git_commit: GitOid(format!("git-{seed}")),
            tree: from.tree.clone(),
            patch_digest: Digest::of(seed.as_bytes()),
        };
        let edge = EvolutionEdge {
            from: from.id.clone(),
            to: next.id.clone(),
            kind,
        };
        (next, edge)
    }
}

fn require(auth: &AuthorityEnvelope) -> Result<(), CapabilityError> {
    if auth.is_present() {
        Ok(())
    } else {
        Err(CapabilityError::Unauthorized)
    }
}

impl AgentRepository for MemoryRepository {
    fn read_tree(&self, auth: &AuthorityEnvelope) -> Result<Vec<String>, CapabilityError> {
        require(auth)?;
        Ok(self.files.iter().map(|(p, _)| p.clone()).collect())
    }

    fn apply_change(
        &mut self,
        auth: &AuthorityEnvelope,
        patches: &[PatchHunk],
    ) -> Result<(), CapabilityError> {
        require(auth)?;
        if self.is_worktree {
            return Err(CapabilityError::WorktreeForbidden);
        }
        for patch in patches {
            if patch.path.starts_with('/') || patch.path.contains("..") {
                return Err(CapabilityError::OutOfScope(patch.path.clone()));
            }
            self.journal.record(&patch.path, &patch.contents);
            if let Some((_, existing)) = self.files.iter_mut().find(|(p, _)| p == &patch.path) {
                *existing = patch.contents.clone();
            } else {
                self.files
                    .push((patch.path.clone(), patch.contents.clone()));
            }
        }
        Ok(())
    }

    fn checkpoint(&mut self, auth: &AuthorityEnvelope) -> Result<Checkpoint, CapabilityError> {
        require(auth)?;
        Ok(self.journal.checkpoint())
    }

    fn prepare_candidate(
        &mut self,
        auth: &AuthorityEnvelope,
        change: &Change,
    ) -> Result<Candidate, CapabilityError> {
        require(auth)?;
        let mut blob = Vec::new();
        for (path, bytes) in &self.files {
            blob.extend_from_slice(path.as_bytes());
            blob.extend_from_slice(bytes);
        }
        Ok(Candidate {
            id: CandidateId::from_seed(&change.id.to_string()),
            change: change.id.clone(),
            git_commit: GitOid(Digest::of(&blob).to_hex()),
            tree: GitOid(Digest::of(&blob).to_hex()),
            patch_digest: Digest::of(&blob),
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

    #[test]
    fn empty_token_is_rejected() {
        let repo = MemoryRepository::new();
        let auth = AuthorityEnvelope { token: vec![] };
        assert_eq!(repo.read_tree(&auth), Err(CapabilityError::Unauthorized));
    }

    #[test]
    fn worktree_writes_are_blocked() {
        let mut repo = MemoryRepository::worktree();
        let auth = AuthorityEnvelope {
            token: b"token".to_vec(),
        };
        let err = repo
            .apply_change(
                &auth,
                &[PatchHunk {
                    path: "src/lib.rs".into(),
                    contents: b"x".to_vec(),
                }],
            )
            .expect_err("blocked");
        assert_eq!(err, CapabilityError::WorktreeForbidden);
    }

    #[test]
    fn prepare_candidate_and_proof() {
        use bullet_git_types::ChangeId;
        let mut repo = MemoryRepository::new();
        let auth = AuthorityEnvelope {
            token: b"token".to_vec(),
        };
        repo.apply_change(
            &auth,
            &[PatchHunk {
                path: "src/lib.rs".into(),
                contents: b"fn main() {}".to_vec(),
            }],
        )
        .expect("patch");
        let _ = repo.checkpoint(&auth).expect("checkpoint");
        let change = Change {
            id: ChangeId::from_seed("feat"),
            mission: "demo".into(),
            acceptance_root: Digest::of(b"acc"),
        };
        let candidate = repo.prepare_candidate(&auth, &change).expect("candidate");
        let proof = bind_proof(&candidate);
        assert_eq!(proof.candidate, candidate.id);
        let (repaired, edge) = MemoryRepository::evolve(&candidate, EvolutionKind::Repair, "r1");
        assert_eq!(edge.kind, EvolutionKind::Repair);
        assert_ne!(repaired.id, candidate.id);
        assert_eq!(repaired.change, candidate.change);
    }
}
