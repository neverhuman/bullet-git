//! Change, Candidate, evolution edges, and proof roots.

use crate::ids::{CandidateId, ChangeId, GitOid};
use crate::{frame, Digest};
use serde::{Deserialize, Serialize};

/// How one Candidate became another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvolutionKind {
    /// Amend in place conceptually; still a new Candidate.
    Amend,
    /// Repair after verifier failure.
    Repair,
    /// Rebase onto a new base. Proof is invalidated.
    Rebase,
    /// Squash.
    Squash,
    /// Split.
    Split,
    /// Synthesis from other Candidates.
    Synthesis,
    /// Cherry-pick.
    CherryPick,
    /// Merge-group composition.
    MergeComposition,
    /// Regeneration of derived artifacts from unchanged sources.
    GeneratedRefresh,
}

/// One typed evolution edge. The ChangeId may survive; the CandidateId never does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvolutionEdge {
    /// Predecessor.
    pub from: CandidateId,
    /// Successor.
    pub to: CandidateId,
    /// Kind.
    pub kind: EvolutionKind,
}

/// Logical change.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    /// Stable intention.
    pub id: ChangeId,
    /// Mission seed or id.
    pub mission: String,
    /// Acceptance digest.
    pub acceptance_root: Digest,
}

/// Exact immutable implementation (spec §6.13 subset).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// Content-derived exact identity.
    pub id: CandidateId,
    /// Parent change.
    pub change: ChangeId,
    /// Base commit the workspace was cloned at.
    pub base_commit: GitOid,
    /// Head commit on the private branch.
    pub head_commit: GitOid,
    /// Exact tree of the head commit.
    pub tree_hash: GitOid,
    /// BLAKE3 of the `git diff base..head` bytes.
    pub patch_hash: Digest,
    /// Variant that produced this Candidate.
    pub variant_id: String,
    /// Attempt incarnation that produced this Candidate.
    pub attempt_id: String,
    /// Scope prefixes granted to the Attempt.
    pub granted_scope: Vec<String>,
    /// Paths actually written, sorted.
    pub actual_scope: Vec<String>,
    /// Predecessor Candidate on an evolution edge, when one exists.
    pub parent_candidate_id: Option<CandidateId>,
    /// Preparation timestamp from the caller's clock (RFC 3339).
    pub prepared_at: String,
    /// Lineage subject bound to this Candidate (kernel/wire sync).
    #[serde(default)]
    pub lineage_subject: Option<String>,
    /// Environment digest bound to this Candidate (kernel/wire sync).
    #[serde(default)]
    pub environment_digest: Option<Digest>,
}

/// Merkle binding of proof claims to an exact Candidate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRoot {
    /// Subject.
    pub candidate: CandidateId,
    /// Bound digest.
    pub root: Digest,
}

impl ProofRoot {
    /// Compute a proof root. Empty fields still bind the subject.
    ///
    /// Every field is length-prefix framed so no two field sequences share a
    /// preimage.
    #[must_use]
    pub fn compute(
        candidate: &Candidate,
        scope: &[u8],
        evidence: &[u8],
        reviews: &[u8],
        policy: &[u8],
    ) -> Self {
        let mut buf = Vec::new();
        for field in [
            b"proof-root.v1" as &[u8],
            candidate.id.as_str().as_bytes(),
            candidate.change.as_str().as_bytes(),
            candidate.base_commit.as_str().as_bytes(),
            candidate.head_commit.as_str().as_bytes(),
            candidate.tree_hash.as_str().as_bytes(),
            candidate.patch_hash.as_bytes(),
            scope,
            evidence,
            reviews,
            policy,
        ] {
            frame(&mut buf, field);
        }
        Self {
            candidate: candidate.id.clone(),
            root: Digest::of(&buf),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GitOidAlgorithm;

    fn candidate(tree: &str, head: &str) -> Candidate {
        let change = ChangeId::from_seed("c");
        let tree = GitOid::from_hex(GitOidAlgorithm::Sha1, tree.repeat(40)).expect("oid");
        let head = GitOid::from_hex(GitOidAlgorithm::Sha1, head.repeat(40)).expect("oid");
        Candidate {
            id: CandidateId::from_content(&change, &tree, &head),
            change,
            base_commit: GitOid::from_hex(GitOidAlgorithm::Sha1, "0".repeat(40)).expect("oid"),
            head_commit: head.clone(),
            tree_hash: tree,
            patch_hash: Digest::of(head.as_str().as_bytes()),
            variant_id: "var_demo".into(),
            attempt_id: "atm_demo".into(),
            granted_scope: vec!["src".into()],
            actual_scope: vec!["src/lib.rs".into()],
            parent_candidate_id: None,
            prepared_at: "2026-08-24T00:00:00Z".into(),
            lineage_subject: None,
            environment_digest: None,
        }
    }

    #[test]
    fn proof_root_changes_when_candidate_changes() {
        let a = candidate("a", "c");
        let b = candidate("b", "d");
        assert_ne!(a.id, b.id);
        let ra = ProofRoot::compute(&a, b"", b"", b"", b"");
        let rb = ProofRoot::compute(&b, b"", b"", b"", b"");
        assert_ne!(ra.root, rb.root);
        assert_eq!(ra, ProofRoot::compute(&a, b"", b"", b"", b""));
    }

    #[test]
    fn proof_root_field_shift_does_not_collide() {
        let a = candidate("a", "c");
        let one = ProofRoot::compute(&a, b"xy", b"", b"", b"");
        let two = ProofRoot::compute(&a, b"x", b"y", b"", b"");
        assert_ne!(one.root, two.root);
    }

    #[test]
    fn evolution_kind_has_generated_refresh() {
        let kind = EvolutionKind::GeneratedRefresh;
        let json = serde_json::to_string(&kind).expect("serialize");
        assert_eq!(json, "\"generated_refresh\"");
        let back: EvolutionKind = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, kind);
    }
}
