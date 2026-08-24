//! Change and Candidate identities. A ChangeId never authorizes integration.

use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

/// Digest of a proof-carrying object.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest([u8; 32]);

impl Digest {
    /// Hash bytes with BLAKE3.
    #[must_use]
    pub fn of(bytes: &[u8]) -> Self {
        Self(*blake3::hash(bytes).as_bytes())
    }

    /// Hex form.
    #[must_use]
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }
}

macro_rules! typed_id {
    ($name:ident, $prefix:literal) => {
        #[doc = concat!("Typed `", $prefix, "` identifier.")]
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            /// Deterministic id from a seed.
            #[must_use]
            pub fn from_seed(seed: &str) -> Self {
                let digest = Digest::of(format!("{}:{seed}", $prefix).as_bytes());
                Self(format!("{}_{}", $prefix, &digest.to_hex()[..32]))
            }

            /// Borrow the prefixed string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

typed_id!(ChangeId, "chg");
typed_id!(CandidateId, "can");
typed_id!(CheckpointId, "ckp");

/// Exported ordinary Git object id.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct GitOid(pub String);

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

/// Exact implementation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    /// Exact identity.
    pub id: CandidateId,
    /// Parent change.
    pub change: ChangeId,
    /// Exported Git commit.
    pub git_commit: GitOid,
    /// Tree.
    pub tree: GitOid,
    /// Patch digest.
    pub patch_digest: Digest,
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
    #[must_use]
    pub fn compute(
        candidate: &Candidate,
        scope: &[u8],
        evidence: &[u8],
        reviews: &[u8],
        policy: &[u8],
    ) -> Self {
        let mut buf = Vec::new();
        buf.extend_from_slice(candidate.id.as_str().as_bytes());
        buf.extend_from_slice(candidate.git_commit.0.as_bytes());
        buf.extend_from_slice(candidate.tree.0.as_bytes());
        buf.extend_from_slice(&candidate.patch_digest.0);
        buf.extend_from_slice(scope);
        buf.extend_from_slice(evidence);
        buf.extend_from_slice(reviews);
        buf.extend_from_slice(policy);
        Self {
            candidate: candidate.id.clone(),
            root: Digest::of(&buf),
        }
    }
}

/// Opaque authority envelope supplied by Bullet Farm.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityEnvelope {
    /// Raw token bytes (JSON of AuthorityToken).
    pub token: Vec<u8>,
}

impl AuthorityEnvelope {
    /// Reject an empty envelope.
    #[must_use]
    pub fn is_present(&self) -> bool {
        !self.token.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn change_id_is_not_candidate_id() {
        let change = ChangeId::from_seed("auth");
        let candidate = CandidateId::from_seed("auth");
        assert!(change.as_str().starts_with("chg_"));
        assert!(candidate.as_str().starts_with("can_"));
        assert_ne!(change.as_str(), candidate.as_str());
    }

    #[test]
    fn proof_root_changes_when_candidate_changes() {
        let change = ChangeId::from_seed("c");
        let a = Candidate {
            id: CandidateId::from_seed("c1"),
            change: change.clone(),
            git_commit: GitOid("aaa".into()),
            tree: GitOid("t1".into()),
            patch_digest: Digest::of(b"p1"),
        };
        let mut b = a.clone();
        b.id = CandidateId::from_seed("c2");
        b.git_commit = GitOid("bbb".into());
        let ra = ProofRoot::compute(&a, b"", b"", b"", b"");
        let rb = ProofRoot::compute(&b, b"", b"", b"", b"");
        assert_ne!(ra.root, rb.root);
    }
}
