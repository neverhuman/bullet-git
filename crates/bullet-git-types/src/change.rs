//! Change, provenance-bound Candidate, evolution edges, and proof roots.

use crate::ids::{
    AttemptId, CandidateId, ChangeId, CheckpointId, ContentId, GitOid, GraphRevisionId,
    PlanRevisionId, RepositoryId, VariantId, WorkPackageId,
};
use crate::{Digest, RepoPath};
use serde::{Deserialize, Serialize};

#[path = "change_candidate.rs"]
mod candidate;
#[path = "change_proof.rs"]
mod proof;
#[cfg(test)]
#[path = "change_tests.rs"]
mod tests;

pub(crate) use candidate::hash_canonical;
pub use candidate::*;
pub use proof::*;

/// Frozen local mirror of the Hub `bullet-wire` Candidate manifest schema.
///
/// This mirror exists only until BulletGit can consume an immutable Hub tag.
pub const CANDIDATE_MANIFEST_SCHEMA_VERSION: u32 = 1;

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

impl EvolutionKind {
    /// Whether dependent Evidence must be invalidated.
    #[must_use]
    pub const fn invalidates_evidence(self) -> bool {
        matches!(
            self,
            Self::Rebase | Self::Squash | Self::Split | Self::MergeComposition | Self::CherryPick
        )
    }
}

/// One typed evolution edge. The ChangeId may survive; the CandidateId never does.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvolutionEdge {
    /// Predecessor.
    pub from: CandidateId,
    /// Successor.
    pub to: CandidateId,
    /// Kind.
    pub kind: EvolutionKind,
}

impl EvolutionEdge {
    /// Evidence bound to `from` is unusable after this edge when the kind rewrites identity.
    #[must_use]
    pub const fn invalidates_evidence(&self) -> bool {
        self.kind.invalidates_evidence()
    }
}

/// Logical change. Narrative fields influence the controlled commit, but are
/// not direct Candidate identity inputs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Change {
    /// Stable intention.
    pub id: ChangeId,
    /// Mission seed or id.
    pub mission: String,
    /// Acceptance digest.
    pub acceptance_root: Digest,
}

/// Kernel-owned provenance required before BulletGit may prepare a Candidate.
///
/// Repository-derived fields (`head_commit`, `tree_oid`, `patch_digest`, and
/// `actual_scope`) are intentionally absent. BulletGit computes those facts.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateProvenance {
    /// Must equal [`CANDIDATE_MANIFEST_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Repository authority subject.
    pub repository_id: RepositoryId,
    /// Attempt that produced the implementation.
    pub producing_attempt_id: AttemptId,
    /// Permanent Attempt fence.
    pub attempt_fence: u64,
    /// Scheduled work package.
    pub work_package_id: WorkPackageId,
    /// Routed Variant.
    pub variant_id: VariantId,
    /// Exact plan revision.
    pub plan_revision_id: PlanRevisionId,
    /// Exact graph revision.
    pub graph_revision_id: GraphRevisionId,
    /// Daemon-issued checkpoint from which preparation starts.
    pub base_checkpoint_id: CheckpointId,
    /// Exact repository base commit expected by the caller.
    pub base_commit: GitOid,
    /// Predecessor Candidates, in authoritative order.
    pub parent_candidate_ids: Vec<CandidateId>,
    /// Exact scope granted to this Attempt.
    pub granted_scope: Vec<RepoPath>,
    /// Context capsule snapshot.
    pub context_capsule_id: ContentId,
    /// Configuration snapshot.
    pub configuration_snapshot_id: ContentId,
    /// Policy snapshot.
    pub policy_snapshot_id: ContentId,
    /// Routing snapshot.
    pub routing_snapshot_id: ContentId,
    /// Execution environment digest.
    pub environment_digest: Digest,
    /// Toolchain digest.
    pub toolchain_digest: Digest,
}

impl CandidateProvenance {
    /// Validate the explicit schema and writer incarnation before repository
    /// preparation can begin.
    ///
    /// # Errors
    ///
    /// Refuses unsupported schemas and fence zero.
    pub fn validate(&self) -> Result<(), CandidateManifestError> {
        if self.schema_version != CANDIDATE_MANIFEST_SCHEMA_VERSION {
            return Err(CandidateManifestError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if self.attempt_fence == 0 {
            return Err(CandidateManifestError::InvalidFence);
        }
        Ok(())
    }
}
