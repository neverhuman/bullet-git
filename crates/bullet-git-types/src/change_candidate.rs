//! Candidate manifest, addresses, and write-set grant check.

use super::*;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Exact Hub-compatible schema-1 Candidate identity subject.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateManifest {
    /// Schema version.
    pub schema_version: u32,
    /// Repository authority subject.
    pub repository_id: RepositoryId,
    /// Stable logical Change.
    pub change_id: ChangeId,
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
    /// Repository base commit.
    pub base_commit: GitOid,
    /// Controlled private-branch commit.
    pub head_commit: GitOid,
    /// Exact Git tree.
    pub tree_oid: GitOid,
    /// BLAKE3 of the exact `git diff base..head` bytes.
    pub patch_digest: Digest,
    /// Predecessor Candidates, in authoritative order.
    pub parent_candidate_ids: Vec<CandidateId>,
    /// Scope granted to the producing Attempt.
    pub granted_scope: Vec<RepoPath>,
    /// Paths actually written, sorted by the repository scanner.
    pub actual_scope: Vec<RepoPath>,
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

impl CandidateManifest {
    /// Reusable repository-content identity. Producing provenance is excluded.
    ///
    /// # Errors
    ///
    /// Returns `CANONICAL_JSON_FAILED` if the strict manifest cannot be
    /// encoded. The algorithm and domain exactly mirror Hub `bullet-wire`.
    pub fn content_id(&self) -> Result<ContentId, CandidateManifestError> {
        let content = CandidateContentManifest {
            repository_id: &self.repository_id,
            base_commit: &self.base_commit,
            head_commit: &self.head_commit,
            tree_oid: &self.tree_oid,
            patch_digest: self.patch_digest,
        };
        hash_canonical("candidate.content", &content).map(ContentId::from_digest)
    }

    /// Provenance-bound Candidate identity.
    ///
    /// # Errors
    ///
    /// Refuses unsupported schemas, zero fences, out-of-grant actual paths,
    /// or failed canonical encoding.
    pub fn candidate_id(&self) -> Result<CandidateId, CandidateManifestError> {
        self.validate()?;
        hash_canonical("candidate.provenance", self).map(CandidateId::from_digest)
    }

    /// Validate semantic invariants shared with Hub `bullet-wire`.
    ///
    /// # Errors
    ///
    /// Returns a typed manifest refusal.
    pub fn validate(&self) -> Result<(), CandidateManifestError> {
        if self.schema_version != CANDIDATE_MANIFEST_SCHEMA_VERSION {
            return Err(CandidateManifestError::UnsupportedSchema(
                self.schema_version,
            ));
        }
        if self.attempt_fence == 0 {
            return Err(CandidateManifestError::InvalidFence);
        }
        write_set_within_grant(&self.granted_scope, &self.actual_scope)
    }
}

#[derive(Serialize)]
struct CandidateContentManifest<'a> {
    repository_id: &'a RepositoryId,
    base_commit: &'a GitOid,
    head_commit: &'a GitOid,
    tree_oid: &'a GitOid,
    patch_digest: Digest,
}

/// Candidate manifest refusal with stable reason codes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CandidateManifestError {
    /// Unsupported disposable pre-1.0 schema.
    #[error("CandidateManifest schema {0} is unsupported")]
    UnsupportedSchema(u32),
    /// Fence zero can never identify a writer incarnation.
    #[error("Candidate fence must be nonzero")]
    InvalidFence,
    /// An observed path was outside the exact grant.
    #[error("actual path {0} is outside the granted scope")]
    ActualScopeExceedsGrant(String),
    /// Stored provenance identity differs from the manifest-derived identity.
    #[error("stored Candidate id does not match the manifest-derived id")]
    CandidateIdMismatch,
    /// Stored content identity differs from the manifest-derived identity.
    #[error("stored Candidate content id does not match the manifest-derived id")]
    ContentIdMismatch,
    /// RFC 8785 encoding failed.
    #[error("canonical Candidate encoding failed: {0}")]
    CanonicalJson(String),
}

impl CandidateManifestError {
    /// Stable machine-readable refusal code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::UnsupportedSchema(_) => "UNSUPPORTED_SCHEMA",
            Self::InvalidFence => "INVALID_FENCE",
            Self::ActualScopeExceedsGrant(_) => "ACTUAL_SCOPE_EXCEEDS_GRANT",
            Self::CandidateIdMismatch => "CANDIDATE_ID_MISMATCH",
            Self::ContentIdMismatch => "CONTENT_ID_MISMATCH",
            Self::CanonicalJson(_) => "CANONICAL_JSON_FAILED",
        }
    }
}

/// Immutable implementation with separate content and provenance addresses.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Candidate {
    /// Provenance-bound identity.
    pub id: CandidateId,
    /// Reusable repository-content identity.
    pub content_id: ContentId,
    /// Exact identity subject.
    pub manifest: CandidateManifest,
    /// Non-authoritative observation metadata from the caller's clock.
    pub prepared_at: String,
}

impl Candidate {
    /// Construct and address an exact Candidate manifest.
    ///
    /// # Errors
    ///
    /// Returns a typed manifest refusal before a Candidate exists.
    pub fn from_manifest(
        manifest: CandidateManifest,
        prepared_at: String,
    ) -> Result<Self, CandidateManifestError> {
        let content_id = manifest.content_id()?;
        let id = manifest.candidate_id()?;
        Ok(Self {
            id,
            content_id,
            manifest,
            prepared_at,
        })
    }

    /// Recompute both stored addresses from the exact manifest.
    ///
    /// This must run after deserialization and before a Candidate becomes a
    /// proof subject. It also re-applies the manifest's semantic validation.
    ///
    /// # Errors
    ///
    /// Returns a typed manifest or stored-identity refusal.
    pub fn validate_identity(&self) -> Result<(), CandidateManifestError> {
        if self.id != self.manifest.candidate_id()? {
            return Err(CandidateManifestError::CandidateIdMismatch);
        }
        if self.content_id != self.manifest.content_id()? {
            return Err(CandidateManifestError::ContentIdMismatch);
        }
        Ok(())
    }
}

/// Object write-set proof. AST/symbol advice must not replace this check.
///
/// # Errors
///
/// `ACTUAL_SCOPE_EXCEEDS_GRANT` for any observed path outside the grant.
pub fn write_set_within_grant(
    granted: &[RepoPath],
    actual: &[RepoPath],
) -> Result<(), CandidateManifestError> {
    for path in actual {
        if !granted
            .iter()
            .any(|grant| path_is_within(grant.as_str(), path.as_str()))
        {
            return Err(CandidateManifestError::ActualScopeExceedsGrant(
                path.to_string(),
            ));
        }
    }
    Ok(())
}

fn path_is_within(grant: &str, path: &str) -> bool {
    path == grant
        || path
            .strip_prefix(grant)
            .is_some_and(|remainder| remainder.starts_with('/'))
}

pub(crate) fn hash_canonical<T: Serialize>(
    domain: &str,
    value: &T,
) -> Result<Digest, CandidateManifestError> {
    let canonical = serde_jcs::to_vec(value)
        .map_err(|error| CandidateManifestError::CanonicalJson(error.to_string()))?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"bullet-wire.v1\0");
    hash_frame(&mut hasher, domain.as_bytes());
    hash_frame(&mut hasher, &canonical);
    Ok(Digest::from_bytes(*hasher.finalize().as_bytes()))
}

fn hash_frame(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}
