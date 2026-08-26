//! Change, provenance-bound Candidate, evolution edges, and proof roots.

use crate::ids::{
    AttemptId, CandidateId, ChangeId, CheckpointId, ContentId, GitOid, GraphRevisionId,
    PlanRevisionId, RepositoryId, VariantId, WorkPackageId,
};
use crate::{frame, framed_digest, Digest, RepoPath};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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

/// Eight caller-supplied `git_role.md` ProofRoot leaves.
///
/// Candidate identity, base/head/tree/patch hashes, and change/lineage are
/// taken from the Candidate. Empty leaves still bind those Candidate facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProofInputs<'a> {
    /// Scope grant and the actual write set.
    pub scope_and_write_set: &'a [u8],
    /// Runner and sandbox attestation.
    pub runner_and_sandbox: &'a [u8],
    /// Toolchain and dependency manifests.
    pub toolchain_and_deps: &'a [u8],
    /// Deterministic Evidence.
    pub evidence: &'a [u8],
    /// Independent verifier Evidence.
    pub verifier_evidence: &'a [u8],
    /// Reviews and independence calculation.
    pub reviews: &'a [u8],
    /// Policy decision.
    pub policy: &'a [u8],
    /// Human approvals and Effect receipts.
    pub approvals_and_effect_receipts: &'a [u8],
}

impl ProofInputs<'_> {
    /// All eight leaves empty. The Candidate still binds.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            scope_and_write_set: b"",
            runner_and_sandbox: b"",
            toolchain_and_deps: b"",
            evidence: b"",
            verifier_evidence: b"",
            reviews: b"",
            policy: b"",
            approvals_and_effect_receipts: b"",
        }
    }

    /// Named leaves in bind order, for tamper tests.
    #[must_use]
    pub const fn named_leaves(&self) -> [(&'static str, &[u8]); 8] {
        [
            ("scope_and_write_set", self.scope_and_write_set),
            ("runner_and_sandbox", self.runner_and_sandbox),
            ("toolchain_and_deps", self.toolchain_and_deps),
            ("evidence", self.evidence),
            ("verifier_evidence", self.verifier_evidence),
            ("reviews", self.reviews),
            ("policy", self.policy),
            (
                "approvals_and_effect_receipts",
                self.approvals_and_effect_receipts,
            ),
        ]
    }
}

/// Merkle binding of proof claims to an exact Candidate.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofRoot {
    /// Subject.
    pub candidate: CandidateId,
    /// Bound digest.
    pub root: Digest,
}

/// Proof-root verification refusal.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProofRootError {
    /// Recomputed digest or subject does not match the stored root.
    #[error("proof root does not match the Candidate and inputs")]
    Mismatch,
}

impl ProofRootError {
    /// Stable machine-readable refusal code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::Mismatch => "PROOF_ROOT_MISMATCH",
        }
    }
}

impl ProofRoot {
    /// Compute a proof root. Empty fields still bind the exact Candidate.
    ///
    /// Maps the four historical blobs onto the eight-leaf bind: scope, evidence,
    /// reviews, and policy. The other four leaves are empty.
    #[must_use]
    pub fn compute(
        candidate: &Candidate,
        scope: &[u8],
        evidence: &[u8],
        reviews: &[u8],
        policy: &[u8],
    ) -> Self {
        Self::bind(
            candidate,
            &ProofInputs {
                scope_and_write_set: scope,
                runner_and_sandbox: b"",
                toolchain_and_deps: b"",
                evidence,
                verifier_evidence: b"",
                reviews,
                policy,
                approvals_and_effect_receipts: b"",
            },
        )
    }

    /// Bind the Candidate-derived tree plus the eight caller leaves.
    #[must_use]
    pub fn bind(candidate: &Candidate, inputs: &ProofInputs<'_>) -> Self {
        let manifest = &candidate.manifest;
        let mut lineage = Vec::new();
        frame(&mut lineage, manifest.change_id.as_str().as_bytes());
        for parent in &manifest.parent_candidate_ids {
            frame(&mut lineage, parent.as_str().as_bytes());
        }
        Self {
            candidate: candidate.id.clone(),
            root: framed_digest(&[
                b"proof-root.v3",
                candidate.id.as_str().as_bytes(),
                candidate.content_id.as_str().as_bytes(),
                manifest.base_commit.as_str().as_bytes(),
                manifest.head_commit.as_str().as_bytes(),
                manifest.tree_oid.as_str().as_bytes(),
                manifest.patch_digest.as_bytes(),
                &lineage,
                inputs.scope_and_write_set,
                inputs.runner_and_sandbox,
                inputs.toolchain_and_deps,
                inputs.evidence,
                inputs.verifier_evidence,
                inputs.reviews,
                inputs.policy,
                inputs.approvals_and_effect_receipts,
            ]),
        }
    }

    /// Recompute the root and refuse on any mismatch.
    ///
    /// # Errors
    ///
    /// `PROOF_ROOT_MISMATCH` when the subject or digest differs.
    pub fn verify(
        &self,
        candidate: &Candidate,
        inputs: &ProofInputs<'_>,
    ) -> Result<(), ProofRootError> {
        if self != &Self::bind(candidate, inputs) {
            return Err(ProofRootError::Mismatch);
        }
        Ok(())
    }
}

/// Recompute a stored proof root on read.
///
/// # Errors
///
/// `PROOF_ROOT_MISMATCH` when the subject or digest differs.
pub fn verify_proof_root(
    root: &ProofRoot,
    candidate: &Candidate,
    inputs: &ProofInputs<'_>,
) -> Result<(), ProofRootError> {
    root.verify(candidate, inputs)
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GitOidAlgorithm;
    use std::str::FromStr;

    fn repeated_id<T>(prefix: &str, hex: char) -> T
    where
        T: TryFrom<String>,
        T::Error: std::fmt::Debug,
    {
        T::try_from(format!("{prefix}_{}", hex.to_string().repeat(64))).expect("typed id")
    }

    fn manifest() -> CandidateManifest {
        CandidateManifest {
            schema_version: CANDIDATE_MANIFEST_SCHEMA_VERSION,
            repository_id: repeated_id("rep", '1'),
            change_id: repeated_id("chg", '2'),
            producing_attempt_id: repeated_id("atm", '3'),
            attempt_fence: 17,
            work_package_id: repeated_id("wpk", '4'),
            variant_id: repeated_id("var", '5'),
            plan_revision_id: repeated_id("pln", '6'),
            graph_revision_id: repeated_id("grf", '7'),
            base_checkpoint_id: repeated_id("ckp", '8'),
            base_commit: GitOid::new(format!("sha1:{}", "9".repeat(40))).expect("oid"),
            head_commit: GitOid::new(format!("sha1:{}", "a".repeat(40))).expect("oid"),
            tree_oid: GitOid::new(format!("sha1:{}", "b".repeat(40))).expect("oid"),
            patch_digest: Digest::from_bytes([12; 32]),
            parent_candidate_ids: vec![repeated_id("can", 'd')],
            granted_scope: vec![RepoPath::from_str("src").expect("path")],
            actual_scope: vec![RepoPath::from_str("src/lib.rs").expect("path")],
            context_capsule_id: repeated_id("cnt", 'e'),
            configuration_snapshot_id: repeated_id("cnt", '1'),
            policy_snapshot_id: repeated_id("cnt", '2'),
            routing_snapshot_id: repeated_id("cnt", '3'),
            environment_digest: Digest::from_bytes([14; 32]),
            toolchain_digest: Digest::from_bytes([15; 32]),
        }
    }

    #[test]
    fn hub_candidate_golden_is_exact() {
        let manifest = manifest();
        const HUB_CANONICAL: &str = r#"{"actual_scope":["src/lib.rs"],"attempt_fence":17,"base_checkpoint_id":"ckp_8888888888888888888888888888888888888888888888888888888888888888","base_commit":"sha1:9999999999999999999999999999999999999999","change_id":"chg_2222222222222222222222222222222222222222222222222222222222222222","configuration_snapshot_id":"cnt_1111111111111111111111111111111111111111111111111111111111111111","context_capsule_id":"cnt_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","environment_digest":"0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e","granted_scope":["src"],"graph_revision_id":"grf_7777777777777777777777777777777777777777777777777777777777777777","head_commit":"sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","parent_candidate_ids":["can_dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],"patch_digest":"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c","plan_revision_id":"pln_6666666666666666666666666666666666666666666666666666666666666666","policy_snapshot_id":"cnt_2222222222222222222222222222222222222222222222222222222222222222","producing_attempt_id":"atm_3333333333333333333333333333333333333333333333333333333333333333","repository_id":"rep_1111111111111111111111111111111111111111111111111111111111111111","routing_snapshot_id":"cnt_3333333333333333333333333333333333333333333333333333333333333333","schema_version":1,"toolchain_digest":"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f","tree_oid":"sha1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","variant_id":"var_5555555555555555555555555555555555555555555555555555555555555555","work_package_id":"wpk_4444444444444444444444444444444444444444444444444444444444444444"}"#;
        assert_eq!(
            String::from_utf8(serde_jcs::to_vec(&manifest).expect("canonical")).expect("utf8"),
            HUB_CANONICAL
        );
        assert_eq!(
            manifest.candidate_id().expect("candidate").as_str(),
            "can_66da272ac2783b2e7c67ff8c3e88dc941b4853838ea24a0d133de6c619e5cdf1"
        );
        assert_eq!(
            manifest.content_id().expect("content").as_str(),
            "cnt_a37542cdff7a381b42a24e83fa1c2875506c6e8fbf492c4317c9a81f44e7c19b"
        );
    }

    #[test]
    fn provenance_changes_leave_content_identity_reusable() {
        let original = manifest();
        let mut successor = original.clone();
        successor.attempt_fence += 1;
        successor.producing_attempt_id = repeated_id("atm", 'f');
        assert_eq!(
            original.content_id().expect("content"),
            successor.content_id().expect("content")
        );
        assert_ne!(
            original.candidate_id().expect("candidate"),
            successor.candidate_id().expect("candidate")
        );
    }

    #[test]
    fn every_content_manifest_field_changes_content_identity() {
        let original = manifest();
        let content_id = original.content_id().expect("content");

        let mut repository = original.clone();
        repository.repository_id = repeated_id("rep", 'f');
        let mut base = original.clone();
        base.base_commit = GitOid::new(format!("sha1:{}", "0".repeat(40))).expect("oid");
        let mut head = original.clone();
        head.head_commit = GitOid::new(format!("sha1:{}", "1".repeat(40))).expect("oid");
        let mut tree = original.clone();
        tree.tree_oid = GitOid::new(format!("sha1:{}", "2".repeat(40))).expect("oid");
        let mut patch = original;
        patch.patch_digest = Digest::from_bytes([3; 32]);

        for (field, changed) in [
            ("repository_id", repository),
            ("base_commit", base),
            ("head_commit", head),
            ("tree_oid", tree),
            ("patch_digest", patch),
        ] {
            assert_ne!(
                changed.content_id().expect("content"),
                content_id,
                "{field}"
            );
        }
    }

    #[test]
    fn observation_metadata_is_not_candidate_authority() {
        let manifest = manifest();
        let earlier = Candidate::from_manifest(manifest.clone(), "2026-08-24T00:00:00Z".into())
            .expect("candidate");
        let later =
            Candidate::from_manifest(manifest, "2026-08-25T00:00:00Z".into()).expect("candidate");
        assert_eq!(earlier.id, later.id);
        assert_eq!(earlier.content_id, later.content_id);
        assert_ne!(earlier.prepared_at, later.prepared_at);
    }

    #[test]
    fn every_manifest_field_is_candidate_sensitive() {
        let manifest = manifest();
        let original = manifest.candidate_id().expect("candidate");
        let value = serde_json::to_value(&manifest).expect("value");
        for key in value.as_object().expect("object").keys() {
            let mut changed = value.clone();
            changed.as_object_mut().expect("object").remove(key);
            let digest = hash_canonical("candidate.provenance", &changed).expect("hash");
            assert_ne!(CandidateId::from_digest(digest), original, "field {key}");
        }
    }

    #[test]
    fn validation_refuses_zero_fence_and_scope_escape() {
        let mut zero = manifest();
        zero.attempt_fence = 0;
        assert_eq!(
            zero.candidate_id().expect_err("zero fence").reason_code(),
            "INVALID_FENCE"
        );
        let mut escaped = manifest();
        escaped.actual_scope = vec![RepoPath::from_str("src2/lib.rs").expect("path")];
        assert_eq!(
            escaped
                .candidate_id()
                .expect_err("scope escape")
                .reason_code(),
            "ACTUAL_SCOPE_EXCEEDS_GRANT"
        );
    }

    #[test]
    fn proof_root_changes_when_candidate_changes() {
        let a =
            Candidate::from_manifest(manifest(), "2026-08-24T00:00:00Z".into()).expect("candidate");
        let mut changed = manifest();
        changed.tree_oid = GitOid::from_hex(GitOidAlgorithm::Sha1, "c".repeat(40)).expect("tree");
        let b =
            Candidate::from_manifest(changed, "2026-08-24T00:00:00Z".into()).expect("candidate");
        let ra = ProofRoot::compute(&a, b"", b"", b"", b"");
        let rb = ProofRoot::compute(&b, b"", b"", b"", b"");
        assert_ne!(ra.root, rb.root);
        assert_eq!(ra, ProofRoot::compute(&a, b"", b"", b"", b""));
    }

    #[test]
    fn proof_root_field_shift_does_not_collide() {
        let candidate = Candidate::from_manifest(manifest(), "observed".into()).expect("candidate");
        let one = ProofRoot::compute(&candidate, b"xy", b"", b"", b"");
        let two = ProofRoot::compute(&candidate, b"x", b"y", b"", b"");
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
