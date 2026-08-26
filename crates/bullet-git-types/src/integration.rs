//! Proof-carrying Candidate binding and first-class Integration subject
//! (`git_role.md` §6, §9, §13). The Hub schema-1 `CandidateManifest` mirror
//! in `change.rs` stays byte-exact so its cross-language golden holds; gate
//! set, proof root, and execution envelope bind here in a sibling identity.

mod root;

use crate::change::{hash_canonical, Candidate, CandidateManifestError, ProofRoot};
use crate::ids::{CandidateId, ContentId, GateId, GitOid};
use crate::{Digest, TypesError};
pub use root::{combined_proof_root, CandidateBindingCheck, IntegrationInputs, IntegrationRoot};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt::{Display, Formatter};
use thiserror::Error;

/// Schema of both sibling identity subjects in this module.
pub const INTEGRATION_MANIFEST_SCHEMA_VERSION: u32 = 1;
/// Upper bound on Candidates composed into one integration subject.
pub const MAX_INTEGRATION_CANDIDATES: usize = 64;
/// Upper bound on gates bound to one Candidate. Mirrors the Hub launch grant.
pub const MAX_BOUND_GATE_IDS: usize = 16;
/// Upper bound on `provider_version` bytes.
pub const MAX_PROVIDER_VERSION_BYTES: usize = 128;
/// Upper bound on `target_ref` bytes.
pub const MAX_TARGET_REF_BYTES: usize = 256;

macro_rules! digest_id {
    ($name:ident, $prefix:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Prefixed identity from a canonical digest.
            #[must_use]
            pub fn from_digest(digest: Digest) -> Self {
                Self(format!("{}_{}", $prefix, digest.to_hex()))
            }

            /// Parse a prefixed hex id.
            ///
            /// # Errors
            ///
            /// `INVALID_ID` when the prefix or the 64-hex body is wrong.
            pub fn parse(raw: impl AsRef<str>) -> Result<Self, TypesError> {
                let raw = raw.as_ref();
                let body = raw
                    .strip_prefix(concat!($prefix, "_"))
                    .ok_or_else(|| TypesError::InvalidId(raw.to_string()))?;
                Digest::from_hex(body).map_err(|_| TypesError::InvalidId(raw.to_string()))?;
                Ok(Self(raw.to_string()))
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

        impl TryFrom<String> for $name {
            type Error = TypesError;

            fn try_from(raw: String) -> Result<Self, Self::Error> {
                Self::parse(raw)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> Self {
                id.0
            }
        }
    };
}

digest_id!(
    BindingId,
    "bnd",
    "Canonical identity of a proof-carrying Candidate binding."
);
digest_id!(
    IntegrationId,
    "int",
    "Canonical identity of an integration subject."
);

/// Reproducible execution envelope (`git_role.md` §13).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEnvelope {
    /// Exact runner image that produced and verified the Candidate.
    pub runner_image_digest: Digest,
    /// Provider, model, and harness version string.
    pub provider_version: String,
    /// Dependency lock digest.
    pub lock_digest: Digest,
    /// Must equal the manifest `toolchain_digest`.
    pub toolchain_digest: Digest,
    /// Must equal the manifest `environment_digest`.
    pub environment_digest: Digest,
}

impl ExecutionEnvelope {
    fn validate(&self) -> Result<(), IntegrationError> {
        let version = &self.provider_version;
        if version.is_empty()
            || version.len() > MAX_PROVIDER_VERSION_BYTES
            || !version.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(IntegrationError::InvalidProviderVersion);
        }
        Ok(())
    }
}

/// Proof-carrying Candidate (`git_role.md` §6): the exact Candidate, its
/// required gate set, its proof root, and its execution envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CandidateBinding {
    /// Must equal [`INTEGRATION_MANIFEST_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Provenance-bound Candidate identity.
    pub candidate_id: CandidateId,
    /// Reusable Candidate content identity.
    pub content_id: ContentId,
    /// Required gates, strictly ascending and non-empty.
    pub gate_ids: Vec<GateId>,
    /// Digest of the Candidate [`ProofRoot`].
    pub proof_root: Digest,
    /// Execution envelope cross-bound to the manifest digests.
    pub envelope: ExecutionEnvelope,
}

impl CandidateBinding {
    /// Bind a validated Candidate, its proof root, gates, and envelope.
    ///
    /// # Errors
    ///
    /// Typed refusal when the Candidate identity, proof-root subject, envelope
    /// cross-bind, gate set, or provider version is wrong.
    pub fn bind(
        candidate: &Candidate,
        root: &ProofRoot,
        gate_ids: Vec<GateId>,
        envelope: ExecutionEnvelope,
    ) -> Result<Self, IntegrationError> {
        candidate.validate_identity()?;
        if root.candidate != candidate.id {
            return Err(IntegrationError::ProofRootSubjectMismatch);
        }
        let manifest = &candidate.manifest;
        if envelope.toolchain_digest != manifest.toolchain_digest {
            return Err(IntegrationError::EnvelopeMismatch("toolchain_digest"));
        }
        if envelope.environment_digest != manifest.environment_digest {
            return Err(IntegrationError::EnvelopeMismatch("environment_digest"));
        }
        let binding = Self {
            schema_version: INTEGRATION_MANIFEST_SCHEMA_VERSION,
            candidate_id: candidate.id.clone(),
            content_id: candidate.content_id.clone(),
            gate_ids,
            proof_root: root.root,
            envelope,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// Recompute the binding from independently admitted inputs on read.
    ///
    /// # Errors
    ///
    /// `BINDING_MISMATCH` when a stored field differs from the recomputation.
    pub fn verify(
        &self,
        candidate: &Candidate,
        root: &ProofRoot,
        expected_gate_ids: &[GateId],
        expected_envelope: &ExecutionEnvelope,
    ) -> Result<(), IntegrationError> {
        let expected = Self::bind(
            candidate,
            root,
            expected_gate_ids.to_vec(),
            expected_envelope.clone(),
        )?;
        if *self != expected {
            return Err(IntegrationError::BindingMismatch);
        }
        Ok(())
    }

    /// Validate schema, gate set, and envelope.
    ///
    /// # Errors
    ///
    /// Typed refusal.
    pub fn validate(&self) -> Result<(), IntegrationError> {
        require_schema(self.schema_version)?;
        validate_gate_ids(&self.gate_ids)?;
        self.envelope.validate()
    }

    /// Canonical binding identity.
    ///
    /// # Errors
    ///
    /// Typed refusal or `CANONICAL_JSON_FAILED`.
    pub fn binding_id(&self) -> Result<BindingId, IntegrationError> {
        self.validate()?;
        Ok(BindingId::from_digest(hash_canonical(
            "candidate.binding",
            self,
        )?))
    }
}

/// First-class integration subject (`git_role.md` §9).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationManifest {
    /// Must equal [`INTEGRATION_MANIFEST_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Full target ref name, for example `refs/heads/main`.
    pub target_ref: String,
    /// Exact target commit read back from the repository.
    pub target_sha: GitOid,
    /// Candidates in landing order. Order is identity.
    pub candidate_ids: Vec<CandidateId>,
    /// Proof-carrying Candidate bindings in the same landing order.
    pub binding_ids: Vec<BindingId>,
    /// Composed merge-group head, when the forge discloses one.
    pub merge_group_sha: Option<GitOid>,
    /// Combined proof requirement; see [`combined_proof_root`].
    pub proof_root: Digest,
    /// Policy snapshot governing the landing.
    pub policy_snapshot_id: ContentId,
}

impl IntegrationManifest {
    /// Validate semantic invariants.
    ///
    /// # Errors
    ///
    /// Typed refusal for schema, target ref, candidate set, or merge group.
    pub fn validate(&self) -> Result<(), IntegrationError> {
        require_schema(self.schema_version)?;
        validate_target_ref(&self.target_ref)?;
        if self.candidate_ids.is_empty() {
            return Err(IntegrationError::EmptyCandidateSet);
        }
        if self.candidate_ids.len() > MAX_INTEGRATION_CANDIDATES {
            return Err(IntegrationError::CandidateSetTooLarge(
                self.candidate_ids.len(),
            ));
        }
        let mut seen = BTreeSet::new();
        for id in &self.candidate_ids {
            if !seen.insert(id) {
                return Err(IntegrationError::DuplicateCandidate(id.to_string()));
            }
        }
        if self.binding_ids.len() != self.candidate_ids.len() {
            return Err(IntegrationError::BindingSetMismatch(
                "binding count differs from the candidate set",
            ));
        }
        let mut seen = BTreeSet::new();
        for id in &self.binding_ids {
            if !seen.insert(id) {
                return Err(IntegrationError::DuplicateBinding(id.to_string()));
            }
        }
        if self.merge_group_sha.as_ref() == Some(&self.target_sha) {
            return Err(IntegrationError::MergeGroupEqualsTarget);
        }
        Ok(())
    }

    /// Canonical integration identity.
    ///
    /// # Errors
    ///
    /// Typed refusal or `CANONICAL_JSON_FAILED`.
    pub fn integration_id(&self) -> Result<IntegrationId, IntegrationError> {
        self.validate()?;
        Ok(IntegrationId::from_digest(hash_canonical(
            "integration.manifest",
            self,
        )?))
    }

    /// Refuse unless `proof_root` is exactly [`combined_proof_root`] of the
    /// supplied Candidate roots in this manifest's candidate order.
    ///
    /// # Errors
    ///
    /// `PROOF_ROOT_NOT_DERIVED` when a root is missing, unlisted, out of
    /// order, or the digest was not derived from the roots.
    pub fn verify_proof_root(&self, candidate_roots: &[ProofRoot]) -> Result<(), IntegrationError> {
        self.validate()?;
        if candidate_roots.len() != self.candidate_ids.len() {
            return Err(IntegrationError::ProofRootNotDerived(
                "candidate root count differs from the candidate set",
            ));
        }
        for (expected, root) in self.candidate_ids.iter().zip(candidate_roots) {
            if root.candidate != *expected {
                return Err(IntegrationError::ProofRootNotDerived(
                    "candidate roots do not follow the ordered candidate set",
                ));
            }
        }
        if combined_proof_root(candidate_roots) != self.proof_root {
            return Err(IntegrationError::ProofRootNotDerived(
                "proof_root is not the combined root of the candidate roots",
            ));
        }
        Ok(())
    }

    /// Verify ordered roots and independently checked binding identities.
    /// # Errors
    /// Typed refusal for any binding, set, or subject mismatch.
    pub fn verify_bindings(
        &self,
        candidate_roots: &[ProofRoot],
        candidate_checks: &[CandidateBindingCheck<'_>],
    ) -> Result<(), IntegrationError> {
        self.verify_proof_root(candidate_roots)?;
        if candidate_checks.len() != self.binding_ids.len() {
            return Err(IntegrationError::BindingSetMismatch(
                "supplied binding count differs from the manifest",
            ));
        }
        for ((candidate_id, root), (binding_id, check)) in self
            .candidate_ids
            .iter()
            .zip(candidate_roots)
            .zip(self.binding_ids.iter().zip(candidate_checks))
        {
            if check.proof_root != root {
                return Err(IntegrationError::BindingSetMismatch(
                    "checked proof root differs from the ordered Candidate root",
                ));
            }
            check.verify()?;
            let binding = check.binding;
            if binding.candidate_id != *candidate_id || binding.proof_root != root.root {
                return Err(IntegrationError::BindingSetMismatch(
                    "binding does not name the corresponding Candidate proof root",
                ));
            }
            if binding.binding_id()? != *binding_id {
                return Err(IntegrationError::BindingSetMismatch(
                    "binding identity differs from the ordered manifest identity",
                ));
            }
        }
        Ok(())
    }
}

/// Integration refusal with stable reason codes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum IntegrationError {
    /// Unsupported schema.
    #[error("integration schema {0} is unsupported")]
    UnsupportedSchema(u32),
    /// Candidate-side refusal, with its own stable code.
    #[error(transparent)]
    Candidate(#[from] CandidateManifestError),
    /// Stored proof root names a different Candidate.
    #[error("proof root subject is not the bound Candidate")]
    ProofRootSubjectMismatch,
    /// Envelope digest differs from the manifest digest of the same name.
    #[error("execution envelope {0} differs from the Candidate manifest")]
    EnvelopeMismatch(&'static str),
    /// Provider version is empty, oversized, or not printable ASCII.
    #[error("provider version must be 1..=128 printable ASCII bytes")]
    InvalidProviderVersion,
    /// A binding must name at least one gate.
    #[error("gate set must not be empty")]
    EmptyGateSet,
    /// Gate ids must be strictly ascending.
    #[error("gate ids must be strictly ascending and unique")]
    GateIdsNotAscending,
    /// Gate set exceeds the bound.
    #[error("gate set of {0} exceeds the bound")]
    GateSetTooLarge(usize),
    /// Stored binding differs from the recomputation.
    #[error("stored Candidate binding does not match the recomputed binding")]
    BindingMismatch,
    /// Target ref is not a well-formed full ref name.
    #[error("target ref {0:?} is not a well-formed full ref name")]
    InvalidTargetRef(String),
    /// Candidate set is empty.
    #[error("integration candidate set must not be empty")]
    EmptyCandidateSet,
    /// Candidate set exceeds the bound.
    #[error("integration candidate set of {0} exceeds the bound")]
    CandidateSetTooLarge(usize),
    /// A Candidate appears twice.
    #[error("candidate {0} appears more than once")]
    DuplicateCandidate(String),
    /// Candidate and binding sets are not an ordered one-to-one match.
    #[error("integration binding set does not match: {0}")]
    BindingSetMismatch(&'static str),
    /// A Candidate binding appears twice.
    #[error("binding {0} appears more than once")]
    DuplicateBinding(String),
    /// Merge-group head cannot be the untouched target.
    #[error("merge-group head equals the target SHA")]
    MergeGroupEqualsTarget,
    /// Manifest proof root was not derived from the ordered Candidate roots.
    #[error("integration proof_root is not derived from the candidate roots: {0}")]
    ProofRootNotDerived(&'static str),
    /// Recomputed integration root differs.
    #[error("integration root does not match the subject and inputs")]
    IntegrationRootMismatch,
}

impl IntegrationError {
    /// Stable machine-readable refusal code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::UnsupportedSchema(_) => "UNSUPPORTED_SCHEMA",
            Self::Candidate(inner) => inner.reason_code(),
            Self::ProofRootSubjectMismatch => "PROOF_ROOT_SUBJECT_MISMATCH",
            Self::EnvelopeMismatch(_) => "ENVELOPE_MISMATCH",
            Self::InvalidProviderVersion => "INVALID_PROVIDER_VERSION",
            Self::EmptyGateSet => "EMPTY_GATE_SET",
            Self::GateIdsNotAscending => "GATE_IDS_NOT_ASCENDING",
            Self::GateSetTooLarge(_) => "GATE_SET_TOO_LARGE",
            Self::BindingMismatch => "BINDING_MISMATCH",
            Self::InvalidTargetRef(_) => "INVALID_TARGET_REF",
            Self::EmptyCandidateSet => "EMPTY_CANDIDATE_SET",
            Self::CandidateSetTooLarge(_) => "CANDIDATE_SET_TOO_LARGE",
            Self::DuplicateCandidate(_) => "DUPLICATE_CANDIDATE_ID",
            Self::BindingSetMismatch(_) => "BINDING_SET_MISMATCH",
            Self::DuplicateBinding(_) => "DUPLICATE_BINDING_ID",
            Self::MergeGroupEqualsTarget => "MERGE_GROUP_EQUALS_TARGET",
            Self::ProofRootNotDerived(_) => "PROOF_ROOT_NOT_DERIVED",
            Self::IntegrationRootMismatch => "INTEGRATION_ROOT_MISMATCH",
        }
    }
}

fn require_schema(schema_version: u32) -> Result<(), IntegrationError> {
    if schema_version != INTEGRATION_MANIFEST_SCHEMA_VERSION {
        return Err(IntegrationError::UnsupportedSchema(schema_version));
    }
    Ok(())
}

fn validate_gate_ids(gate_ids: &[GateId]) -> Result<(), IntegrationError> {
    if gate_ids.is_empty() {
        return Err(IntegrationError::EmptyGateSet);
    }
    if gate_ids.len() > MAX_BOUND_GATE_IDS {
        return Err(IntegrationError::GateSetTooLarge(gate_ids.len()));
    }
    if gate_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(IntegrationError::GateIdsNotAscending);
    }
    Ok(())
}

/// Subset of `git check-ref-format` for a full ref name.
fn validate_target_ref(target_ref: &str) -> Result<(), IntegrationError> {
    const FORBIDDEN: &[u8] = b"~^:?*[\\";
    let malformed = target_ref.len() > MAX_TARGET_REF_BYTES
        || !target_ref.starts_with("refs/")
        || target_ref.ends_with('/')
        || target_ref.ends_with('.')
        || target_ref.ends_with(".lock")
        || ["..", "//", "/.", "@{"]
            .iter()
            .any(|needle| target_ref.contains(needle))
        || target_ref
            .bytes()
            .any(|byte| !byte.is_ascii_graphic() || FORBIDDEN.contains(&byte));
    if malformed {
        return Err(IntegrationError::InvalidTargetRef(target_ref.to_string()));
    }
    Ok(())
}
