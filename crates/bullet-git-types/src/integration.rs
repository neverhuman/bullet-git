//! Proof-carrying Candidate binding and first-class Integration subject
//! (`git_role.md` §6, §9, §13). The Hub schema-1 `CandidateManifest` mirror
//! in `change.rs` stays byte-exact so its cross-language golden holds; gate
//! set, proof root, and execution envelope bind here in a sibling identity.

#[path = "integration_binding.rs"]
mod binding;
mod root;
pub use binding::CandidateBinding;
#[path = "integration_error.rs"]
mod error;
pub use error::IntegrationError;
use error::{require_schema, validate_gate_ids, validate_target_ref};

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
