//! Proof-carrying Candidate binding.

use super::*;

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
