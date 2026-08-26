//! Integration root: Merkle binding of integration claims to an exact
//! [`IntegrationManifest`] whose `proof_root` is derived from its Candidate
//! roots. No root is ever minted from a hand-supplied `proof_root`.

use super::{
    CandidateBinding, ExecutionEnvelope, IntegrationError, IntegrationId, IntegrationManifest,
};
use crate::change::{Candidate, ProofRoot};
use crate::ids::{GateId, GitOid};
use crate::{frame, framed_digest, Digest};
use serde::{Deserialize, Serialize};

/// Combined proof requirement over Candidate roots, in landing order. This is
/// the only admitted derivation of [`IntegrationManifest::proof_root`].
#[must_use]
pub fn combined_proof_root(roots: &[ProofRoot]) -> Digest {
    let mut leaves = Vec::new();
    for root in roots {
        frame(&mut leaves, root.candidate.as_str().as_bytes());
        frame(&mut leaves, root.root.as_bytes());
    }
    framed_digest(&[b"integration.proof-requirement.v1", &leaves])
}

/// Four caller-supplied integration leaves (`git_role.md` §9). The default
/// (all empty) still binds the subject.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IntegrationInputs<'a> {
    /// Merge method.
    pub merge_method: &'a [u8],
    /// Conflict resolutions.
    pub conflict_resolutions: &'a [u8],
    /// Integration Evidence for the composed subject.
    pub integration_evidence: &'a [u8],
    /// Human approvals and Effect receipts.
    pub approvals_and_effect_receipts: &'a [u8],
}

impl IntegrationInputs<'_> {
    /// Named leaves in bind order, for tamper tests.
    #[must_use]
    pub const fn named_leaves(&self) -> [(&'static str, &[u8]); 4] {
        [
            ("merge_method", self.merge_method),
            ("conflict_resolutions", self.conflict_resolutions),
            ("integration_evidence", self.integration_evidence),
            (
                "approvals_and_effect_receipts",
                self.approvals_and_effect_receipts,
            ),
        ]
    }
}

/// One Candidate binding plus the independently admitted inputs that must
/// reproduce it before an Integration root can be minted.
#[derive(Clone, Copy, Debug)]
pub struct CandidateBindingCheck<'a> {
    /// Stored proof-carrying binding.
    pub binding: &'a CandidateBinding,
    /// Independently loaded Candidate subject.
    pub candidate: &'a Candidate,
    /// Independently recomputed Candidate proof root.
    pub proof_root: &'a ProofRoot,
    /// Independently admitted required gate set.
    pub expected_gate_ids: &'a [GateId],
    /// Independently admitted execution envelope.
    pub expected_envelope: &'a ExecutionEnvelope,
}

impl CandidateBindingCheck<'_> {
    pub(super) fn verify(&self) -> Result<(), IntegrationError> {
        self.binding.verify(
            self.candidate,
            self.proof_root,
            self.expected_gate_ids,
            self.expected_envelope,
        )
    }
}

/// Merkle binding of integration claims to an exact integration subject.
/// Distinct from [`ProofRoot`] in subject type, field name, and preimage
/// domain; neither validates as the other.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationRoot {
    /// Subject.
    pub subject: IntegrationId,
    /// Bound digest.
    pub root: Digest,
}

impl IntegrationRoot {
    /// Bind the manifest-derived tree plus the four caller leaves, after
    /// proving the ordered Candidate roots and bindings match the manifest.
    ///
    /// # Errors
    ///
    /// Typed manifest refusal, or `PROOF_ROOT_NOT_DERIVED` when the manifest
    /// proof root is not the combined root of the ordered Candidate roots.
    pub fn bind(
        manifest: &IntegrationManifest,
        candidate_roots: &[ProofRoot],
        candidate_checks: &[CandidateBindingCheck<'_>],
        inputs: &IntegrationInputs<'_>,
    ) -> Result<Self, IntegrationError> {
        let subject = manifest.integration_id()?;
        manifest.verify_bindings(candidate_roots, candidate_checks)?;
        let mut candidates = Vec::new();
        for id in &manifest.candidate_ids {
            frame(&mut candidates, id.as_str().as_bytes());
        }
        let mut bindings = Vec::new();
        for id in &manifest.binding_ids {
            frame(&mut bindings, id.as_str().as_bytes());
        }
        let merge_group = manifest.merge_group_sha.as_ref().map_or("", GitOid::as_str);
        let root = framed_digest(&[
            b"integration-root.v1",
            subject.as_str().as_bytes(),
            manifest.target_ref.as_bytes(),
            manifest.target_sha.as_str().as_bytes(),
            &candidates,
            &bindings,
            merge_group.as_bytes(),
            manifest.proof_root.as_bytes(),
            manifest.policy_snapshot_id.as_str().as_bytes(),
            inputs.merge_method,
            inputs.conflict_resolutions,
            inputs.integration_evidence,
            inputs.approvals_and_effect_receipts,
        ]);
        Ok(Self { subject, root })
    }

    /// Recompute the root and refuse on any mismatch.
    ///
    /// # Errors
    ///
    /// `INTEGRATION_ROOT_MISMATCH` when the subject or digest differs; a
    /// typed manifest or `PROOF_ROOT_NOT_DERIVED` refusal when the manifest
    /// itself cannot bind.
    pub fn verify(
        &self,
        manifest: &IntegrationManifest,
        candidate_roots: &[ProofRoot],
        candidate_checks: &[CandidateBindingCheck<'_>],
        inputs: &IntegrationInputs<'_>,
    ) -> Result<(), IntegrationError> {
        if self != &Self::bind(manifest, candidate_roots, candidate_checks, inputs)? {
            return Err(IntegrationError::IntegrationRootMismatch);
        }
        Ok(())
    }
}
