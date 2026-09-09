//! ProofRoot bind and verify over an exact Candidate.

use super::*;
use crate::{frame, framed_digest};
use serde::{Deserialize, Serialize};
use thiserror::Error;

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
