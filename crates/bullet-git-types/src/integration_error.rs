//! Integration refusal codes and shared validators.

use super::*;

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

pub(super) fn require_schema(schema_version: u32) -> Result<(), IntegrationError> {
    if schema_version != INTEGRATION_MANIFEST_SCHEMA_VERSION {
        return Err(IntegrationError::UnsupportedSchema(schema_version));
    }
    Ok(())
}

pub(super) fn validate_gate_ids(gate_ids: &[GateId]) -> Result<(), IntegrationError> {
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
pub(super) fn validate_target_ref(target_ref: &str) -> Result<(), IntegrationError> {
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
