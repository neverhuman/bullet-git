//! Change and Candidate identities. A ChangeId never authorizes integration.

mod authority;
mod change;
mod ids;
mod integration;
mod lineage;
mod proposal;
pub mod schema_bundle;

pub use authority::{AuthorityEnvelope, AuthorityError, WireAuthorityToken};
pub use change::{
    verify_proof_root, write_set_within_grant, Candidate, CandidateManifest,
    CandidateManifestError, CandidateProvenance, Change, EvolutionEdge, EvolutionKind, ProofInputs,
    ProofRoot, ProofRootError, CANDIDATE_MANIFEST_SCHEMA_VERSION,
};
pub use ids::{
    AttemptId, CandidateId, ChangeId, CheckpointId, ContentId, GateId, GitOid, GitOidAlgorithm,
    GraphRevisionId, PlanRevisionId, RepositoryId, VariantId, WorkPackageId,
};
pub use integration::{
    combined_proof_root, BindingId, CandidateBinding, CandidateBindingCheck, ExecutionEnvelope,
    IntegrationError, IntegrationId, IntegrationInputs, IntegrationManifest, IntegrationRoot,
    INTEGRATION_MANIFEST_SCHEMA_VERSION, MAX_BOUND_GATE_IDS, MAX_INTEGRATION_CANDIDATES,
    MAX_PROVIDER_VERSION_BYTES, MAX_TARGET_REF_BYTES,
};
pub use lineage::{ChangeEvolution, LineageError, LineageGraph};
pub use proposal::{
    PatchMutation, PatchOperation, PatchProposal, Preimage, ProposalError, RepoPath,
    MAX_AGGREGATE_CONTENT_BYTES, MAX_CONTENT_BYTES, MAX_PATCH_OPERATIONS,
    PATCH_PROPOSAL_SCHEMA_VERSION,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Typed identity/encoding error with stable reason codes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum TypesError {
    /// An identifier was missing its prefix or full 64-hex body.
    #[error("invalid id: {0}")]
    InvalidId(String),
    /// A Git object id was not a supported algorithm-tagged lowercase value.
    #[error("invalid git oid: {0}")]
    InvalidOid(String),
    /// A hex digest failed to decode into 32 bytes.
    #[error("invalid digest encoding: {0}")]
    Encoding(String),
}

impl TypesError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidId(_) => "INVALID_ID",
            Self::InvalidOid(_) => "INVALID_OID",
            Self::Encoding(_) => "ENCODING",
        }
    }
}

/// Digest of a proof-carrying object. Serializes as a 64-char hex string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Digest(#[serde(with = "hex_bytes")] [u8; 32]);

impl Digest {
    /// Construct a digest from exact BLAKE3 bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

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

    /// Raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parse a 64-character hex digest.
    ///
    /// # Errors
    ///
    /// Returns `TypesError::Encoding` when the text is not 32 bytes of hex.
    pub fn from_hex(text: &str) -> Result<Self, TypesError> {
        if text.len() != 64
            || !text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(TypesError::Encoding(
                "digest must be 64 lowercase hexadecimal characters".into(),
            ));
        }
        let raw = hex::decode(text).map_err(|err| TypesError::Encoding(err.to_string()))?;
        let bytes: [u8; 32] = raw
            .try_into()
            .map_err(|_| TypesError::Encoding("digest must be 32 bytes".into()))?;
        Ok(Self(bytes))
    }
}

mod hex_bytes {
    use super::Digest;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(de)?;
        Digest::from_hex(&text)
            .map(|digest| *digest.as_bytes())
            .map_err(serde::de::Error::custom)
    }
}

/// Length-prefix framing for multi-field hash preimages: u64 LE length, then bytes.
///
/// Every digest over more than one variable-length field MUST frame each field
/// so that field boundaries are unambiguous (`["ab","c"]` never collides with
/// `["a","bc"]`).
pub fn frame(buf: &mut Vec<u8>, bytes: &[u8]) {
    buf.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buf.extend_from_slice(bytes);
}

/// Digest of a sequence of framed fields.
#[must_use]
pub fn framed_digest(fields: &[&[u8]]) -> Digest {
    let mut buf = Vec::new();
    for field in fields {
        frame(&mut buf, field);
    }
    Digest::of(&buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn framing_disambiguates_field_boundaries() {
        let a = framed_digest(&[b"ab", b"c"]);
        let b = framed_digest(&[b"a", b"bc"]);
        assert_ne!(a, b);
        assert_ne!(framed_digest(&[b"abc"]), framed_digest(&[b"ab", b"c"]));
    }

    #[test]
    fn digest_hex_serde_round_trip() {
        let digest = Digest::of(b"payload");
        let json = serde_json::to_string(&digest).expect("serialize");
        assert_eq!(json, format!("\"{}\"", digest.to_hex()));
        let back: Digest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, digest);
        assert_eq!(Digest::from_hex(&digest.to_hex()).expect("hex"), digest);
    }

    #[test]
    fn digest_from_hex_rejects_bad_input() {
        assert_eq!(
            Digest::from_hex("zz").expect_err("reject").reason_code(),
            "ENCODING"
        );
        assert_eq!(
            Digest::from_hex("ab").expect_err("reject").reason_code(),
            "ENCODING"
        );
        assert_eq!(
            Digest::from_hex(&"A".repeat(64))
                .expect_err("uppercase refused")
                .reason_code(),
            "ENCODING"
        );
        assert!(serde_json::from_str::<Digest>(&format!("\"{}\"", "A".repeat(64))).is_err());
    }
}
