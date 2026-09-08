//! Line-delimited JSON protocol: one request object per line, one response
//! object per line. Documented in `docs/architecture.md`.

use bullet_git_types::{
    schema_bundle::SignedCandidatePreparationGrantV1, AuthorityEnvelope, Candidate,
    CandidateProvenance, Change, PatchProposal, ProofRoot, MAX_AGGREGATE_CONTENT_BYTES,
};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use std::io::BufRead;
use thiserror::Error;

/// Bytes reserved around the content of one request: the envelope (`id`,
/// `method`, `token`, keys) plus 128 operations of at most 4 KiB path, a
/// preimage digest, and mutation framing — well under 1 MiB in total.
pub const FRAME_ENVELOPE_BYTES: usize = 1_048_576;

/// Maximum bytes in one JSONL request, excluding the newline delimiter.
///
/// Derived from the shared proposal bound rather than chosen independently,
/// so the daemon never admits less than `PatchProposal::validate` and
/// `validate_batch` document: the 32 MiB aggregate is measured on decoded
/// bytes, and both wire encodings expand it at most twofold for text —
/// `apply_change` carries `contents_hex` (exactly 2x) and `apply_proposal`
/// carries JSON-escaped `content_utf8` (2x when every byte is a quote,
/// backslash, tab, or newline). Bodies dominated by other control characters
/// escape sixfold and are refused at the frame with `FRAME_TOO_LARGE`; that
/// is the one documented case where the transport is stricter than the
/// types, and it fails closed.
pub const MAX_FRAME_BYTES: usize = 2 * MAX_AGGREGATE_CONTENT_BYTES + FRAME_ENVELOPE_BYTES;

/// Bounded JSONL frame-read failure.
#[derive(Debug, Error)]
pub enum FrameReadError {
    /// Reading stdin failed.
    #[error("read protocol frame: {0}")]
    Io(String),
    /// A frame crossed the fixed input bound.
    #[error("protocol frame exceeds {MAX_FRAME_BYTES} bytes")]
    TooLarge,
    /// JSONL protocol input must be UTF-8.
    #[error("protocol frame is not valid UTF-8")]
    InvalidUtf8,
}

impl FrameReadError {
    /// Stable protocol reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Io(_) => "PROTOCOL_IO_FAILED",
            Self::TooLarge => "FRAME_TOO_LARGE",
            Self::InvalidUtf8 => "INVALID_UTF8",
        }
    }
}

/// Read one bounded JSONL frame without allowing unbounded `read_line` growth.
pub fn read_frame(reader: &mut impl BufRead) -> Result<Option<String>, FrameReadError> {
    let mut bytes = Vec::new();
    loop {
        let available = reader
            .fill_buf()
            .map_err(|error| FrameReadError::Io(error.to_string()))?;
        if available.is_empty() {
            if bytes.is_empty() {
                return Ok(None);
            }
            break;
        }
        let newline = available.iter().position(|byte| *byte == b'\n');
        let payload_len = newline.unwrap_or(available.len());
        let next_len = bytes
            .len()
            .checked_add(payload_len)
            .ok_or(FrameReadError::TooLarge)?;
        if next_len > MAX_FRAME_BYTES {
            return Err(FrameReadError::TooLarge);
        }
        bytes.extend_from_slice(&available[..payload_len]);
        let consumed = payload_len + usize::from(newline.is_some());
        reader.consume(consumed);
        if newline.is_some() {
            break;
        }
    }
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| FrameReadError::InvalidUtf8)
}

/// One request:
/// `{"id": <any>, "method": <name>, "token": <AuthorityToken JSON>, "params": {...}}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    /// Correlation id, echoed back verbatim.
    pub id: Value,
    /// clone | read_tree | apply_change | apply_proposal | checkpoint |
    /// prepare_candidate | bind_proof | verify_proof_root | preserve | cleanup.
    pub method: String,
    /// AuthorityToken JSON object. A string is treated as raw token bytes;
    /// null or absent as an empty token. Both fail verification.
    #[serde(default)]
    pub token: Value,
    /// Method parameters.
    #[serde(default)]
    pub params: Value,
}

/// Convert the request token field into an opaque envelope.
#[must_use]
pub fn envelope(token: &Value) -> AuthorityEnvelope {
    let bytes = match token {
        Value::Null => Vec::new(),
        Value::String(text) => text.clone().into_bytes(),
        other => serde_json::to_vec(other).unwrap_or_default(),
    };
    AuthorityEnvelope { token: bytes }
}

/// Success response line: `{"id": ..., "ok": <result>}`.
#[must_use]
pub fn ok_line(id: &Value, result: &Value) -> String {
    json!({"id": id, "ok": result}).to_string()
}

/// Error response line: `{"id": ..., "err": {"code", "message"}}`.
#[must_use]
pub fn err_line(id: &Value, code: &str, message: &str) -> String {
    json!({"id": id, "err": {"code": code, "message": message}}).to_string()
}

/// `clone` parameters. Variant, attempt, and nonce come from the token, never
/// from the params.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloneParams {
    /// Source repository path (the mirror).
    pub source_repo: String,
    /// Exact algorithm-tagged base commit.
    pub base_sha: String,
    /// Root under which `work/` and `runtime/` live.
    pub root: String,
    /// RFC 3339 creation timestamp from the caller's clock.
    pub created_at: String,
    /// Scope grant: normalized relative path prefixes.
    pub allowed_prefixes: Vec<String>,
    /// Fixed commit date for the controlled identity.
    pub commit_date: String,
}

/// One patch in `apply_change`.
///
/// `op` selects the operation: `write` (the default when absent) replaces
/// the full file contents from `contents_hex`; `delete` removes the file and
/// must not carry `contents_hex`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchParam {
    /// Repository-relative path.
    pub path: String,
    /// `write` (default) or `delete`.
    #[serde(default)]
    pub op: Option<String>,
    /// Hex encoding of the replacement bytes (write only).
    #[serde(default)]
    pub contents_hex: Option<String>,
}

/// `apply_change` parameters.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyParams {
    /// Patches applied all-or-nothing.
    pub patches: Vec<PatchParam>,
}

/// `apply_proposal` parameters. The nested proposal is the canonical typed
/// write subject; model commentary and legacy flattened patches are refused.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApplyProposalParams {
    /// Exact schema-1 proposal.
    pub proposal: PatchProposal,
}

/// `prepare_candidate` parameters.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareParams {
    /// Kernel-issued carrier. BulletGit admits only its closed generated shape;
    /// the raw params remain unchanged for Kernel final authentication.
    pub candidate_preparation_grant: SignedCandidatePreparationGrantV1,
    /// Exact logical Change. Narrative fields are commit inputs, never direct
    /// Candidate provenance fields.
    pub change: Change,
    /// Strict nonlocal provenance. Repository-derived fields are computed by
    /// BulletGit and cannot be supplied here.
    pub provenance: CandidateProvenance,
}

fn nonempty_proof_input<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value.is_empty() {
        return Err(serde::de::Error::custom("proof input must not be empty"));
    }
    Ok(value)
}

/// Eight mandatory caller-supplied ProofRoot leaves.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofInputParams {
    /// Scope grant and actual write set.
    #[serde(deserialize_with = "nonempty_proof_input")]
    pub scope_and_write_set: String,
    /// Runner and sandbox attestation.
    #[serde(deserialize_with = "nonempty_proof_input")]
    pub runner_and_sandbox: String,
    /// Toolchain and dependency manifests.
    #[serde(deserialize_with = "nonempty_proof_input")]
    pub toolchain_and_deps: String,
    /// Deterministic Evidence.
    #[serde(deserialize_with = "nonempty_proof_input")]
    pub evidence: String,
    /// Independent verifier Evidence.
    #[serde(deserialize_with = "nonempty_proof_input")]
    pub verifier_evidence: String,
    /// Reviews and independence calculation.
    #[serde(deserialize_with = "nonempty_proof_input")]
    pub reviews: String,
    /// Policy decision.
    #[serde(deserialize_with = "nonempty_proof_input")]
    pub policy: String,
    /// Human approvals and Effect receipts.
    #[serde(deserialize_with = "nonempty_proof_input")]
    pub approvals_and_effect_receipts: String,
}

/// `bind_proof` parameters. Pure function over an exact Candidate.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindProofParams {
    /// Exact Candidate identity subject.
    pub candidate: Candidate,
    /// Complete nonempty eight-leaf proof subject.
    pub inputs: ProofInputParams,
}

/// `verify_proof_root` parameters. Recomputes on read.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifyProofParams {
    /// Previously bound root.
    pub root: ProofRoot,
    /// Exact Candidate identity subject.
    pub candidate: Candidate,
    /// The complete nonempty eight leaves that must recompute to `root`.
    pub inputs: ProofInputParams,
}

/// `preserve` parameters.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreserveParams {
    /// New absolute canonical directory outside workspace-owned paths.
    pub destination: String,
}

/// `cleanup` parameters.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupParams {
    /// Opaque sealed token returned by `preserve`.
    pub preservation_receipt: String,
    /// RFC 3339 deletion timestamp from the caller's clock.
    pub deleted_at: String,
}

#[cfg(test)]
#[path = "protocol_tests.rs"]
mod tests;
