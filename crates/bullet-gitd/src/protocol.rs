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
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn frame_reader_is_bounded_and_keeps_frame_boundaries() {
        let mut input = Cursor::new(b"one\ntwo\n".to_vec());
        assert_eq!(read_frame(&mut input).unwrap().as_deref(), Some("one"));
        assert_eq!(read_frame(&mut input).unwrap().as_deref(), Some("two"));
        assert!(read_frame(&mut input).unwrap().is_none());

        let mut oversized = Cursor::new(vec![b'x'; MAX_FRAME_BYTES + 1]);
        let error = read_frame(&mut oversized).expect_err("oversized refused");
        assert_eq!(error.reason_code(), "FRAME_TOO_LARGE");

        let mut invalid = Cursor::new(vec![0xff, b'\n']);
        let error = read_frame(&mut invalid).expect_err("invalid UTF-8 refused");
        assert_eq!(error.reason_code(), "INVALID_UTF8");
    }

    use bullet_git_types::{MAX_CONTENT_BYTES, MAX_PATCH_OPERATIONS};

    /// A 4 KiB path (the `RepoPath` maximum) with a distinct top segment so
    /// no operation contains another.
    fn long_path(index: usize) -> String {
        let head = format!("d{index:03}/");
        format!("{head}{}", "p".repeat(4_096 - head.len()))
    }

    /// The largest request the shared bounds admit: every operation slot
    /// used at the path maximum, and the full 32 MiB aggregate spread over
    /// 32 maximal write bodies made of `fill`; the remaining slots delete.
    fn maximal_proposal(fill: char) -> Value {
        let body: String = std::iter::repeat_n(fill, MAX_CONTENT_BYTES).collect();
        let writes = MAX_AGGREGATE_CONTENT_BYTES / MAX_CONTENT_BYTES;
        let operations: Vec<Value> = (0..MAX_PATCH_OPERATIONS)
            .map(|index| {
                if index < writes {
                    json!({
                        "path": long_path(index),
                        "preimage": {"kind": "absent"},
                        "mutation": {"kind": "write", "content_utf8": body},
                    })
                } else {
                    json!({
                        "path": long_path(index),
                        "preimage": {"kind": "digest", "digest": "7".repeat(64)},
                        "mutation": {"kind": "delete"},
                    })
                }
            })
            .collect();
        json!({
            "schema_version": 1,
            "proposal_id": format!("cnt_{}", "1".repeat(64)),
            "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
            "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
            "base_checkpoint_digest": "4".repeat(64),
            "operations": operations,
            "gate_ids": [format!("gat_{}", "5".repeat(64))],
        })
    }

    fn request_line(method: &str, params: Value) -> String {
        json!({
            "id": 1,
            "method": method,
            "token": {"attempt_id": format!("atm_{}", "2".repeat(64)), "attempt_fence": 7},
            "params": params,
        })
        .to_string()
    }

    fn framed(line: &str) -> Request {
        let mut input = Cursor::new(format!("{line}\n").into_bytes());
        let frame = read_frame(&mut input)
            .expect("frame within bound")
            .expect("one frame");
        serde_json::from_str(&frame).expect("request decodes")
    }

    #[test]
    fn frame_bound_is_derived_from_the_shared_aggregate_bound() {
        assert_eq!(MAX_AGGREGATE_CONTENT_BYTES, 32 * 1_048_576);
        assert_eq!(MAX_FRAME_BYTES, 65 * 1_048_576);

        let mut exact = Cursor::new([vec![b'x'; MAX_FRAME_BYTES], vec![b'\n']].concat());
        let frame = read_frame(&mut exact).expect("exact bound admitted");
        assert_eq!(frame.map(|text| text.len()), Some(MAX_FRAME_BYTES));

        let mut over = Cursor::new([vec![b'x'; MAX_FRAME_BYTES + 1], vec![b'\n']].concat());
        let error = read_frame(&mut over).expect_err("one byte over refused");
        assert_eq!(error.reason_code(), "FRAME_TOO_LARGE");
    }

    #[test]
    fn maximal_apply_proposal_crosses_the_frame_and_one_byte_more_is_refused() {
        // Printable bodies: the aggregate crosses the frame with room to spare.
        let plain = request_line("apply_proposal", json!({"proposal": maximal_proposal('x')}));
        assert!(plain.len() <= MAX_FRAME_BYTES, "{} bytes", plain.len());
        let request = framed(&plain);
        assert_eq!(request.method, "apply_proposal");
        let params: ApplyProposalParams =
            serde_json::from_value(request.params).expect("maximal proposal decodes");
        params
            .proposal
            .validate()
            .expect("exactly the aggregate is admitted");
        let aggregate: usize = params
            .proposal
            .operations
            .iter()
            .filter_map(|operation| match &operation.mutation {
                bullet_git_types::PatchMutation::Write { content_utf8 } => Some(content_utf8.len()),
                bullet_git_types::PatchMutation::Delete => None,
            })
            .sum();
        assert_eq!(aggregate, MAX_AGGREGATE_CONTENT_BYTES);

        // Worst two-byte escaping: every content byte is a quote.
        let escaped = request_line("apply_proposal", json!({"proposal": maximal_proposal('"')}));
        assert!(
            escaped.len() > 2 * MAX_AGGREGATE_CONTENT_BYTES,
            "{} bytes",
            escaped.len()
        );
        assert!(escaped.len() <= MAX_FRAME_BYTES, "{} bytes", escaped.len());
        framed(&escaped);

        // One content byte over the aggregate: framed, then typed refusal.
        let mut over = maximal_proposal('x');
        over["operations"][MAX_PATCH_OPERATIONS - 1] = json!({
            "path": long_path(MAX_PATCH_OPERATIONS - 1),
            "preimage": {"kind": "absent"},
            "mutation": {"kind": "write", "content_utf8": "y"},
        });
        let line = request_line("apply_proposal", json!({"proposal": over}));
        assert!(line.len() <= MAX_FRAME_BYTES);
        let params: ApplyProposalParams =
            serde_json::from_value(framed(&line).params).expect("decodes");
        let error = params
            .proposal
            .validate()
            .expect_err("aggregate + 1 refused");
        assert_eq!(error.reason_code(), "AGGREGATE_CONTENT_TOO_LARGE");
    }

    #[test]
    fn maximal_hex_apply_change_crosses_the_frame() {
        let body = "ab".repeat(MAX_CONTENT_BYTES);
        let writes = MAX_AGGREGATE_CONTENT_BYTES / MAX_CONTENT_BYTES;
        let patches: Vec<Value> = (0..MAX_PATCH_OPERATIONS)
            .map(|index| {
                if index < writes {
                    json!({"path": long_path(index), "contents_hex": body})
                } else {
                    json!({"path": long_path(index), "op": "delete"})
                }
            })
            .collect();
        let line = request_line("apply_change", json!({"patches": patches}));
        assert!(line.len() > 2 * MAX_AGGREGATE_CONTENT_BYTES);
        assert!(line.len() <= MAX_FRAME_BYTES, "{} bytes", line.len());
        let params: ApplyParams = serde_json::from_value(framed(&line).params).expect("decodes");
        assert_eq!(params.patches.len(), MAX_PATCH_OPERATIONS);
        let decoded: usize = params
            .patches
            .iter()
            .filter_map(|patch| patch.contents_hex.as_ref())
            .map(|hex_text| hex_text.len() / 2)
            .sum();
        assert_eq!(decoded, MAX_AGGREGATE_CONTENT_BYTES);
    }

    #[test]
    fn apply_proposal_params_deny_legacy_and_model_fields() {
        let proposal = json!({
            "schema_version": 1,
            "proposal_id": format!("cnt_{}", "1".repeat(64)),
            "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
            "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
            "base_checkpoint_digest": "4".repeat(64),
            "operations": [{
                "path": "src/lib.rs",
                "preimage": {"kind": "absent"},
                "mutation": {"kind": "write", "content_utf8": "next"}
            }],
            "gate_ids": [format!("gat_{}", "5".repeat(64))]
        });
        let decoded: ApplyProposalParams =
            serde_json::from_value(json!({"proposal": proposal.clone()})).expect("canonical");
        decoded.proposal.validate().expect("semantic validation");

        let mut proposal_with_comment = proposal.clone();
        proposal_with_comment["intent_summary"] = json!("model text");
        for bad in [
            json!({"proposal": proposal.clone(), "patches": []}),
            json!({"proposal": proposal_with_comment}),
        ] {
            assert!(
                serde_json::from_value::<ApplyProposalParams>(bad).is_err(),
                "non-canonical params accepted"
            );
        }
    }
}
