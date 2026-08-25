//! Line-delimited JSON protocol: one request object per line, one response
//! object per line. Documented in `docs/architecture.md`.

use bullet_git_types::AuthorityEnvelope;
use serde::Deserialize;
use serde_json::{json, Value};
use std::io::BufRead;
use thiserror::Error;

/// Maximum bytes in one JSONL request, excluding the newline delimiter.
pub const MAX_FRAME_BYTES: usize = 4 * 1_048_576;

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
    /// clone | read_tree | apply_change | checkpoint | prepare_candidate | preserve | cleanup.
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

/// `prepare_candidate` parameters.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrepareParams {
    /// Seed for the stable ChangeId.
    pub change_seed: String,
    /// Mission text; its digest becomes the acceptance root.
    pub mission: String,
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
}
