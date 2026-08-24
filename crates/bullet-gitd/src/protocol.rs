//! Line-delimited JSON protocol: one request object per line, one response
//! object per line. Documented in `docs/architecture.md`.

use bullet_git_types::AuthorityEnvelope;
use serde::Deserialize;
use serde_json::{json, Value};

/// One request:
/// `{"id": <any>, "method": <name>, "token": <AuthorityToken JSON>, "params": {...}}`.
#[derive(Debug, Deserialize)]
pub struct Request {
    /// Correlation id, echoed back verbatim.
    pub id: Value,
    /// clone | read_tree | apply_change | checkpoint | prepare_candidate | cleanup.
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
pub struct CloneParams {
    /// Source repository path (the mirror).
    pub source_repo: String,
    /// Exact base commit (40 hex).
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

/// One patch in `apply_change`: full file contents, hex encoded.
#[derive(Debug, Deserialize)]
pub struct PatchParam {
    /// Repository-relative path.
    pub path: String,
    /// Hex encoding of the replacement bytes.
    pub contents_hex: String,
}

/// `apply_change` parameters.
#[derive(Debug, Deserialize)]
pub struct ApplyParams {
    /// Patches applied all-or-nothing.
    pub patches: Vec<PatchParam>,
}

/// `prepare_candidate` parameters.
#[derive(Debug, Deserialize)]
pub struct PrepareParams {
    /// Seed for the stable ChangeId.
    pub change_seed: String,
    /// Mission text; its digest becomes the acceptance root.
    pub mission: String,
}

/// `cleanup` parameters.
#[derive(Debug, Deserialize)]
pub struct CleanupParams {
    /// Where to write the preservation bundle. Required: cleanup without a
    /// preservation receipt is refused.
    #[serde(default)]
    pub bundle_path: Option<String>,
    /// RFC 3339 deletion timestamp from the caller's clock.
    pub deleted_at: String,
}
