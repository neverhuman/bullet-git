use crate::authority_gateway::GatewayError;
use crate::protocol::{PatchParam, ProofInputParams};
use bullet_git_types::{AuthorityError, CandidateManifestError, ProofInputs};
use bullet_git_workspace::{CapabilityError, PatchHunk, MAX_CONTENT_BYTES};
use serde::de::DeserializeOwned;
use serde_json::Value;

pub(super) type MethodError = (String, String);
pub(super) type MethodResult = Result<Value, MethodError>;

pub(super) fn cap(err: &CapabilityError) -> MethodError {
    (err.reason_code().to_string(), err.to_string())
}

pub(super) fn auth(err: &AuthorityError) -> MethodError {
    (err.reason_code().to_string(), err.to_string())
}

pub(super) fn candidate_manifest(err: &CandidateManifestError) -> MethodError {
    (err.reason_code().to_string(), err.to_string())
}

pub(super) fn gateway(err: &GatewayError) -> MethodError {
    (err.reason_code().to_string(), err.to_string())
}

pub(super) fn not_cloned() -> MethodError {
    ("NOT_CLONED".into(), "clone must be the first call".into())
}

pub(super) fn parse_params<T: DeserializeOwned>(params: &Value) -> Result<T, MethodError> {
    serde_json::from_value(params.clone())
        .map_err(|err| ("BAD_REQUEST".into(), format!("invalid params: {err}")))
}

pub(super) fn proof_inputs(params: &ProofInputParams) -> ProofInputs<'_> {
    ProofInputs {
        scope_and_write_set: params.scope_and_write_set.as_bytes(),
        runner_and_sandbox: params.runner_and_sandbox.as_bytes(),
        toolchain_and_deps: params.toolchain_and_deps.as_bytes(),
        evidence: params.evidence.as_bytes(),
        verifier_evidence: params.verifier_evidence.as_bytes(),
        reviews: params.reviews.as_bytes(),
        policy: params.policy.as_bytes(),
        approvals_and_effect_receipts: params.approvals_and_effect_receipts.as_bytes(),
    }
}

pub(super) fn to_value<T: serde::Serialize>(value: &T) -> MethodResult {
    serde_json::to_value(value).map_err(|err| ("ENCODING".into(), format!("encode result: {err}")))
}

/// Decode one wire patch entry into a typed hunk.
///
/// `op` absent or `write` keeps the v1 shape and requires `contents_hex`;
/// `delete` forbids it. Anything else is `BAD_REQUEST`.
pub(super) fn decode_patch(patch: PatchParam) -> Result<PatchHunk, MethodError> {
    let bad = |message: String| ("BAD_REQUEST".to_string(), message);
    match patch.op.as_deref() {
        None | Some("write") => {
            let Some(hex_text) = patch.contents_hex else {
                return Err(bad(format!(
                    "contents_hex required for write op: {}",
                    patch.path
                )));
            };
            if hex_text.len() > MAX_CONTENT_BYTES.saturating_mul(2) {
                return Err((
                    "CONTENT_TOO_LARGE".into(),
                    format!("{} exceeds {MAX_CONTENT_BYTES} decoded bytes", patch.path),
                ));
            }
            let contents = hex::decode(&hex_text)
                .map_err(|err| bad(format!("contents_hex for {}: {err}", patch.path)))?;
            Ok(PatchHunk::write(patch.path, contents))
        }
        Some("delete") => {
            if patch.contents_hex.is_some() {
                return Err(bad(format!(
                    "delete op must not carry contents_hex: {}",
                    patch.path
                )));
            }
            Ok(PatchHunk::delete(patch.path))
        }
        Some(other) => Err(bad(format!("unknown patch op {other:?}: {}", patch.path))),
    }
}
