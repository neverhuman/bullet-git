use super::GatewayError;
use crate::mutation_ledger::{MutationOperation, MutationOutcome, MutationSubject};
use bullet_git_types::{framed_digest, Digest};
use serde_json::Value;

pub(super) fn settlement_fingerprint(
    subject: &MutationSubject,
    outcome: MutationOutcome,
    result_digest: &str,
    completed_at_unix_ms: u64,
) -> Digest {
    let workspace_generation = subject.workspace_generation.to_string();
    let attempt_fence = subject.attempt_fence.to_string();
    let authority_epoch = subject.authority_epoch.to_string();
    let freeze_generation = subject.freeze_generation.to_string();
    let completed_at = completed_at_unix_ms.to_string();
    let outcome = match outcome {
        MutationOutcome::Committed => b"committed".as_slice(),
        MutationOutcome::Aborted => b"aborted".as_slice(),
        MutationOutcome::Unknown => b"unknown".as_slice(),
    };
    framed_digest(&[
        b"bullet-gitd.pre-contract-settlement-fingerprint.v1",
        subject.authority_envelope_digest.as_bytes(),
        subject.authority_token_nonce.as_bytes(),
        subject.mutation_id.as_bytes(),
        subject.reservation_id.as_bytes(),
        subject.operation.as_str().as_bytes(),
        subject.request_digest.as_bytes(),
        subject.repository_id.as_bytes(),
        subject.workspace_id.as_bytes(),
        workspace_generation.as_bytes(),
        subject.workspace_nonce.as_bytes(),
        subject.attempt_id.as_bytes(),
        attempt_fence.as_bytes(),
        authority_epoch.as_bytes(),
        freeze_generation.as_bytes(),
        subject.permit_nonce.as_bytes(),
        subject.permit_digest.as_bytes(),
        outcome,
        result_digest.as_bytes(),
        completed_at.as_bytes(),
    ])
}

pub(super) fn transport_fingerprint(
    operation: MutationOperation,
    authority: &Value,
    params: &Value,
) -> Result<Digest, GatewayError> {
    let authority = serde_json::to_vec(authority)
        .map_err(|error| GatewayError::Refused(format!("encode authority: {error}")))?;
    let params = serde_json::to_vec(params)
        .map_err(|error| GatewayError::Refused(format!("encode parameters: {error}")))?;
    Ok(framed_digest(&[
        b"bullet-gitd.pre-contract-request-fingerprint.v1",
        operation.as_str().as_bytes(),
        &authority,
        &params,
    ]))
}
