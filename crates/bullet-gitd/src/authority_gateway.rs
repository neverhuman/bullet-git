//! Fail-closed boundary between pre-contract daemon requests and frozen authority.
//!
//! The frozen `bullet-wire` runtime crate is not yet available from an
//! immutable permitted source. Production therefore installs only an
//! unavailable checker. Test-only checkers exercise the private one-use
//! permit and durable replay machinery without creating a production bypass.

use crate::mutation_ledger::{
    MutationLedger, MutationLedgerError, MutationOperation, MutationOutcome, MutationSubject,
    ReplayDisposition,
};

#[cfg(feature = "fixture-authority")]
#[path = "fixture_permit.rs"]
mod fixture_permit;

use bullet_git_types::{framed_digest, Digest};
#[cfg(feature = "fixture-authority")]
pub use fixture_permit::{
    consume_fixture_generation, destination_is_fixture_root, mint_fixture_permit,
    parse_fixture_key, require_preopened_fixture_root, verify_fixture_permit, FixturePermit,
    FixturePermitClaims, FixturePermitError,
};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

const MAX_MUTATION_PERMIT_TTL_MS: u64 = 1_000;

/// Exact pre-contract call presented to a future frozen-contract consumer.
struct FinalCheckInput<'a> {
    operation: MutationOperation,
    authority: &'a Value,
    params: &'a Value,
    transport_fingerprint: Digest,
}

/// Result of local PASETO plus Kernel final-check verification.
///
/// Constructors remain private so unverified transport data cannot become a
/// repository permit.
#[derive(Clone)]
struct VerifiedDecision {
    subject: MutationSubject,
    operation: MutationOperation,
    transport_fingerprint: Digest,
    expires_at_unix_ms: u64,
}

/// Exact settlement submitted after the repository call has returned.
struct FinalSettlementInput<'a> {
    subject: &'a MutationSubject,
    outcome: MutationOutcome,
    result_digest: &'a str,
    completed_at_unix_ms: u64,
    settlement_fingerprint: Digest,
}

/// Acknowledgment verified by the future frozen online authority consumer.
#[derive(Clone)]
struct VerifiedSettlement {
    mutation_id: String,
    reservation_id: String,
    result_digest: String,
    settlement_fingerprint: Digest,
}

trait FinalAuthorityCheck: Send {
    fn check(&mut self, input: &FinalCheckInput<'_>) -> Result<VerifiedDecision, GatewayError>;

    fn settle(
        &mut self,
        input: &FinalSettlementInput<'_>,
    ) -> Result<VerifiedSettlement, GatewayError>;
}

struct UnavailableFinalCheck;

impl FinalAuthorityCheck for UnavailableFinalCheck {
    fn check(&mut self, input: &FinalCheckInput<'_>) -> Result<VerifiedDecision, GatewayError> {
        let _ = (
            input.operation,
            input.authority,
            input.params,
            input.transport_fingerprint,
        );
        Err(GatewayError::ContractUnavailable(
            "frozen bullet-wire authority source and Kernel final-check client are unavailable"
                .into(),
        ))
    }

    fn settle(
        &mut self,
        input: &FinalSettlementInput<'_>,
    ) -> Result<VerifiedSettlement, GatewayError> {
        let _ = (
            input.subject,
            input.outcome,
            input.result_digest,
            input.completed_at_unix_ms,
            input.settlement_fingerprint,
        );
        Err(GatewayError::ContractUnavailable(
            "frozen bullet-wire authority source and Kernel settlement client are unavailable"
                .into(),
        ))
    }
}

trait Clock: Send {
    fn now_unix_ms(&self) -> Result<u64, GatewayError>;
}

struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_ms(&self) -> Result<u64, GatewayError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| GatewayError::Clock(error.to_string()))?;
        u64::try_from(duration.as_millis())
            .map_err(|_| GatewayError::Clock("system time exceeds u64 milliseconds".into()))
    }
}

/// Fail-closed gateway error.
#[derive(Debug, Error)]
pub(crate) enum GatewayError {
    #[error("authority contract unavailable: {0}")]
    ContractUnavailable(String),
    #[error("authority final check refused: {0}")]
    Refused(String),
    #[error("verified authority subject mismatch: {0}")]
    SubjectMismatch(String),
    #[error("mutation permit expired")]
    PermitExpired,
    #[error("mutation permit window is invalid")]
    InvalidPermitWindow,
    #[error("trusted clock failed: {0}")]
    Clock(String),
    #[error("mutation outcome is unknown after repository execution: {0}")]
    SettlementUnknown(String),
    #[error(transparent)]
    Ledger(#[from] MutationLedgerError),
}

impl GatewayError {
    #[must_use]
    pub(crate) const fn reason_code(&self) -> &'static str {
        match self {
            Self::ContractUnavailable(_) => "AUTHORITY_CONTRACT_UNAVAILABLE",
            Self::Refused(_) => "AUTHORITY_REFUSED",
            Self::SubjectMismatch(_) => "AUTHORITY_SUBJECT_MISMATCH",
            Self::PermitExpired => "MUTATION_PERMIT_EXPIRED",
            Self::InvalidPermitWindow => "INVALID_MUTATION_PERMIT_WINDOW",
            Self::Clock(_) => "AUTHORITY_CLOCK_FAILED",
            Self::SettlementUnknown(_) => "MUTATION_OUTCOME_UNKNOWN",
            Self::Ledger(error) => error.reason_code(),
        }
    }
}

/// Private, non-cloneable proof that one exact operation was authorized.
pub(crate) struct MutationPermit {
    subject: MutationSubject,
    operation: MutationOperation,
    transport_fingerprint: Digest,
    expires_at_unix_ms: u64,
}

impl MutationPermit {
    /// Consume the permit immediately before its matching repository call.
    pub(crate) fn consume(
        self,
        operation: MutationOperation,
        authority: &Value,
        params: &Value,
        now_unix_ms: u64,
    ) -> Result<PendingMutation, GatewayError> {
        let actual = transport_fingerprint(operation, authority, params)?;
        if self.operation != operation || self.transport_fingerprint != actual {
            return Err(GatewayError::SubjectMismatch(
                "operation or request fields changed after final check".into(),
            ));
        }
        if now_unix_ms >= self.expires_at_unix_ms {
            return Err(GatewayError::PermitExpired);
        }
        Ok(PendingMutation {
            subject: self.subject,
        })
    }
}

/// Non-cloneable exact mutation that must be settled after repository execution.
#[must_use = "a consumed mutation permit must be settled"]
pub(crate) struct PendingMutation {
    subject: MutationSubject,
}

/// Authority gateway held by one daemon process.
pub(crate) struct AuthorityGateway {
    checker: Box<dyn FinalAuthorityCheck>,
    clock: Box<dyn Clock>,
    ledger: Option<MutationLedger>,
}

impl AuthorityGateway {
    /// Production-safe gateway while immutable contract publication is
    /// blocked. It can return no permit under any input.
    #[must_use]
    pub(crate) fn unavailable() -> Self {
        Self {
            checker: Box::new(UnavailableFinalCheck),
            clock: Box::new(SystemClock),
            ledger: None,
        }
    }

    /// Fixture-only gateway bound to one pre-opened root and MAC key.
    #[cfg(feature = "fixture-authority")]
    pub(crate) fn fixture(
        root: &std::path::Path,
        key: [u8; 32],
        permit: FixturePermit,
    ) -> Result<Self, GatewayError> {
        let claims = verify_fixture_permit(&key, &permit)
            .map_err(|err| GatewayError::Refused(err.to_string()))?;
        if claims.destination != root.display().to_string()
            && std::fs::canonicalize(root)
                .ok()
                .map(|path| path.display().to_string())
                != Some(claims.destination.clone())
        {
            return Err(GatewayError::Refused(
                "fixture permit destination does not match the pre-opened root".into(),
            ));
        }
        let ledger = MutationLedger::open(root.join(".bullet-mutation-ledger"))?;
        Ok(Self {
            checker: Box::new(FixtureCheck { key, permit }),
            clock: Box::new(SystemClock),
            ledger: Some(ledger),
        })
    }

    pub(crate) fn authorize(
        &mut self,
        operation: MutationOperation,
        authority: &Value,
        params: &Value,
        expected_attempt: &str,
        expected_fence: u64,
        expected_workspace_nonce: &[u8; 32],
    ) -> Result<MutationPermit, GatewayError> {
        if let Some(ledger) = self.ledger.as_ref() {
            ledger.require_writable()?;
        }
        let fingerprint = transport_fingerprint(operation, authority, params)?;
        let input = FinalCheckInput {
            operation,
            authority,
            params,
            transport_fingerprint: fingerprint,
        };
        let decision = self.checker.check(&input)?;
        if decision.operation != operation
            || decision.subject.operation != operation
            || decision.transport_fingerprint != fingerprint
        {
            return Err(GatewayError::SubjectMismatch(
                "final-check response does not bind the exact operation and request".into(),
            ));
        }
        if decision.subject.attempt_id != expected_attempt
            || decision.subject.attempt_fence != expected_fence
            || decision.subject.workspace_nonce != hex::encode(expected_workspace_nonce)
        {
            return Err(GatewayError::SubjectMismatch(
                "final-check response does not bind the exact writer incarnation".into(),
            ));
        }
        let now = self.clock.now_unix_ms()?;
        if now >= decision.expires_at_unix_ms {
            return Err(GatewayError::PermitExpired);
        }
        if decision.expires_at_unix_ms - now > MAX_MUTATION_PERMIT_TTL_MS {
            return Err(GatewayError::InvalidPermitWindow);
        }
        let ledger = self.ledger.as_mut().ok_or_else(|| {
            GatewayError::ContractUnavailable("durable authority ledger is unavailable".into())
        })?;
        match ledger.reserve(&decision.subject)? {
            ReplayDisposition::Fresh => Ok(MutationPermit {
                subject: decision.subject,
                operation,
                transport_fingerprint: fingerprint,
                expires_at_unix_ms: decision.expires_at_unix_ms,
            }),
            ReplayDisposition::ExactReplay(_) => Err(GatewayError::Refused(
                "settled replay returns its durable result, never another permit".into(),
            )),
        }
    }

    pub(crate) fn now_unix_ms(&self) -> Result<u64, GatewayError> {
        self.clock.now_unix_ms()
    }

    /// Settle one consumed permit against online authority and local replay state.
    ///
    /// Once repository execution has started, every refusal, outage, mismatch,
    /// or local persistence failure is UNKNOWN rather than a proven abort.
    pub(crate) fn settle(
        &mut self,
        pending: PendingMutation,
        outcome: MutationOutcome,
        result_digest: &str,
    ) -> Result<(), GatewayError> {
        let completed_at_unix_ms = self
            .clock
            .now_unix_ms()
            .map_err(|error| GatewayError::SettlementUnknown(error.to_string()))?;
        let parsed_digest = Digest::from_hex(result_digest)
            .map_err(|error| GatewayError::SettlementUnknown(error.to_string()))?;
        if parsed_digest.to_hex() != result_digest {
            return Err(GatewayError::SettlementUnknown(
                "result digest is not full lowercase hexadecimal".into(),
            ));
        }
        let settlement_fingerprint = settlement_fingerprint(
            &pending.subject,
            outcome,
            result_digest,
            completed_at_unix_ms,
        );
        let input = FinalSettlementInput {
            subject: &pending.subject,
            outcome,
            result_digest,
            completed_at_unix_ms,
            settlement_fingerprint,
        };
        let acknowledgment = self
            .checker
            .settle(&input)
            .map_err(|error| GatewayError::SettlementUnknown(error.to_string()))?;
        if acknowledgment.mutation_id != input.subject.mutation_id
            || acknowledgment.reservation_id != input.subject.reservation_id
            || acknowledgment.result_digest != input.result_digest
            || acknowledgment.settlement_fingerprint != input.settlement_fingerprint
        {
            return Err(GatewayError::SettlementUnknown(
                "online settlement acknowledgment changed an exact bound field".into(),
            ));
        }
        let ledger = self.ledger.as_mut().ok_or_else(|| {
            GatewayError::SettlementUnknown("durable authority ledger is unavailable".into())
        })?;
        ledger
            .settle(
                &pending.subject,
                outcome,
                result_digest,
                completed_at_unix_ms,
            )
            .map_err(|error| GatewayError::SettlementUnknown(error.to_string()))?;
        Ok(())
    }
}

#[cfg(feature = "fixture-authority")]
struct FixtureCheck {
    key: [u8; 32],
    permit: FixturePermit,
}

#[cfg(feature = "fixture-authority")]
impl FinalAuthorityCheck for FixtureCheck {
    fn check(&mut self, input: &FinalCheckInput<'_>) -> Result<VerifiedDecision, GatewayError> {
        let claims = verify_fixture_permit(&self.key, &self.permit)
            .map_err(|err| GatewayError::Refused(err.to_string()))?;
        let token = crate::protocol::envelope(input.authority);
        let parsed = bullet_git_types::WireAuthorityToken::parse(&token.token)
            .map_err(|err| GatewayError::Refused(err.to_string()))?;
        let nonce_hex = hex::encode(parsed.workspace_nonce);
        if parsed.attempt_id != claims.attempt_id
            || parsed.attempt_fence != claims.attempt_fence
            || nonce_hex != claims.workspace_nonce_hex
        {
            return Err(GatewayError::Refused(
                "fixture permit does not bind this authority token".into(),
            ));
        }
        if input.operation == MutationOperation::CloneWorkspace {
            let root = input
                .params
                .get("root")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if root != claims.destination {
                return Err(GatewayError::Refused(format!(
                    "FIXTURE_DESTINATION_REFUSED: {root}"
                )));
            }
        }
        let now = SystemClock.now_unix_ms()?;
        let expires_at_unix_ms = now.saturating_add(500);
        let envelope_digest =
            framed_digest(&[b"fixture.authority-envelope", &token.token]).to_hex();
        let token_nonce = framed_digest(&[b"fixture.token-nonce", &token.token]).to_hex();
        let mutation_hex = framed_digest(&[
            b"fixture.mutation",
            input.operation.as_str().as_bytes(),
            input.transport_fingerprint.as_bytes(),
        ])
        .to_hex();
        let reservation_hex =
            framed_digest(&[b"fixture.reservation", mutation_hex.as_bytes()]).to_hex();
        let request_digest = input.transport_fingerprint.to_hex();
        let permit_nonce =
            framed_digest(&[b"fixture.permit-nonce", self.permit.mac_hex.as_bytes()]).to_hex();
        let permit_digest =
            framed_digest(&[b"fixture.permit-digest", self.permit.mac_hex.as_bytes()]).to_hex();
        let repository_id = format!(
            "rep_{}",
            framed_digest(&[b"fixture.repo", claims.destination.as_bytes()]).to_hex()
        );
        let workspace_id = format!(
            "wsp_{}",
            framed_digest(&[b"fixture.workspace", claims.destination.as_bytes()]).to_hex()
        );
        Ok(VerifiedDecision {
            subject: MutationSubject {
                authority_envelope_digest: envelope_digest,
                authority_token_nonce: token_nonce,
                mutation_id: format!("mut_{mutation_hex}"),
                reservation_id: format!("rsv_{reservation_hex}"),
                operation: input.operation,
                request_digest,
                repository_id,
                workspace_id,
                workspace_generation: 1,
                workspace_nonce: nonce_hex,
                attempt_id: parsed.attempt_id,
                attempt_fence: parsed.attempt_fence,
                authority_epoch: 1,
                freeze_generation: 0,
                permit_nonce,
                permit_digest,
            },
            operation: input.operation,
            transport_fingerprint: input.transport_fingerprint,
            expires_at_unix_ms,
        })
    }

    fn settle(
        &mut self,
        input: &FinalSettlementInput<'_>,
    ) -> Result<VerifiedSettlement, GatewayError> {
        Ok(VerifiedSettlement {
            mutation_id: input.subject.mutation_id.clone(),
            reservation_id: input.subject.reservation_id.clone(),
            result_digest: input.result_digest.to_string(),
            settlement_fingerprint: input.settlement_fingerprint,
        })
    }
}

fn settlement_fingerprint(
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

fn transport_fingerprint(
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

#[cfg(test)]
#[path = "authority_gateway_tests.rs"]
mod tests;
