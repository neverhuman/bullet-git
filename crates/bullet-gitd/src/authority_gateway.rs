//! Fail-closed boundary between pre-contract daemon requests and frozen authority.
//!
//! The frozen `bullet-wire` runtime crate is not yet available from an
//! immutable permitted source. Production therefore installs only an
//! unavailable checker. Test-only checkers exercise the private one-use
//! permit and durable replay machinery without creating a production bypass.

use crate::mutation_ledger::{
    MutationLedger, MutationLedgerError, MutationOperation, MutationSubject, ReplayDisposition,
};
use bullet_git_types::{framed_digest, Digest};
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

trait FinalAuthorityCheck: Send {
    fn check(&mut self, input: &FinalCheckInput<'_>) -> Result<VerifiedDecision, GatewayError>;
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
    ) -> Result<MutationSubject, GatewayError> {
        let actual = transport_fingerprint(operation, authority, params)?;
        if self.operation != operation || self.transport_fingerprint != actual {
            return Err(GatewayError::SubjectMismatch(
                "operation or request fields changed after final check".into(),
            ));
        }
        if now_unix_ms >= self.expires_at_unix_ms {
            return Err(GatewayError::PermitExpired);
        }
        Ok(self.subject)
    }
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

    pub(crate) fn authorize(
        &mut self,
        operation: MutationOperation,
        authority: &Value,
        params: &Value,
    ) -> Result<MutationPermit, GatewayError> {
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
mod tests {
    use super::*;
    use crate::mutation_ledger::{MutationOperation, MutationOutcome};
    use tempfile::TempDir;

    struct FixedClock(u64);

    impl Clock for FixedClock {
        fn now_unix_ms(&self) -> Result<u64, GatewayError> {
            Ok(self.0)
        }
    }

    struct FixedCheck {
        subject: MutationSubject,
        expires_at_unix_ms: u64,
        mutate_fingerprint: bool,
    }

    struct SupersededCheck;

    impl FinalAuthorityCheck for SupersededCheck {
        fn check(
            &mut self,
            _input: &FinalCheckInput<'_>,
        ) -> Result<VerifiedDecision, GatewayError> {
            Err(GatewayError::Refused(
                "active lease was superseded before mutation".into(),
            ))
        }
    }

    impl FinalAuthorityCheck for FixedCheck {
        fn check(&mut self, input: &FinalCheckInput<'_>) -> Result<VerifiedDecision, GatewayError> {
            let fingerprint = if self.mutate_fingerprint {
                Digest::of(b"wrong request")
            } else {
                input.transport_fingerprint
            };
            Ok(VerifiedDecision {
                subject: self.subject.clone(),
                operation: input.operation,
                transport_fingerprint: fingerprint,
                expires_at_unix_ms: self.expires_at_unix_ms,
            })
        }
    }

    fn subject() -> MutationSubject {
        MutationSubject {
            mutation_id: format!("mut_{}", "1".repeat(64)),
            reservation_id: format!("rsv_{}", "2".repeat(64)),
            operation: MutationOperation::ApplyPatch,
            request_digest: "3".repeat(64),
            permit_digest: "4".repeat(64),
        }
    }

    fn gateway(temp: &TempDir, expires: u64, mutate: bool) -> AuthorityGateway {
        AuthorityGateway {
            checker: Box::new(FixedCheck {
                subject: subject(),
                expires_at_unix_ms: expires,
                mutate_fingerprint: mutate,
            }),
            clock: Box::new(FixedClock(100)),
            ledger: Some(MutationLedger::open(temp.path()).expect("ledger")),
        }
    }

    fn refused(result: Result<MutationPermit, GatewayError>) -> GatewayError {
        match result {
            Ok(_) => panic!("unexpected permit"),
            Err(error) => error,
        }
    }

    #[test]
    fn unavailable_production_gateway_never_returns_a_permit() {
        let mut gateway = AuthorityGateway::unavailable();
        let error = refused(gateway.authorize(
            MutationOperation::ApplyPatch,
            &serde_json::json!({"paseto": "forged"}),
            &serde_json::json!({"path": "src/lib.rs"}),
        ));
        assert_eq!(error.reason_code(), "AUTHORITY_CONTRACT_UNAVAILABLE");
    }

    #[test]
    fn changed_fields_and_expiry_never_produce_a_consumable_permit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let authority = serde_json::json!({"paseto": "fixture"});
        let params = serde_json::json!({"path": "src/lib.rs"});

        let error = refused(gateway(&temp, 200, true).authorize(
            MutationOperation::ApplyPatch,
            &authority,
            &params,
        ));
        assert_eq!(error.reason_code(), "AUTHORITY_SUBJECT_MISMATCH");

        let expired_temp = tempfile::tempdir().expect("tempdir");
        let error = refused(gateway(&expired_temp, 100, false).authorize(
            MutationOperation::ApplyPatch,
            &authority,
            &params,
        ));
        assert_eq!(error.reason_code(), "MUTATION_PERMIT_EXPIRED");

        let live_temp = tempfile::tempdir().expect("tempdir");
        let mut live = gateway(&live_temp, 200, false);
        let permit = live
            .authorize(MutationOperation::ApplyPatch, &authority, &params)
            .expect("permit");
        let changed = serde_json::json!({"path": "src/other.rs"});
        let error = permit
            .consume(MutationOperation::ApplyPatch, &authority, &changed, 101)
            .expect_err("changed after check");
        assert_eq!(error.reason_code(), "AUTHORITY_SUBJECT_MISMATCH");
    }

    #[test]
    fn supersession_refusal_creates_no_reservation_or_permit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut gateway = AuthorityGateway {
            checker: Box::new(SupersededCheck),
            clock: Box::new(FixedClock(100)),
            ledger: Some(MutationLedger::open(temp.path()).expect("ledger")),
        };
        let error = refused(gateway.authorize(
            MutationOperation::ApplyPatch,
            &serde_json::json!({"paseto": "superseded"}),
            &serde_json::json!({"path": "src/lib.rs"}),
        ));
        assert_eq!(error.reason_code(), "AUTHORITY_REFUSED");
        assert_eq!(temp.path().read_dir().expect("ledger dir").count(), 0);
    }

    #[test]
    fn settled_replay_never_returns_another_permit() {
        let temp = tempfile::tempdir().expect("tempdir");
        let exact = subject();
        let mut ledger = MutationLedger::open(temp.path()).expect("ledger");
        ledger.reserve(&exact).expect("reserve");
        ledger
            .settle(&exact, MutationOutcome::Committed, &"5".repeat(64), 99)
            .expect("settle");
        let mut gateway = AuthorityGateway {
            checker: Box::new(FixedCheck {
                subject: exact,
                expires_at_unix_ms: 200,
                mutate_fingerprint: false,
            }),
            clock: Box::new(FixedClock(100)),
            ledger: Some(ledger),
        };
        let error = refused(gateway.authorize(
            MutationOperation::ApplyPatch,
            &serde_json::json!({"paseto": "fixture"}),
            &serde_json::json!({"path": "src/lib.rs"}),
        ));
        assert_eq!(error.reason_code(), "AUTHORITY_REFUSED");
    }
}
