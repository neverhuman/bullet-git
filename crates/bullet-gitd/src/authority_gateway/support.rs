use super::{
    FinalAuthorityCheck, FinalCheckInput, FinalSettlementInput, VerifiedDecision,
    VerifiedSettlement,
};
use crate::mutation_ledger::MutationLedgerError;
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

pub(super) trait Clock: Send {
    fn now_unix_ms(&self) -> Result<u64, GatewayError>;
}

pub(super) struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_ms(&self) -> Result<u64, GatewayError> {
        let duration = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|error| GatewayError::Clock(error.to_string()))?;
        u64::try_from(duration.as_millis())
            .map_err(|_| GatewayError::Clock("system time exceeds u64 milliseconds".into()))
    }
}

#[allow(dead_code)]
pub(super) struct UnavailableFinalCheck;

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
