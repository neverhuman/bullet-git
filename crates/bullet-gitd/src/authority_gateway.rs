//! Fail-closed boundary between pre-contract daemon requests and frozen authority.
//!
//! Production installs a Kernel-permit checker that accepts only a
//! Kernel-issued one-use permit plus online lease/fence/reservation
//! read-back. Fixture MAC stays off this path. Unsigned tokens refuse.

use crate::mutation_ledger::{MutationLedger, MutationOperation, MutationOutcome, MutationSubject};

#[path = "authority_gateway/fingerprint.rs"]
mod fingerprint;
#[path = "authority_gateway/gateway.rs"]
mod gateway;
#[path = "authority_gateway/support.rs"]
mod support;

#[cfg(feature = "fixture-authority")]
#[path = "authority_gateway/fixture.rs"]
mod fixture;
#[cfg(feature = "fixture-authority")]
#[path = "fixture_permit.rs"]
mod fixture_permit;

use bullet_git_types::Digest;
use fingerprint::transport_fingerprint;
#[cfg(feature = "fixture-authority")]
pub use fixture_permit::{
    consume_fixture_generation, destination_is_fixture_root, mint_fixture_permit,
    parse_fixture_key, require_preopened_fixture_root, verify_fixture_permit, FixturePermit,
    FixturePermitClaims, FixturePermitError,
};
use serde_json::Value;
pub(crate) use support::GatewayError;
use support::{Clock, SystemClock, UnavailableFinalCheck};

/// Exact pre-contract call presented to a future frozen-contract consumer.
pub(crate) struct FinalCheckInput<'a> {
    pub(crate) operation: MutationOperation,
    pub(crate) authority: &'a Value,
    pub(crate) params: &'a Value,
    pub(crate) transport_fingerprint: Digest,
}

/// Result of local PASETO plus Kernel final-check verification.
///
/// Constructors remain private so unverified transport data cannot become a
/// repository permit.
#[derive(Clone)]
pub(crate) struct VerifiedDecision {
    pub(crate) subject: MutationSubject,
    pub(crate) operation: MutationOperation,
    pub(crate) transport_fingerprint: Digest,
    pub(crate) expires_at_unix_ms: u64,
}

/// Exact settlement after either a proven pre-I/O abort or repository return.
pub(crate) struct FinalSettlementInput<'a> {
    pub(crate) subject: &'a MutationSubject,
    pub(crate) outcome: MutationOutcome,
    pub(crate) result_digest: &'a str,
    pub(crate) completed_at_unix_ms: u64,
    pub(crate) settlement_fingerprint: Digest,
}

/// Acknowledgment verified by the future frozen online authority consumer.
#[derive(Clone)]
pub(crate) struct VerifiedSettlement {
    pub(crate) mutation_id: String,
    pub(crate) reservation_id: String,
    pub(crate) result_digest: String,
    pub(crate) settlement_fingerprint: Digest,
}

pub(crate) trait FinalAuthorityCheck: Send {
    fn check(&mut self, input: &FinalCheckInput<'_>) -> Result<VerifiedDecision, GatewayError>;

    fn settle(
        &mut self,
        input: &FinalSettlementInput<'_>,
    ) -> Result<VerifiedSettlement, GatewayError>;
}

/// Private, non-cloneable proof that one exact operation was authorized.
pub(crate) struct MutationPermit {
    subject: MutationSubject,
    operation: MutationOperation,
    transport_fingerprint: Digest,
    expires_at_unix_ms: u64,
}

impl MutationPermit {
    fn validate_immediately_before_repository(
        &self,
        operation: MutationOperation,
        authority: &Value,
        params: &Value,
        now_unix_ms: u64,
    ) -> Result<(), GatewayError> {
        let stripped = crate::kernel_permit::authority_without_permit(authority);
        let actual = transport_fingerprint(operation, &stripped, params)?;
        if self.operation != operation || self.transport_fingerprint != actual {
            return Err(GatewayError::SubjectMismatch(
                "operation or request fields changed after final check".into(),
            ));
        }
        if now_unix_ms >= self.expires_at_unix_ms {
            return Err(GatewayError::PermitExpired);
        }
        Ok(())
    }

    fn into_pending(self) -> PendingMutation {
        PendingMutation {
            subject: self.subject,
        }
    }

    #[cfg(test)]
    fn consume(
        self,
        operation: MutationOperation,
        authority: &Value,
        params: &Value,
        now_unix_ms: u64,
    ) -> Result<PendingMutation, GatewayError> {
        self.validate_immediately_before_repository(operation, authority, params, now_unix_ms)?;
        Ok(self.into_pending())
    }
}

/// Non-cloneable reservation settled before I/O as aborted or after execution.
#[must_use = "a consumed mutation permit must be settled"]
pub(crate) struct PendingMutation {
    subject: MutationSubject,
}

/// Authority gateway held by one daemon process.
pub(crate) struct AuthorityGateway {
    checker: Box<dyn FinalAuthorityCheck>,
    clock: Box<dyn Clock>,
    ledger: Option<MutationLedger>,
    ledger_root: Option<std::path::PathBuf>,
}

#[cfg(test)]
#[path = "authority_gateway_tests.rs"]
mod tests;
