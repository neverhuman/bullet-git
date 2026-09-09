//! Production Kernel-permit checker. Unsigned and fixture tokens refuse.
//!
//! `Daemon::new()` installs this checker. It accepts only a Kernel-issued
//! one-use permit plus an online lease/fence/reservation read-back over
//! `BULLET_KERNEL_AUTHORITY_SOCKET`. `fixture-authority` is not on this path.

use crate::authority_gateway::{
    FinalAuthorityCheck, FinalCheckInput, FinalSettlementInput, GatewayError, VerifiedDecision,
    VerifiedSettlement,
};
#[cfg(target_os = "linux")]
use bullet_git_types::Digest;
use serde_json::Value;
#[cfg(target_os = "linux")]
use std::env;
#[cfg(target_os = "linux")]
use std::path::PathBuf;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
mod transport;
#[cfg(target_os = "linux")]
mod wire;

#[cfg(all(test, target_os = "linux"))]
#[path = "kernel_permit/tests.rs"]
mod tests;

#[cfg(target_os = "linux")]
const ENV_SOCKET: &str = "BULLET_KERNEL_AUTHORITY_SOCKET";
#[cfg(target_os = "linux")]
const ENV_SERVER_UID: &str = "BULLET_KERNEL_AUTHORITY_SERVER_UID";
#[cfg(target_os = "linux")]
const ENV_SOCKET_GID: &str = "BULLET_KERNEL_AUTHORITY_SOCKET_GID";
#[cfg(target_os = "linux")]
const RPC_DEADLINE: Duration = Duration::from_secs(1);

/// Strip `kernel_permit` so the request fingerprint is independent of the envelope.
pub(crate) fn authority_without_permit(authority: &Value) -> Value {
    match authority {
        Value::Object(map) => {
            let mut stripped = map.clone();
            stripped.remove("kernel_permit");
            Value::Object(stripped)
        }
        other => other.clone(),
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn extract_kernel_permit(authority: &Value) -> Option<Value> {
    authority.get("kernel_permit").cloned()
}

pub(crate) struct KernelPermitCheck {
    #[cfg(target_os = "linux")]
    transport: Result<transport::TransportConfig, String>,
}

impl KernelPermitCheck {
    pub(crate) fn from_env() -> Self {
        #[cfg(target_os = "linux")]
        {
            Self {
                transport: transport::TransportConfig::from_values(
                    env::var_os(ENV_SOCKET).map(PathBuf::from),
                    env::var_os(ENV_SERVER_UID),
                    env::var_os(ENV_SOCKET_GID),
                    RPC_DEADLINE,
                ),
            }
        }
        #[cfg(not(target_os = "linux"))]
        Self {
            // Production authority requires Linux SO_PEERCRED.
        }
    }

    #[cfg(target_os = "linux")]
    fn transport(&self) -> Result<&transport::TransportConfig, GatewayError> {
        self.transport.as_ref().map_err(|message| {
            GatewayError::ContractUnavailable(format!(
                "Kernel authority transport is not admitted: {message}"
            ))
        })
    }
}

#[cfg(target_os = "linux")]
impl FinalAuthorityCheck for KernelPermitCheck {
    fn check(&mut self, input: &FinalCheckInput<'_>) -> Result<VerifiedDecision, GatewayError> {
        let Some(permit) = extract_kernel_permit(input.authority) else {
            return Err(GatewayError::ContractUnavailable(
                "unsigned or legacy authority token is not a Kernel-issued mutation permit".into(),
            ));
        };
        let reply: wire::CheckReply = wire::call(
            self.transport()?,
            "check",
            &wire::CheckBody {
                operation: input.operation.as_str().to_string(),
                authority: authority_without_permit(input.authority),
                params: input.params.clone(),
                kernel_permit: permit,
                transport_fingerprint: input.transport_fingerprint.to_hex(),
            },
        )?;
        if reply.operation != input.operation.as_str()
            || reply.transport_fingerprint != input.transport_fingerprint.to_hex()
        {
            return Err(GatewayError::SubjectMismatch(
                "Kernel check did not bind the exact operation and request".into(),
            ));
        }
        Ok(VerifiedDecision {
            subject: reply.subject,
            operation: input.operation,
            transport_fingerprint: input.transport_fingerprint,
            expires_at_unix_ms: reply.expires_at_unix_ms,
        })
    }

    fn settle(
        &mut self,
        input: &FinalSettlementInput<'_>,
    ) -> Result<VerifiedSettlement, GatewayError> {
        let reply: wire::SettleReply = wire::call(
            self.transport()?,
            "settle",
            &wire::SettleBody {
                subject: input.subject.clone(),
                outcome: match input.outcome {
                    crate::mutation_ledger::MutationOutcome::Committed => "committed",
                    crate::mutation_ledger::MutationOutcome::Aborted => "aborted",
                    crate::mutation_ledger::MutationOutcome::Unknown => "unknown",
                }
                .to_string(),
                result_digest: input.result_digest.to_string(),
                completed_at_unix_ms: input.completed_at_unix_ms,
                settlement_fingerprint: input.settlement_fingerprint.to_hex(),
            },
        )?;
        Ok(VerifiedSettlement {
            mutation_id: reply.mutation_id,
            reservation_id: reply.reservation_id,
            result_digest: reply.result_digest,
            settlement_fingerprint: Digest::from_hex(&reply.settlement_fingerprint)
                .map_err(|error| GatewayError::SettlementUnknown(error.to_string()))?,
        })
    }
}

#[cfg(not(target_os = "linux"))]
impl FinalAuthorityCheck for KernelPermitCheck {
    fn check(&mut self, input: &FinalCheckInput<'_>) -> Result<VerifiedDecision, GatewayError> {
        let _ = (
            input.operation,
            input.authority,
            input.params,
            input.transport_fingerprint,
        );
        Err(GatewayError::ContractUnavailable(
            "Kernel authority transport requires Linux SO_PEERCRED and a peer-authenticated Unix socket"
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
            "Kernel authority transport requires Linux SO_PEERCRED and a peer-authenticated Unix socket"
                .into(),
        ))
    }
}
