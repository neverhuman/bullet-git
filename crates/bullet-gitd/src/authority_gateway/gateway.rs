use super::fingerprint::{settlement_fingerprint, transport_fingerprint};
use super::*;
use crate::mutation_ledger::{MutationLedgerError, ReplayDisposition};

const MAX_MUTATION_PERMIT_TTL_MS: u64 = 1_000;

impl AuthorityGateway {
    /// Production-safe gateway while immutable contract publication is
    /// blocked. It can return no permit under any input.
    #[allow(dead_code)]
    #[must_use]
    pub(crate) fn unavailable() -> Self {
        Self {
            checker: Box::new(UnavailableFinalCheck),
            clock: Box::new(SystemClock),
            ledger: None,
            ledger_root: None,
        }
    }

    /// Production checker: Kernel-issued one-use permit plus online read-back.
    #[must_use]
    pub(crate) fn kernel() -> Self {
        Self {
            checker: Box::new(crate::kernel_permit::KernelPermitCheck::from_env()),
            clock: Box::new(SystemClock),
            ledger: None,
            ledger_root: None,
        }
    }

    pub(crate) fn attach_ledger_root(&mut self, root: &std::path::Path) {
        self.ledger_root = Some(root.to_path_buf());
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
        self.recover_existing_ledger()?;
        let stripped = crate::kernel_permit::authority_without_permit(authority);
        let fingerprint = transport_fingerprint(operation, &stripped, params)?;
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
            || decision.subject.request_digest != fingerprint.to_hex()
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
        let window_refusal = match self.clock.now_unix_ms() {
            Ok(now) if now >= decision.expires_at_unix_ms => Some(GatewayError::PermitExpired),
            Ok(now) if decision.expires_at_unix_ms - now > MAX_MUTATION_PERMIT_TTL_MS => {
                Some(GatewayError::InvalidPermitWindow)
            }
            Ok(_) => None,
            Err(error) => Some(error),
        };
        if self.ledger.is_none() {
            if let Some(root) = &self.ledger_root {
                self.ledger = Some(MutationLedger::open(root.join(".bullet-mutation-ledger"))?);
            }
        }
        let ledger = self.ledger.as_mut().ok_or_else(|| {
            GatewayError::ContractUnavailable("durable authority ledger is unavailable".into())
        })?;
        let permit = match ledger.reserve(&decision.subject)? {
            ReplayDisposition::Fresh => MutationPermit {
                subject: decision.subject,
                operation,
                transport_fingerprint: fingerprint,
                expires_at_unix_ms: decision.expires_at_unix_ms,
            },
            ReplayDisposition::ExactReplay(_) => {
                return Err(GatewayError::Refused(
                    "settled replay returns its durable result, never another permit".into(),
                ));
            }
        };
        if let Some(refusal) = window_refusal {
            return Err(self.abort_before_repository(permit.into_pending(), refusal));
        }
        Ok(permit)
    }

    fn recover_existing_ledger(&mut self) -> Result<(), GatewayError> {
        if self.ledger.is_none() {
            if let Some(root) = &self.ledger_root {
                let path = root.join(".bullet-mutation-ledger");
                match std::fs::symlink_metadata(&path) {
                    Ok(_) => self.ledger = Some(MutationLedger::open(path)?),
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                    Err(error) => {
                        return Err(MutationLedgerError::Io(format!(
                            "inspect {} before online authority check: {error}",
                            path.display()
                        ))
                        .into())
                    }
                }
            }
        }
        if let Some(ledger) = self.ledger.as_ref() {
            ledger.require_writable()?;
        }
        Ok(())
    }

    /// Rebind and consume immediately before repository I/O. A refusal after
    /// durable reservation is a proven abort only when both settlements agree.
    pub(crate) fn consume(
        &mut self,
        permit: MutationPermit,
        operation: MutationOperation,
        authority: &Value,
        params: &Value,
    ) -> Result<PendingMutation, GatewayError> {
        let validation = self.clock.now_unix_ms().and_then(|now| {
            permit.validate_immediately_before_repository(operation, authority, params, now)
        });
        match validation {
            Ok(()) => Ok(permit.into_pending()),
            Err(refusal) => Err(self.abort_before_repository(permit.into_pending(), refusal)),
        }
    }

    fn abort_before_repository(
        &mut self,
        pending: PendingMutation,
        refusal: GatewayError,
    ) -> GatewayError {
        let subject = pending.subject.clone();
        let result_digest = bullet_git_types::framed_digest(&[
            b"bullet-gitd.pre-repository-abort.v1",
            subject.operation.as_str().as_bytes(),
            refusal.reason_code().as_bytes(),
        ])
        .to_hex();
        match self.settle(pending, MutationOutcome::Aborted, &result_digest) {
            Ok(()) => refusal,
            Err(unknown) => {
                if let Some(ledger) = self.ledger.as_mut() {
                    let _ = ledger.reserve(&subject);
                }
                unknown
            }
        }
    }

    /// Settle one reserved operation against online authority and local replay state.
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
