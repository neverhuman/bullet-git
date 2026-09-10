use super::fingerprint::{settlement_fingerprint, transport_fingerprint};
use super::*;
use crate::daemon::{ReceiptAuthorization, ReceiptSubject};
use crate::mutation_ledger::{MutationLedgerError, ReplayDisposition};

const MAX_MUTATION_PERMIT_TTL_MS: u64 = 1_000;

/// Revocation epoch recorded for a receipt-gated cleanup.
///
/// The sealed preservation receipt is the authority on this path, so no
/// online epoch is read back. The constant records exactly that: one fixed
/// local receipt-authority epoch, never a claim about Kernel state.
const RECEIPT_AUTHORITY_EPOCH: u64 = 1;

/// Which authority settles one reserved mutation.
#[derive(Clone, Copy, Eq, PartialEq)]
enum SettlementPath {
    /// Kernel-permit operations acknowledge online before the local record.
    Kernel,
    /// Receipt-gated cleanup has no Kernel reservation to acknowledge.
    ReceiptLocal,
}

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
        let permit = match self.open_ledger()?.reserve(&decision.subject)? {
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
            return Err(self.abort_before_repository(
                permit.into_pending(),
                refusal,
                SettlementPath::Kernel,
            ));
        }
        Ok(permit)
    }

    /// Authorize one cleanup against an already verified sealed receipt.
    ///
    /// No Kernel permit is required and no online check is made: the caller
    /// has proven that this daemon session issued the receipt over this exact
    /// workspace, and the writer lease that authorized the attempt is
    /// terminal by protocol once the attempt has succeeded. The reservation
    /// is still durable, so replay detection and exactly-once still hold.
    pub(crate) fn authorize_by_preservation_receipt(
        &mut self,
        authority: &Value,
        params: &Value,
        receipt: &ReceiptSubject<'_>,
    ) -> Result<ReceiptAuthorization, GatewayError> {
        const OPERATION: MutationOperation = MutationOperation::CleanupWorkspace;
        self.recover_existing_ledger()?;
        let stripped = crate::kernel_permit::authority_without_permit(authority);
        let fingerprint = transport_fingerprint(OPERATION, &stripped, params)?;
        let now = self.clock.now_unix_ms()?;
        let expires_at_unix_ms = now
            .checked_add(MAX_MUTATION_PERMIT_TTL_MS)
            .ok_or_else(|| GatewayError::Clock("permit window exceeds u64 milliseconds".into()))?;
        let subject = receipt_mutation_subject(receipt, fingerprint);
        match self.open_ledger()?.reserve(&subject)? {
            ReplayDisposition::Fresh => Ok(ReceiptAuthorization::Fresh(Box::new(MutationPermit {
                subject,
                operation: OPERATION,
                transport_fingerprint: fingerprint,
                expires_at_unix_ms,
            }))),
            ReplayDisposition::ExactReplay(result) => Ok(ReceiptAuthorization::Replay(result)),
        }
    }

    /// Open the durable replay ledger under the attached root, once.
    fn open_ledger(&mut self) -> Result<&mut MutationLedger, GatewayError> {
        if self.ledger.is_none() {
            if let Some(root) = &self.ledger_root {
                self.ledger = Some(MutationLedger::open(root.join(".bullet-mutation-ledger"))?);
            }
        }
        self.ledger.as_mut().ok_or_else(|| {
            GatewayError::ContractUnavailable("durable authority ledger is unavailable".into())
        })
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
        self.consume_through(permit, operation, authority, params, SettlementPath::Kernel)
    }

    /// Consume a receipt-gated cleanup permit. A pre-repository refusal is a
    /// proven abort recorded locally, never a Kernel settlement.
    pub(crate) fn consume_by_preservation_receipt(
        &mut self,
        permit: MutationPermit,
        authority: &Value,
        params: &Value,
    ) -> Result<PendingMutation, GatewayError> {
        self.consume_through(
            permit,
            MutationOperation::CleanupWorkspace,
            authority,
            params,
            SettlementPath::ReceiptLocal,
        )
    }

    fn consume_through(
        &mut self,
        permit: MutationPermit,
        operation: MutationOperation,
        authority: &Value,
        params: &Value,
        path: SettlementPath,
    ) -> Result<PendingMutation, GatewayError> {
        let validation = self.clock.now_unix_ms().and_then(|now| {
            permit.validate_immediately_before_repository(operation, authority, params, now)
        });
        match validation {
            Ok(()) => Ok(permit.into_pending()),
            Err(refusal) => Err(self.abort_before_repository(permit.into_pending(), refusal, path)),
        }
    }

    fn abort_before_repository(
        &mut self,
        pending: PendingMutation,
        refusal: GatewayError,
        path: SettlementPath,
    ) -> GatewayError {
        let subject = pending.subject.clone();
        let result_digest = bullet_git_types::framed_digest(&[
            b"bullet-gitd.pre-repository-abort.v1",
            subject.operation.as_str().as_bytes(),
            refusal.reason_code().as_bytes(),
        ])
        .to_hex();
        match self.settle_through(pending, MutationOutcome::Aborted, &result_digest, path) {
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
        self.settle_through(pending, outcome, result_digest, SettlementPath::Kernel)
    }

    /// Settle one receipt-gated cleanup against local durable state only.
    ///
    /// The sealed receipt, not an online lease, authorized this mutation, so
    /// there is no Kernel reservation to acknowledge. Every local persistence
    /// failure after repository execution is still UNKNOWN.
    pub(crate) fn settle_locally(
        &mut self,
        pending: PendingMutation,
        outcome: MutationOutcome,
        result_digest: &str,
    ) -> Result<(), GatewayError> {
        self.settle_through(
            pending,
            outcome,
            result_digest,
            SettlementPath::ReceiptLocal,
        )
    }

    fn settle_through(
        &mut self,
        pending: PendingMutation,
        outcome: MutationOutcome,
        result_digest: &str,
        path: SettlementPath,
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
        if path == SettlementPath::Kernel {
            self.acknowledge_online(&pending, outcome, result_digest, completed_at_unix_ms)?;
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

    fn acknowledge_online(
        &mut self,
        pending: &PendingMutation,
        outcome: MutationOutcome,
        result_digest: &str,
        completed_at_unix_ms: u64,
    ) -> Result<(), GatewayError> {
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
        Ok(())
    }
}

/// Derive the exact durable subject of one receipt-gated cleanup.
///
/// Every identifier is a domain-separated digest over facts that already
/// exist: the sealed receipt, the operation, and the writer incarnation. The
/// same receipt over the same incarnation therefore always names the same
/// Mutation, which is what makes replay detection exact.
fn receipt_mutation_subject(receipt: &ReceiptSubject<'_>, fingerprint: Digest) -> MutationSubject {
    let workspace_nonce = hex::encode(receipt.workspace_nonce);
    let attempt_fence = receipt.attempt_fence.to_string();
    let derive = |domain: &[u8]| {
        bullet_git_types::framed_digest(&[
            domain,
            receipt.receipt_digest.as_bytes(),
            MutationOperation::CleanupWorkspace.as_str().as_bytes(),
            receipt.attempt_id.as_bytes(),
            attempt_fence.as_bytes(),
            workspace_nonce.as_bytes(),
        ])
        .to_hex()
    };
    MutationSubject {
        // The sealed receipt is the authority envelope on this path, so the
        // envelope digest and the token nonce are both the receipt digest.
        authority_envelope_digest: Digest::of(receipt.receipt_token.as_bytes()).to_hex(),
        authority_token_nonce: receipt.receipt_digest.to_owned(),
        mutation_id: format!("mut_{}", derive(b"bullet-gitd.receipt-mutation-id.v1")),
        reservation_id: format!("rsv_{}", derive(b"bullet-gitd.receipt-reservation-id.v1")),
        operation: MutationOperation::CleanupWorkspace,
        request_digest: fingerprint.to_hex(),
        repository_id: receipt.repository_id.to_owned(),
        workspace_id: receipt.workspace_id.to_owned(),
        workspace_generation: receipt.workspace_generation,
        workspace_nonce: workspace_nonce.clone(),
        attempt_id: receipt.attempt_id.to_owned(),
        attempt_fence: receipt.attempt_fence,
        authority_epoch: RECEIPT_AUTHORITY_EPOCH,
        freeze_generation: 0,
        permit_nonce: derive(b"bullet-gitd.receipt-permit-nonce.v1"),
        permit_digest: derive(b"bullet-gitd.receipt-permit-digest.v1"),
    }
}

#[cfg(test)]
#[path = "receipt_gateway_tests.rs"]
mod receipt_gateway_tests;
