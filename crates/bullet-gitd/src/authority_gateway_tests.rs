use super::fingerprint::settlement_fingerprint;
use super::*;
use tempfile::TempDir;

const WRITER_NONCE: [u8; 32] = [7; 32];
const RESULT_DIGEST: &str = "5555555555555555555555555555555555555555555555555555555555555555";

struct FixedClock(u64);

impl Clock for FixedClock {
    fn now_unix_ms(&self) -> Result<u64, GatewayError> {
        Ok(self.0)
    }
}

struct UnexpectedClock;

impl Clock for UnexpectedClock {
    fn now_unix_ms(&self) -> Result<u64, GatewayError> {
        panic!("request-subject mismatch must refuse before reading trusted time")
    }
}

#[derive(Clone, Copy)]
enum SettlementBehavior {
    Exact,
    Refuse,
    ChangeMutation,
    ChangeReservation,
    ChangeDigest,
    ChangeFingerprint,
}

struct FixedCheck {
    subject: MutationSubject,
    expires_at_unix_ms: u64,
    mutate_fingerprint: bool,
    settlement: SettlementBehavior,
}

struct SupersededCheck;
struct UnexpectedCheck;

impl FinalAuthorityCheck for SupersededCheck {
    fn check(&mut self, _input: &FinalCheckInput<'_>) -> Result<VerifiedDecision, GatewayError> {
        Err(GatewayError::Refused(
            "active lease was superseded before mutation".into(),
        ))
    }

    fn settle(
        &mut self,
        _input: &FinalSettlementInput<'_>,
    ) -> Result<VerifiedSettlement, GatewayError> {
        Err(GatewayError::Refused("no reservation to settle".into()))
    }
}

impl FinalAuthorityCheck for UnexpectedCheck {
    fn check(&mut self, _input: &FinalCheckInput<'_>) -> Result<VerifiedDecision, GatewayError> {
        panic!("recovered freeze must refuse before final check")
    }

    fn settle(
        &mut self,
        _input: &FinalSettlementInput<'_>,
    ) -> Result<VerifiedSettlement, GatewayError> {
        panic!("recovered freeze has no mutation to settle")
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

    fn settle(
        &mut self,
        input: &FinalSettlementInput<'_>,
    ) -> Result<VerifiedSettlement, GatewayError> {
        if matches!(self.settlement, SettlementBehavior::Refuse) {
            return Err(GatewayError::Refused(
                "authority service unavailable".into(),
            ));
        }
        let mut acknowledgment = VerifiedSettlement {
            mutation_id: input.subject.mutation_id.clone(),
            reservation_id: input.subject.reservation_id.clone(),
            result_digest: input.result_digest.to_owned(),
            settlement_fingerprint: input.settlement_fingerprint,
        };
        match self.settlement {
            SettlementBehavior::ChangeMutation => acknowledgment.mutation_id = "mut_bad".into(),
            SettlementBehavior::ChangeReservation => {
                acknowledgment.reservation_id = "rsv_bad".into();
            }
            SettlementBehavior::ChangeDigest => acknowledgment.result_digest = "6".repeat(64),
            SettlementBehavior::ChangeFingerprint => {
                acknowledgment.settlement_fingerprint = Digest::of(b"wrong settlement");
            }
            SettlementBehavior::Exact | SettlementBehavior::Refuse => {}
        }
        Ok(acknowledgment)
    }
}

fn subject() -> MutationSubject {
    let request_digest = transport_fingerprint(
        MutationOperation::ApplyPatch,
        &serde_json::json!({"paseto": "fixture"}),
        &serde_json::json!({"path": "src/lib.rs"}),
    )
    .expect("fixture fingerprint")
    .to_hex();
    MutationSubject {
        authority_envelope_digest: "a".repeat(64),
        authority_token_nonce: "b".repeat(64),
        mutation_id: format!("mut_{}", "1".repeat(64)),
        reservation_id: format!("rsv_{}", "2".repeat(64)),
        operation: MutationOperation::ApplyPatch,
        request_digest,
        repository_id: format!("rep_{}", "4".repeat(64)),
        workspace_id: format!("wsp_{}", "5".repeat(64)),
        workspace_generation: 6,
        workspace_nonce: hex::encode(WRITER_NONCE),
        attempt_id: format!("atm_{}", "8".repeat(64)),
        attempt_fence: 9,
        authority_epoch: 10,
        freeze_generation: 0,
        permit_nonce: "c".repeat(64),
        permit_digest: "4".repeat(64),
    }
}

fn gateway(temp: &TempDir, expires: u64, mutate: bool) -> AuthorityGateway {
    gateway_with_settlement(temp, expires, mutate, SettlementBehavior::Exact)
}

fn gateway_with_settlement(
    temp: &TempDir,
    expires: u64,
    mutate: bool,
    settlement: SettlementBehavior,
) -> AuthorityGateway {
    AuthorityGateway {
        checker: Box::new(FixedCheck {
            subject: subject(),
            expires_at_unix_ms: expires,
            mutate_fingerprint: mutate,
            settlement,
        }),
        clock: Box::new(FixedClock(100)),
        ledger: Some(MutationLedger::open(temp.path()).expect("ledger")),
        ledger_root: None,
    }
}

fn refused(result: Result<MutationPermit, GatewayError>) -> GatewayError {
    match result {
        Ok(_) => panic!("unexpected permit"),
        Err(error) => error,
    }
}

fn consume(gateway: &mut AuthorityGateway) -> PendingMutation {
    let authority = serde_json::json!({"paseto": "fixture"});
    let params = serde_json::json!({"path": "src/lib.rs"});
    gateway
        .authorize(
            MutationOperation::ApplyPatch,
            &authority,
            &params,
            &subject().attempt_id,
            subject().attempt_fence,
            &WRITER_NONCE,
        )
        .expect("permit")
        .consume(MutationOperation::ApplyPatch, &authority, &params, 101)
        .expect("consume")
}

#[path = "authority_gateway_tests/authorization.rs"]
mod authorization;
#[path = "authority_gateway_tests/settlement.rs"]
mod settlement;
