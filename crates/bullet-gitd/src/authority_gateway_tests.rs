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

#[test]
fn unavailable_production_gateway_never_returns_a_permit() {
    let mut gateway = AuthorityGateway::unavailable();
    let error = refused(gateway.authorize(
        MutationOperation::ApplyPatch,
        &serde_json::json!({"paseto": "forged"}),
        &serde_json::json!({"path": "src/lib.rs"}),
        &subject().attempt_id,
        subject().attempt_fence,
        &WRITER_NONCE,
    ));
    assert_eq!(error.reason_code(), "AUTHORITY_CONTRACT_UNAVAILABLE");
}

#[test]
fn recovered_freeze_refuses_before_online_final_check() {
    let temp = tempfile::tempdir().expect("tempdir");
    MutationLedger::open(temp.path())
        .expect("open")
        .reserve(&subject())
        .expect("reserve");
    let mut gateway = AuthorityGateway {
        checker: Box::new(UnexpectedCheck),
        clock: Box::new(FixedClock(100)),
        ledger: Some(MutationLedger::open(temp.path()).expect("reopen")),
    };
    let error = refused(gateway.authorize(
        MutationOperation::ApplyPatch,
        &serde_json::json!({"paseto": "never sent"}),
        &serde_json::json!({"path": "src/lib.rs"}),
        &subject().attempt_id,
        subject().attempt_fence,
        &WRITER_NONCE,
    ));
    assert_eq!(error.reason_code(), "MUTATION_OUTCOME_UNKNOWN");
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
        &subject().attempt_id,
        subject().attempt_fence,
        &WRITER_NONCE,
    ));
    assert_eq!(error.reason_code(), "AUTHORITY_SUBJECT_MISMATCH");

    let expired_temp = tempfile::tempdir().expect("tempdir");
    let error = refused(gateway(&expired_temp, 100, false).authorize(
        MutationOperation::ApplyPatch,
        &authority,
        &params,
        &subject().attempt_id,
        subject().attempt_fence,
        &WRITER_NONCE,
    ));
    assert_eq!(error.reason_code(), "MUTATION_PERMIT_EXPIRED");

    let changed = serde_json::json!({"path": "src/other.rs"});
    for (operation, presented_authority, presented_params) in [
        (
            MutationOperation::Checkpoint,
            authority.clone(),
            params.clone(),
        ),
        (
            MutationOperation::ApplyPatch,
            serde_json::json!({"paseto": "changed"}),
            params.clone(),
        ),
        (MutationOperation::ApplyPatch, authority.clone(), changed),
    ] {
        let live_temp = tempfile::tempdir().expect("tempdir");
        let mut live = gateway(&live_temp, 200, false);
        let permit = live
            .authorize(
                MutationOperation::ApplyPatch,
                &authority,
                &params,
                &subject().attempt_id,
                subject().attempt_fence,
                &WRITER_NONCE,
            )
            .expect("permit");
        let error = match permit.consume(operation, &presented_authority, &presented_params, 101) {
            Ok(_) => panic!("changed request consumed"),
            Err(error) => error,
        };
        assert_eq!(error.reason_code(), "AUTHORITY_SUBJECT_MISMATCH");
    }

    let digest_temp = tempfile::tempdir().expect("tempdir");
    let changed_subject = MutationSubject {
        request_digest: "0".repeat(64),
        ..subject()
    };
    let mut digest_gateway = AuthorityGateway {
        checker: Box::new(FixedCheck {
            subject: changed_subject,
            expires_at_unix_ms: 200,
            mutate_fingerprint: false,
            settlement: SettlementBehavior::Exact,
        }),
        clock: Box::new(UnexpectedClock),
        ledger: Some(MutationLedger::open(digest_temp.path()).expect("ledger")),
    };

    let error = refused(digest_gateway.authorize(
        MutationOperation::ApplyPatch,
        &serde_json::json!({"paseto": "fixture"}),
        &serde_json::json!({"path": "src/lib.rs"}),
        &subject().attempt_id,
        subject().attempt_fence,
        &WRITER_NONCE,
    ));

    assert_eq!(error.reason_code(), "AUTHORITY_SUBJECT_MISMATCH");
    assert_eq!(
        digest_temp.path().read_dir().expect("ledger dir").count(),
        0
    );
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
        &subject().attempt_id,
        subject().attempt_fence,
        &WRITER_NONCE,
    ));
    assert_eq!(error.reason_code(), "AUTHORITY_REFUSED");
    assert_eq!(temp.path().read_dir().expect("ledger dir").count(), 0);
}

#[test]
fn exact_online_acknowledgment_durably_settles_consumed_permit() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut live = gateway(&temp, 200, false);
    let pending = consume(&mut live);
    live.settle(pending, MutationOutcome::Committed, RESULT_DIGEST)
        .expect("settle");

    let error = refused(live.authorize(
        MutationOperation::ApplyPatch,
        &serde_json::json!({"paseto": "fixture"}),
        &serde_json::json!({"path": "src/lib.rs"}),
        &subject().attempt_id,
        subject().attempt_fence,
        &WRITER_NONCE,
    ));
    assert_eq!(error.reason_code(), "AUTHORITY_REFUSED");
}

#[test]
fn settlement_outage_or_changed_acknowledgment_is_unknown_and_stays_in_flight() {
    for behavior in [
        SettlementBehavior::Refuse,
        SettlementBehavior::ChangeMutation,
        SettlementBehavior::ChangeReservation,
        SettlementBehavior::ChangeDigest,
        SettlementBehavior::ChangeFingerprint,
    ] {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut live = gateway_with_settlement(&temp, 200, false, behavior);
        let pending = consume(&mut live);
        let error = live
            .settle(pending, MutationOutcome::Committed, RESULT_DIGEST)
            .expect_err("settlement must fail closed");
        assert_eq!(error.reason_code(), "MUTATION_OUTCOME_UNKNOWN");

        let mut reopened = MutationLedger::open(temp.path()).expect("reopen");
        let replay = reopened.reserve(&subject()).expect_err("in flight");
        assert_eq!(replay.reason_code(), "MUTATION_OUTCOME_UNKNOWN");
    }
}

#[test]
fn settlement_fingerprint_is_sensitive_to_every_bound_field() {
    let exact = subject();
    let expected = settlement_fingerprint(&exact, MutationOutcome::Committed, RESULT_DIGEST, 100);
    let changed_subjects = [
        MutationSubject {
            authority_envelope_digest: "0".repeat(64),
            ..exact.clone()
        },
        MutationSubject {
            authority_token_nonce: "0".repeat(64),
            ..exact.clone()
        },
        MutationSubject {
            mutation_id: format!("mut_{}", "0".repeat(64)),
            ..exact.clone()
        },
        MutationSubject {
            reservation_id: format!("rsv_{}", "0".repeat(64)),
            ..exact.clone()
        },
        MutationSubject {
            operation: MutationOperation::Checkpoint,
            ..exact.clone()
        },
        MutationSubject {
            request_digest: "0".repeat(64),
            ..exact.clone()
        },
        MutationSubject {
            repository_id: format!("rep_{}", "0".repeat(64)),
            ..exact.clone()
        },
        MutationSubject {
            workspace_id: format!("wsp_{}", "0".repeat(64)),
            ..exact.clone()
        },
        MutationSubject {
            workspace_generation: 7,
            ..exact.clone()
        },
        MutationSubject {
            workspace_nonce: "0".repeat(64),
            ..exact.clone()
        },
        MutationSubject {
            attempt_id: format!("atm_{}", "0".repeat(64)),
            ..exact.clone()
        },
        MutationSubject {
            attempt_fence: 10,
            ..exact.clone()
        },
        MutationSubject {
            authority_epoch: 11,
            ..exact.clone()
        },
        MutationSubject {
            freeze_generation: 1,
            ..exact.clone()
        },
        MutationSubject {
            permit_nonce: "0".repeat(64),
            ..exact.clone()
        },
        MutationSubject {
            permit_digest: "0".repeat(64),
            ..exact.clone()
        },
    ];
    for changed in changed_subjects {
        assert_ne!(
            settlement_fingerprint(&changed, MutationOutcome::Committed, RESULT_DIGEST, 100,),
            expected
        );
    }
    for outcome in [MutationOutcome::Aborted, MutationOutcome::Unknown] {
        assert_ne!(
            settlement_fingerprint(&exact, outcome, RESULT_DIGEST, 100),
            expected
        );
    }
    assert_ne!(
        settlement_fingerprint(&exact, MutationOutcome::Committed, &"6".repeat(64), 100),
        expected
    );
    assert_ne!(
        settlement_fingerprint(&exact, MutationOutcome::Committed, RESULT_DIGEST, 101),
        expected
    );
}

#[test]
fn malformed_settlement_digest_never_reaches_online_or_local_success() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut live = gateway(&temp, 200, false);
    let pending = consume(&mut live);
    let error = live
        .settle(pending, MutationOutcome::Committed, &"A".repeat(64))
        .expect_err("uppercase digest");
    assert_eq!(error.reason_code(), "MUTATION_OUTCOME_UNKNOWN");
}

#[test]
fn changed_writer_incarnation_creates_no_reservation_or_permit() {
    for changed in [
        MutationSubject {
            attempt_id: format!("atm_{}", "6".repeat(64)),
            ..subject()
        },
        MutationSubject {
            attempt_fence: 11,
            ..subject()
        },
        MutationSubject {
            workspace_nonce: "6".repeat(64),
            ..subject()
        },
    ] {
        let temp = tempfile::tempdir().expect("tempdir");
        let mut gateway = AuthorityGateway {
            checker: Box::new(FixedCheck {
                subject: changed,
                expires_at_unix_ms: 200,
                mutate_fingerprint: false,
                settlement: SettlementBehavior::Exact,
            }),
            clock: Box::new(FixedClock(100)),
            ledger: Some(MutationLedger::open(temp.path()).expect("ledger")),
        };
        let error = refused(gateway.authorize(
            MutationOperation::ApplyPatch,
            &serde_json::json!({"paseto": "fixture"}),
            &serde_json::json!({"path": "src/lib.rs"}),
            &subject().attempt_id,
            subject().attempt_fence,
            &WRITER_NONCE,
        ));
        assert_eq!(error.reason_code(), "AUTHORITY_SUBJECT_MISMATCH");
        assert_eq!(temp.path().read_dir().expect("ledger dir").count(), 0);
    }
}
