use super::*;
use std::collections::VecDeque;
use std::sync::Mutex;

struct AbortClock(Mutex<VecDeque<u64>>);

impl Clock for AbortClock {
    fn now_unix_ms(&self) -> Result<u64, GatewayError> {
        self.0
            .lock()
            .map_err(|_| GatewayError::Clock("abort clock poisoned".into()))?
            .pop_front()
            .ok_or_else(|| GatewayError::Clock("abort clock exhausted".into()))
    }
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
    assert_ambiguous_pre_repository_abort_latches_unknown();
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

fn assert_ambiguous_pre_repository_abort_latches_unknown() {
    for behavior in [
        SettlementBehavior::Refuse,
        SettlementBehavior::ChangeMutation,
        SettlementBehavior::ChangeReservation,
        SettlementBehavior::ChangeDigest,
        SettlementBehavior::ChangeFingerprint,
    ] {
        let temp = tempfile::tempdir().expect("tempdir");
        let authority = serde_json::json!({"paseto": "fixture"});
        let params = serde_json::json!({"path": "src/lib.rs"});
        let mut live = AuthorityGateway {
            checker: Box::new(FixedCheck {
                subject: subject(),
                expires_at_unix_ms: 200,
                mutate_fingerprint: false,
                settlement: behavior,
            }),
            clock: Box::new(AbortClock(Mutex::new([100, 200, 201].into()))),
            ledger: Some(MutationLedger::open(temp.path()).expect("ledger")),
            ledger_root: None,
        };
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
        let error = match live.consume(permit, MutationOperation::ApplyPatch, &authority, &params) {
            Ok(_) => panic!("ambiguous abort reached repository I/O"),
            Err(error) => error,
        };
        assert_eq!(error.reason_code(), "MUTATION_OUTCOME_UNKNOWN");
        let error = refused(live.authorize(
            MutationOperation::ApplyPatch,
            &authority,
            &params,
            &subject().attempt_id,
            subject().attempt_fence,
            &WRITER_NONCE,
        ));
        assert_eq!(error.reason_code(), "MUTATION_OUTCOME_UNKNOWN");
        drop(live);

        let restarted = MutationLedger::open(temp.path()).expect("restart");
        assert!(restarted.recovery_status().is_frozen());
        assert_eq!(restarted.recovery_status().indeterminate().len(), 1);
    }
}
