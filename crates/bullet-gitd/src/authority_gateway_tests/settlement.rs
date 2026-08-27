use super::*;

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
