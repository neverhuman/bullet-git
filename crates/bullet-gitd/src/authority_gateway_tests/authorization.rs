use super::*;

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
        ledger_root: None,
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

    let lazy_root = tempfile::tempdir().expect("lazy root");
    MutationLedger::open(lazy_root.path().join(".bullet-mutation-ledger"))
        .expect("open lazy ledger")
        .reserve(&subject())
        .expect("reserve lazy ledger");
    let mut lazy_gateway = AuthorityGateway {
        checker: Box::new(UnexpectedCheck),
        clock: Box::new(FixedClock(100)),
        ledger: None,
        ledger_root: Some(lazy_root.path().to_path_buf()),
    };
    let error = refused(lazy_gateway.authorize(
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
        ledger_root: None,
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
        ledger_root: None,
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

    let lazy_root = tempfile::tempdir().expect("lazy root");
    let mut lazy_gateway = AuthorityGateway {
        checker: Box::new(SupersededCheck),
        clock: Box::new(FixedClock(100)),
        ledger: None,
        ledger_root: Some(lazy_root.path().to_path_buf()),
    };
    let error = refused(lazy_gateway.authorize(
        MutationOperation::ApplyPatch,
        &serde_json::json!({"paseto": "superseded"}),
        &serde_json::json!({"path": "src/lib.rs"}),
        &subject().attempt_id,
        subject().attempt_fence,
        &WRITER_NONCE,
    ));
    assert_eq!(error.reason_code(), "AUTHORITY_REFUSED");
    assert!(!lazy_root.path().join(".bullet-mutation-ledger").exists());
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
            ledger_root: None,
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
