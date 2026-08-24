//! Durable replay and crash-uncertainty tests for the contract-independent
//! BulletGit mutation ledger. These tests issue no authority.

use bullet_gitd::mutation_ledger::{
    MutationLedger, MutationOperation, MutationOutcome, MutationSubject, ReplayDisposition,
};
use bullet_gitd::protocol::MAX_FRAME_BYTES;

fn subject() -> MutationSubject {
    MutationSubject {
        authority_envelope_digest: "a".repeat(64),
        authority_token_nonce: "b".repeat(64),
        mutation_id: format!("mut_{}", "1".repeat(64)),
        reservation_id: format!("rsv_{}", "2".repeat(64)),
        operation: MutationOperation::ApplyPatch,
        request_digest: "3".repeat(64),
        repository_id: format!("rep_{}", "4".repeat(64)),
        workspace_id: format!("wsp_{}", "5".repeat(64)),
        workspace_generation: 6,
        workspace_nonce: "7".repeat(64),
        attempt_id: format!("atm_{}", "8".repeat(64)),
        attempt_fence: 9,
        authority_epoch: 10,
        freeze_generation: 0,
        permit_nonce: "c".repeat(64),
        permit_digest: "4".repeat(64),
    }
}

#[test]
fn terminal_result_replays_exactly_without_a_second_reservation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let exact = subject();
    let mut ledger = MutationLedger::open(temp.path()).expect("open");
    assert_eq!(
        ledger.reserve(&exact).expect("reserve"),
        ReplayDisposition::Fresh
    );
    assert_eq!(
        ledger
            .settle(&exact, MutationOutcome::Committed, &"4".repeat(64), 101)
            .expect("settle"),
        ReplayDisposition::Fresh
    );

    let mut reopened = MutationLedger::open(temp.path()).expect("reopen");
    let ReplayDisposition::ExactReplay(result) = reopened.reserve(&exact).expect("replay") else {
        panic!("expected exact replay");
    };
    assert_eq!(result.subject, exact);
    assert_eq!(result.outcome, MutationOutcome::Committed);
    assert_eq!(result.result_digest, "4".repeat(64));
    assert_eq!(result.completed_at_unix_ms, 101);
}

#[test]
fn subject_or_result_mutation_is_a_replay_conflict() {
    let temp = tempfile::tempdir().expect("tempdir");
    let exact = subject();
    let mut ledger = MutationLedger::open(temp.path()).expect("open");
    ledger.reserve(&exact).expect("reserve");

    for changed in [
        MutationSubject {
            authority_envelope_digest: "6".repeat(64),
            ..exact.clone()
        },
        MutationSubject {
            authority_token_nonce: "6".repeat(64),
            ..exact.clone()
        },
        MutationSubject {
            reservation_id: format!("rsv_{}", "5".repeat(64)),
            ..exact.clone()
        },
        MutationSubject {
            operation: MutationOperation::Checkpoint,
            ..exact.clone()
        },
        MutationSubject {
            request_digest: "6".repeat(64),
            ..exact.clone()
        },
        MutationSubject {
            repository_id: format!("rep_{}", "6".repeat(64)),
            ..exact.clone()
        },
        MutationSubject {
            workspace_id: format!("wsp_{}", "6".repeat(64)),
            ..exact.clone()
        },
        MutationSubject {
            workspace_generation: 11,
            ..exact.clone()
        },
        MutationSubject {
            workspace_nonce: "6".repeat(64),
            ..exact.clone()
        },
        MutationSubject {
            attempt_id: format!("atm_{}", "6".repeat(64)),
            ..exact.clone()
        },
        MutationSubject {
            attempt_fence: 11,
            ..exact.clone()
        },
        MutationSubject {
            authority_epoch: 11,
            ..exact.clone()
        },
        MutationSubject {
            freeze_generation: 11,
            ..exact.clone()
        },
        MutationSubject {
            permit_nonce: "6".repeat(64),
            ..exact.clone()
        },
        MutationSubject {
            permit_digest: "6".repeat(64),
            ..exact.clone()
        },
    ] {
        let error = ledger.reserve(&changed).expect_err("conflict");
        assert_eq!(error.reason_code(), "AUTHORITY_REPLAY_CONFLICT");
    }

    ledger
        .settle(&exact, MutationOutcome::Committed, &"7".repeat(64), 102)
        .expect("settle");
    let error = ledger
        .settle(&exact, MutationOutcome::Committed, &"8".repeat(64), 102)
        .expect_err("result conflict");
    assert_eq!(error.reason_code(), "AUTHORITY_REPLAY_CONFLICT");
}

#[test]
fn restart_with_only_a_reservation_is_unknown_and_never_fresh() {
    let temp = tempfile::tempdir().expect("tempdir");
    let exact = subject();
    MutationLedger::open(temp.path())
        .expect("open")
        .reserve(&exact)
        .expect("reserve");

    let mut restarted = MutationLedger::open(temp.path()).expect("reopen");
    let error = restarted.reserve(&exact).expect_err("unknown");
    assert_eq!(error.reason_code(), "MUTATION_OUTCOME_UNKNOWN");
    let error = restarted
        .settle(&exact, MutationOutcome::Aborted, &"9".repeat(64), 103)
        .expect_err("cannot settle earlier process");
    assert_eq!(error.reason_code(), "MUTATION_OUTCOME_UNKNOWN");
}

#[test]
fn partial_or_hostile_records_and_ids_fail_closed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let exact = subject();
    let path = temp.path().join(format!("{}.jsonl", exact.mutation_id));
    std::fs::write(&path, b"{\"event\":\"reserved\"").expect("partial record");
    let mut ledger = MutationLedger::open(temp.path()).expect("open");
    let error = ledger.reserve(&exact).expect_err("corrupt is unknown");
    assert_eq!(error.reason_code(), "MUTATION_OUTCOME_UNKNOWN");

    let invalid = MutationSubject {
        mutation_id: "mut_../../escape".into(),
        ..exact
    };
    let error = ledger.reserve(&invalid).expect_err("invalid id");
    assert_eq!(error.reason_code(), "INVALID_MUTATION_SUBJECT");
    assert!(!temp.path().join("escape.jsonl").exists());
}

#[test]
fn every_malformed_authority_subject_field_fails_before_reservation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let exact = subject();
    let invalid = [
        MutationSubject {
            authority_envelope_digest: "not-a-digest".into(),
            ..exact.clone()
        },
        MutationSubject {
            authority_token_nonce: "not-a-nonce".into(),
            ..exact.clone()
        },
        MutationSubject {
            reservation_id: "rsv_../../escape".into(),
            ..exact.clone()
        },
        MutationSubject {
            request_digest: "not-a-digest".into(),
            ..exact.clone()
        },
        MutationSubject {
            repository_id: "rep_../../escape".into(),
            ..exact.clone()
        },
        MutationSubject {
            workspace_id: "wsp_../../escape".into(),
            ..exact.clone()
        },
        MutationSubject {
            workspace_generation: 0,
            ..exact.clone()
        },
        MutationSubject {
            workspace_nonce: "not-a-nonce".into(),
            ..exact.clone()
        },
        MutationSubject {
            attempt_id: "atm_../../escape".into(),
            ..exact.clone()
        },
        MutationSubject {
            attempt_fence: 0,
            ..exact.clone()
        },
        MutationSubject {
            authority_epoch: 9_007_199_254_740_992,
            ..exact.clone()
        },
        MutationSubject {
            freeze_generation: 9_007_199_254_740_992,
            ..exact.clone()
        },
        MutationSubject {
            permit_nonce: "not-a-nonce".into(),
            ..exact.clone()
        },
        MutationSubject {
            permit_digest: "not-a-digest".into(),
            ..exact
        },
    ];

    let mut ledger = MutationLedger::open(temp.path()).expect("open");
    for changed in invalid {
        let error = ledger.reserve(&changed).expect_err("invalid subject");
        assert_eq!(error.reason_code(), "INVALID_MUTATION_SUBJECT");
    }
    assert_eq!(temp.path().read_dir().expect("ledger directory").count(), 0);
}

#[test]
fn oversized_record_is_unknown_without_an_unbounded_parse() {
    let temp = tempfile::tempdir().expect("tempdir");
    let exact = subject();
    let path = temp.path().join(format!("{}.jsonl", exact.mutation_id));
    std::fs::write(path, vec![b'x'; MAX_FRAME_BYTES + 1]).expect("oversized record");

    let mut ledger = MutationLedger::open(temp.path()).expect("open");
    let error = ledger.reserve(&exact).expect_err("oversized is unknown");
    assert_eq!(error.reason_code(), "MUTATION_OUTCOME_UNKNOWN");
}
