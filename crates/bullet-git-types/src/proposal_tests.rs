//! Unit proofs extracted from the parent module.

use super::*;

fn proposal(operations: Vec<PatchOperation>) -> PatchProposal {
    PatchProposal {
        schema_version: PATCH_PROPOSAL_SCHEMA_VERSION,
        proposal_id: ContentId::from_seed("proposal"),
        producing_attempt_id: AttemptId::from_seed("attempt"),
        base_checkpoint_id: CheckpointId::from_seed("checkpoint"),
        base_checkpoint_digest: Digest::of(b"checkpoint"),
        operations,
        gate_ids: vec![GateId::from_seed("gate")],
    }
}

fn write(path: &str, preimage: Preimage) -> PatchOperation {
    write_with_content(path, preimage, "next".into())
}

fn write_with_content(path: &str, preimage: Preimage, content_utf8: String) -> PatchOperation {
    PatchOperation {
        path: path.parse().expect("path"),
        preimage,
        mutation: PatchMutation::Write { content_utf8 },
    }
}

#[test]
fn canonical_json_shape_round_trips_and_denies_unknown_fields() {
    let expected = serde_json::json!({
        "schema_version": 1,
        "proposal_id": format!("cnt_{}", "1".repeat(64)),
        "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
        "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
        "base_checkpoint_digest": "04".repeat(32),
        "operations": [{
            "path": "PONG.txt",
            "preimage": { "kind": "absent" },
            "mutation": { "kind": "write", "content_utf8": "PONG\n" }
        }],
        "gate_ids": [format!("gat_{}", "5".repeat(64))]
    });
    assert_eq!(expected.as_object().expect("object").len(), 7);

    let proposal = serde_json::from_value::<PatchProposal>(expected.clone()).expect("decode");
    proposal.validate().expect("validate");
    assert_eq!(serde_json::to_value(&proposal).expect("encode"), expected);

    let mut unknown = serde_json::to_value(&proposal).expect("encode");
    unknown["model_comment"] = serde_json::json!("not authoritative");
    assert!(serde_json::from_value::<PatchProposal>(unknown).is_err());
}

#[test]
fn ids_digests_paths_and_semantics_fail_closed() {
    let valid = serde_json::to_value(proposal(vec![write("src/lib.rs", Preimage::Absent)]))
        .expect("encode");
    for (pointer, replacement) in [
        ("/proposal_id", serde_json::json!("cnt_short")),
        ("/producing_attempt_id", serde_json::json!("atm_short")),
        ("/base_checkpoint_id", serde_json::json!("ckp_short")),
        ("/base_checkpoint_digest", serde_json::json!("A".repeat(64))),
        ("/gate_ids/0", serde_json::json!("gat_short")),
        ("/operations/0/path", serde_json::json!("src/../escape")),
    ] {
        let mut bad = valid.clone();
        *bad.pointer_mut(pointer).expect("pointer") = replacement;
        assert!(
            serde_json::from_value::<PatchProposal>(bad).is_err(),
            "accepted malformed {pointer}"
        );
    }

    let mut empty_gates = proposal(vec![write("src/lib.rs", Preimage::Absent)]);
    empty_gates.gate_ids.clear();
    assert_eq!(
        empty_gates
            .validate()
            .expect_err("gate required")
            .reason_code(),
        "GATE_REQUIRED"
    );
    for (parent, child) in [
        ("src", "src/lib.rs"),
        ("Src", "src/lib.rs"),
        ("Étage", "étage/file.rs"),
    ] {
        let conflict = proposal(vec![
            write(parent, Preimage::Absent),
            write(child, Preimage::Absent),
        ]);
        assert_eq!(
            conflict.validate().expect_err("conflict").reason_code(),
            "PATH_CONFLICT",
            "accepted portable ancestor conflict {parent:?} and {child:?}"
        );
    }

    let exact_path_bound = proposal(
        (0..MAX_PATCH_OPERATIONS)
            .map(|index| write(&format!("src/{index}.rs"), Preimage::Absent))
            .collect(),
    );
    exact_path_bound.validate().expect("exact path bound");
    let over_path_bound = proposal(
        (0..=MAX_PATCH_OPERATIONS)
            .map(|index| write(&format!("src/{index}.rs"), Preimage::Absent))
            .collect(),
    );
    assert_eq!(
        over_path_bound
            .validate()
            .expect_err("operation bound")
            .reason_code(),
        "INVALID_OPERATION_COUNT"
    );

    let full_files = MAX_AGGREGATE_CONTENT_BYTES / MAX_CONTENT_BYTES;
    let aggregate_bound = (0..full_files)
        .map(|index| {
            write_with_content(
                &format!("src/aggregate-{index}.txt"),
                Preimage::Absent,
                "x".repeat(MAX_CONTENT_BYTES),
            )
        })
        .collect::<Vec<_>>();
    proposal(aggregate_bound.clone())
        .validate()
        .expect("exact aggregate bound");
    let mut over_aggregate_bound = aggregate_bound;
    over_aggregate_bound.push(write_with_content(
        "src/one-byte-over.txt",
        Preimage::Absent,
        "x".into(),
    ));
    assert_eq!(
        proposal(over_aggregate_bound)
            .validate()
            .expect_err("aggregate bound")
            .reason_code(),
        "AGGREGATE_CONTENT_TOO_LARGE"
    );
}
