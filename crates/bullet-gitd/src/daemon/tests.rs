use super::*;

#[test]
fn indeterminate_daemon_refuses_later_mutation_before_authority() {
    let mut daemon = Daemon::new();
    daemon.mutation_frozen = true;
    let request = Request {
        id: json!(1),
        method: "apply_change".into(),
        token: json!({"paseto": "never consulted"}),
        params: json!({"patches": []}),
    };
    let token = WireAuthorityToken {
        variant_id: "var_test".into(),
        attempt_id: "atm_test".into(),
        attempt_fence: 1,
        workspace_nonce: [7; 32],
    };
    let error = match daemon.authorize_mutation(&request, MutationOperation::ApplyPatch, &token) {
        Ok(_) => panic!("frozen daemon returned a permit"),
        Err(error) => error,
    };
    assert_eq!(error.0, "MUTATION_OUTCOME_UNKNOWN");
}

#[test]
fn malformed_apply_proposal_is_a_typed_bad_request() {
    let bad = json!({
        "proposal": {
            "schema_version": 1,
            "proposal_id": "cnt_short",
            "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
            "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
            "base_checkpoint_digest": "4".repeat(64),
            "operations": [],
            "gate_ids": [format!("gat_{}", "5".repeat(64))]
        }
    });
    let error = parse_params::<ApplyProposalParams>(&bad).expect_err("malformed refused");
    assert_eq!(error.0, "BAD_REQUEST");
}

fn valid_prepare_params() -> Value {
    json!({
        "candidate_preparation_grant": {
            "schema_version": "v1alpha1",
            "issuer": "kernel-local",
            "key_id": "candidate-preparation-1",
            "paseto": "structurally-opaque-until-kernel-final-check"
        },
        "change": {
            "id": format!("chg_{}", "1".repeat(64)),
            "mission": "exact mission subject",
            "acceptance_root": "2".repeat(64)
        },
        "provenance": {
            "schema_version": 1,
            "repository_id": format!("rep_{}", "3".repeat(64)),
            "producing_attempt_id": format!("atm_{}", "4".repeat(64)),
            "attempt_fence": 9,
            "work_package_id": format!("wpk_{}", "5".repeat(64)),
            "variant_id": format!("var_{}", "6".repeat(64)),
            "plan_revision_id": format!("pln_{}", "7".repeat(64)),
            "graph_revision_id": format!("grf_{}", "8".repeat(64)),
            "base_checkpoint_id": format!("ckp_{}", "9".repeat(64)),
            "base_commit": format!("sha1:{}", "a".repeat(40)),
            "parent_candidate_ids": [format!("can_{}", "b".repeat(64))],
            "granted_scope": ["src"],
            "context_capsule_id": format!("cnt_{}", "c".repeat(64)),
            "configuration_snapshot_id": format!("cnt_{}", "d".repeat(64)),
            "policy_snapshot_id": format!("cnt_{}", "e".repeat(64)),
            "routing_snapshot_id": format!("cnt_{}", "f".repeat(64)),
            "environment_digest": "1".repeat(64),
            "toolchain_digest": "2".repeat(64)
        }
    })
}

#[test]
fn prepare_candidate_requires_the_complete_strict_provenance_shape() {
    let valid = valid_prepare_params();
    let parsed = parse_params::<PrepareParams>(&valid).expect("strict params");
    assert_eq!(
        serde_json::to_value(&parsed.candidate_preparation_grant).expect("generated carrier"),
        valid["candidate_preparation_grant"],
        "structural decoding must preserve the exact carrier fields for Kernel final check"
    );

    let legacy = json!({"change_seed": "demo", "mission": "synthetic"});
    assert_eq!(
        parse_params::<PrepareParams>(&legacy)
            .expect_err("legacy shape refused")
            .0,
        "BAD_REQUEST"
    );

    let keys = valid["provenance"]
        .as_object()
        .expect("provenance object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    for key in keys {
        let mut missing = valid.clone();
        missing["provenance"]
            .as_object_mut()
            .expect("provenance object")
            .remove(&key);
        assert_eq!(
            parse_params::<PrepareParams>(&missing)
                .expect_err("missing provenance refused")
                .0,
            "BAD_REQUEST",
            "field {key} received a default"
        );
    }

    let carrier_keys = valid["candidate_preparation_grant"]
        .as_object()
        .expect("carrier object")
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    for key in carrier_keys {
        let mut missing = valid.clone();
        missing["candidate_preparation_grant"]
            .as_object_mut()
            .expect("carrier object")
            .remove(&key);
        assert_eq!(
            parse_params::<PrepareParams>(&missing)
                .expect_err("partial carrier refused")
                .0,
            "BAD_REQUEST",
            "carrier field {key} received a default"
        );
    }

    for malformed in [Value::Null, json!("signed-string"), json!([])] {
        let mut request = valid.clone();
        request["candidate_preparation_grant"] = malformed;
        assert_eq!(
            parse_params::<PrepareParams>(&request)
                .expect_err("non-record carrier refused")
                .0,
            "BAD_REQUEST"
        );
    }

    let mut missing_carrier = valid.clone();
    missing_carrier
        .as_object_mut()
        .expect("params object")
        .remove("candidate_preparation_grant");
    assert_eq!(
        parse_params::<PrepareParams>(&missing_carrier)
            .expect_err("missing carrier refused")
            .0,
        "BAD_REQUEST"
    );

    let mut unknown = valid.clone();
    unknown["provenance"]["model_commentary"] = json!("not authority");
    assert_eq!(
        parse_params::<PrepareParams>(&unknown)
            .expect_err("unknown provenance refused")
            .0,
        "BAD_REQUEST"
    );

    let mut nested_unknown = valid.clone();
    nested_unknown["candidate_preparation_grant"]["authenticated"] = json!(true);
    assert_eq!(
        parse_params::<PrepareParams>(&nested_unknown)
            .expect_err("caller trust claim refused")
            .0,
        "BAD_REQUEST"
    );

    let mut top_level_unknown = valid;
    top_level_unknown["legacy_candidate_authority"] = json!(true);
    assert_eq!(
        parse_params::<PrepareParams>(&top_level_unknown)
            .expect_err("legacy authority field refused")
            .0,
        "BAD_REQUEST"
    );
}
