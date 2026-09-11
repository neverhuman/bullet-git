//! Exact report mutations, not native execution or source-custody evidence.
use super::*;
use serde_json::json;

const POLICY: &[u8] = b"minimum_score = 85\nfail_on = [\"critical\", \"high\"]\nadvisory_on = [\"medium\", \"low\"]\n";
fn report(policy: &[u8]) -> Value {
    let policy = Policy::parse(policy).unwrap();
    json!({"score": 90, "policy": {"minimum_score": policy.minimum,
        "fail_on": policy.fail_on, "advisory_on": policy.advisory_on, "mode": "standard"},
        "policy_fingerprint": policy.fingerprint, "decision": {"passed": true, "status": "pass",
            "minimum_score": policy.minimum, "hard_findings": 0}, "findings": [], "caps_applied": [],
        "report_fingerprint": "sha256:fixture-report", "input_fingerprint": "sha256:fixture-input",
        "schema_version": "fixture-schema", "standard_version": "fixture-standard"})
}
fn ratchet() -> (Value, Value) {
    let mut baseline = report(POLICY);
    baseline["score"] = json!(89);
    let mut current = report(POLICY);
    current["policy"]["mode"] = json!("ratchet");
    current["decision"]["ratchet"] = json!({"passed": true, "allowed_drop": 0,
        "baseline_score": 89, "score_delta": 1, "new_caps": [], "new_hard_findings": [],
        "policy_changed": false, "baseline_report_fingerprint": baseline["report_fingerprint"],
        "baseline_input_fingerprint": baseline["input_fingerprint"],
        "baseline_policy_fingerprint": baseline["policy_fingerprint"]});
    (current, baseline)
}

#[test]
fn standard_report_preserves_unknown_native_fields() {
    let mut current = report(POLICY);
    current["native_history"] = json!({"future": [1, true, null]});
    let bytes = serde_json::to_vec(&current).unwrap();
    let decoded = decode(&bytes).unwrap();
    assert_eq!(decoded, current);
    assert!(validate(&decoded, POLICY, None).is_ok());
}
#[test]
fn lowered_report_threshold_cannot_replace_source_policy() {
    let mut current = report(POLICY);
    current["policy"]["minimum_score"] = json!(70);
    current["decision"]["minimum_score"] = json!(70);
    assert_eq!(
        validate(&current, POLICY, None).unwrap_err(),
        "REPORT_POLICY_MISMATCH:minimum_score"
    );
}
#[test]
fn severity_and_advisory_lists_bind_exact_source_values() {
    for (key, value) in [
        ("fail_on", json!(["critical"])),
        ("advisory_on", json!([])),
        ("fail_on", json!(["high", "critical"])),
    ] {
        let mut current = report(POLICY);
        current["policy"][key] = value;
        assert_eq!(
            validate(&current, POLICY, None).unwrap_err(),
            format!("REPORT_POLICY_MISMATCH:{key}")
        );
    }
}
#[test]
fn policy_fingerprint_binds_raw_comments_and_newlines() {
    let current = report(POLICY);
    let changed = [POLICY, b"# byte-distinct\n"].concat();
    assert_eq!(
        validate(&current, &changed, None).unwrap_err(),
        "POLICY_FINGERPRINT_MISMATCH"
    );
    assert!(validate(&report(&changed), &changed, None).is_ok());
}
#[test]
fn source_floor_is_fixed_but_legitimate_threshold_raises_work() {
    for value in ["64", "true", "65.0"] {
        let source = String::from_utf8(POLICY.to_vec())
            .unwrap()
            .replace("85", value);
        assert_eq!(
            validate(&report(POLICY), source.as_bytes(), None).unwrap_err(),
            "SOURCE_POLICY_BELOW_FLOOR"
        );
    }
    let raised = String::from_utf8(POLICY.to_vec())
        .unwrap()
        .replace("85", "90");
    assert!(validate(&report(raised.as_bytes()), raised.as_bytes(), None).is_ok());
    let high = raised.replace("90", "91");
    assert_eq!(
        validate(&report(high.as_bytes()), high.as_bytes(), None).unwrap_err(),
        "REPORT_DECISION_NOT_PASSING"
    );
}
#[test]
fn scores_and_decision_counts_require_integer_json() {
    for value in [json!(true), json!(90.0), json!("90"), json!(84)] {
        let mut current = report(POLICY);
        current["score"] = value;
        assert_eq!(
            validate(&current, POLICY, None).unwrap_err(),
            "REPORT_DECISION_NOT_PASSING"
        );
    }
    let mut current = report(POLICY);
    current["decision"]["hard_findings"] = json!(false);
    assert_eq!(
        validate(&current, POLICY, None).unwrap_err(),
        "REPORT_DECISION_NOT_PASSING"
    );
}
#[test]
fn contradictory_success_and_hidden_hard_findings_refuse() {
    for (key, value) in [
        ("passed", json!(false)),
        ("status", json!("fail")),
        ("hard_findings", json!(1)),
        ("minimum_score", json!(70)),
    ] {
        let mut current = report(POLICY);
        current["decision"][key] = value;
        assert_eq!(
            validate(&current, POLICY, None).unwrap_err(),
            "REPORT_DECISION_NOT_PASSING"
        );
    }
    let mut current = report(POLICY);
    current["findings"] = json!([{"severity": "high"}]);
    assert_eq!(
        validate(&current, POLICY, None).unwrap_err(),
        "HARD_FINDING_IN_PASS"
    );
}
#[test]
fn mode_requires_the_selected_baseline() {
    let (mut current, baseline) = ratchet();
    assert_eq!(
        validate(&current, POLICY, None).unwrap_err(),
        "REPORT_MODE_MISMATCH"
    );
    current["policy"]["mode"] = json!("standard");
    assert_eq!(
        validate(&current, POLICY, Some(&baseline)).unwrap_err(),
        "REPORT_MODE_MISMATCH"
    );
}
#[test]
fn ratchet_accepts_raise_and_refuses_drop_above_source_floor() {
    let (mut current, baseline) = ratchet();
    assert!(validate(&current, POLICY, Some(&baseline)).is_ok());
    current["score"] = json!(88);
    assert_eq!(
        validate(&current, POLICY, Some(&baseline)).unwrap_err(),
        "RATCHET_SCORE_DROP"
    );
}
#[test]
fn ratchet_claims_must_match_actual_score_and_empty_new_findings() {
    for (key, value) in [
        ("passed", json!(false)),
        ("allowed_drop", json!(1)),
        ("allowed_drop", json!(false)),
        ("baseline_score", json!(88)),
        ("score_delta", json!(0)),
        ("new_caps", json!(["cap"])),
        ("new_hard_findings", json!(["finding"])),
        ("policy_changed", json!(true)),
    ] {
        let (mut current, baseline) = ratchet();
        current["decision"]["ratchet"][key] = value;
        assert_eq!(
            validate(&current, POLICY, Some(&baseline)).unwrap_err(),
            "RATCHET_DECISION_MISMATCH"
        );
    }
}
#[test]
fn baseline_identity_and_version_are_independent_ratchet_bindings() {
    for key in [
        "report_fingerprint",
        "input_fingerprint",
        "policy_fingerprint",
    ] {
        let (mut current, baseline) = ratchet();
        current["decision"]["ratchet"][format!("baseline_{key}")] = json!("foreign");
        assert_eq!(
            validate(&current, POLICY, Some(&baseline)).unwrap_err(),
            "RATCHET_BASELINE_MISMATCH"
        );
    }
    for key in ["schema_version", "standard_version"] {
        let (mut current, baseline) = ratchet();
        current[key] = json!("foreign");
        assert_eq!(
            validate(&current, POLICY, Some(&baseline)).unwrap_err(),
            "RATCHET_POLICY_OR_VERSION_DRIFT"
        );
    }
}
#[test]
fn actual_new_cap_refuses_even_when_ratchet_claims_none() {
    let (mut current, baseline) = ratchet();
    current["caps_applied"] = json!(["undeclared-cap"]);
    assert_eq!(
        validate(&current, POLICY, Some(&baseline)).unwrap_err(),
        "RATCHET_NEW_CAP"
    );
}
#[test]
fn malformed_policy_and_missing_report_fields_refuse() {
    assert!(validate(
        &report(POLICY),
        b"minimum_score = 85\nminimum_score = 90",
        None
    )
    .is_err());
    let mut current = report(POLICY);
    current.as_object_mut().unwrap().remove("decision");
    assert_eq!(
        validate(&current, POLICY, None).unwrap_err(),
        "REPORT_FIELD_MISSING:decision"
    );
}
#[test]
fn duplicate_json_keys_refuse_at_every_depth_after_escape_decoding() {
    for bytes in [
        br#"{"score":90,"score":70}"#.as_slice(),
        br#"{"nested":[{"score":90,"score":70}]}"#,
        br#"{"score":90,"\u0073core":70}"#,
    ] {
        assert!(decode(bytes)
            .unwrap_err()
            .contains("DUPLICATE_JSON_KEY:score"));
    }
}
#[test]
fn malformed_nonfinite_trailing_and_excessive_depth_json_refuse() {
    for bytes in [
        b"NaN".as_slice(),
        b"Infinity",
        b"1e999",
        b"{} {}",
        b"{",
        b"\xff",
    ] {
        assert!(decode(bytes).is_err());
    }
    let nested = format!("{}0{}", "[".repeat(200), "]".repeat(200));
    assert!(decode(nested.as_bytes()).is_err());
}
#[test]
fn json_size_limit_precedes_parsing() {
    assert_eq!(
        decode(&vec![b' '; 64 * 1024 * 1024 + 1]).unwrap_err(),
        "JSON_BYTE_LIMIT"
    );
}
