//! Filesystem and native-record consumer cases; synthetic records grant no installed credit.
use super::{fixtures::*, *};
use std::fs;

#[test]
fn capture_check_exact_subject_and_one_use() {
    let f = Fixture::new();
    assert_eq!(f.capture(0).unwrap(), 0);
    f.check().unwrap();
    assert_eq!(f.saved()["tools"]["audit"]["native_returncode"], 0);
    let original = f.read("observation.json");
    assert!(f.capture(0).is_err());
    assert_eq!(original, f.read("observation.json"));
}
#[test]
fn copied_foreign_run_record_refuses() {
    let f = Fixture::new();
    let mut rows = f.rows("doctor");
    rows[0]["record_path"] = json!(format!("{}.foreign/doctor.tool.jsonl", f.run));
    f.save_rows("doctor", &rows);
    f.refused("TOOL_REQUEST_BINDING_MISMATCH:doctor");
}
#[test]
fn duplicate_and_reordered_events_refuse() {
    let f = Fixture::new();
    let mut rows = f.rows("audit");
    rows.insert(4, rows[3].clone());
    f.save_rows("audit", &rows);
    f.refused("TOOL_RECORD_ORDER_OR_SCHEMA");
}
#[test]
fn missing_native_record_refuses() {
    let f = Fixture::new();
    fs::remove_file(format!("{}/audit.tool.jsonl", f.run)).unwrap();
    f.refused("ARTIFACT_MISSING:audit.tool.jsonl");
}
#[test]
fn extra_artifact_is_hashed_and_refuses() {
    let f = Fixture::new();
    f.put("unexpected-report.json", b"retained extra\n");
    f.refused("EXTRA_ARTIFACT");
    assert!(f.saved()["artifact_hashes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["path"] == "unexpected-report.json"));
    assert!(f.saved()["artifact_hashes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["path"] == "final/.jankurai/repo-score.json"));
}
#[test]
fn missing_and_duplicate_snapshot_subjects_refuse() {
    let f = Fixture::new();
    fs::remove_file(format!("{}/audit/.jankurai/repo-score.md", f.run)).unwrap();
    f.refused("SNAPSHOT_INCOMPLETE:audit");
    let f = Fixture::new();
    let mut bytes = f.read("before.absent");
    bytes.extend_from_slice(b"target/jankurai/audit-state.json\n");
    f.put("before.absent", &bytes);
    f.refused("SNAPSHOT_INCOMPLETE:before");
}
#[test]
fn lowered_report_policy_refuses_at_capture() {
    let mut f = Fixture::new();
    f.report["policy"]["minimum_score"] = json!(70);
    f.report["decision"]["minimum_score"] = json!(70);
    f.refresh();
    f.refused("REPORT_POLICY_MISMATCH:minimum_score");
}
#[test]
fn severity_and_fingerprint_mismatch_refuse() {
    let mut f = Fixture::new();
    f.report["policy"]["fail_on"] = json!(["critical"]);
    f.refresh();
    f.refused("REPORT_POLICY_MISMATCH:fail_on");
    let mut f = Fixture::new();
    f.report["policy_fingerprint"] = json!("sha256:foreign");
    f.refresh();
    f.refused("POLICY_FINGERPRINT_MISMATCH");
}
#[test]
fn failed_native_process_with_valid_report_cannot_pass() {
    let f = Fixture::new();
    f.tool_rows("audit", &validate::native_argv(&f.run, "audit"), 23);
    f.refused("TOOL_EXIT_CONTRADICTION");
}
#[test]
fn native_failure_keeps_primary_and_failed_diagnostic() {
    let f = Fixture::new();
    f.tool_rows("audit", &validate::native_argv(&f.run, "audit"), 23);
    f.put("audit.exit", b"23\n");
    f.put("lane.exit", b"23\n");
    f.put(
        "result.txt",
        b"stage=audit\nprimary_status=23\nretention_status=0\nfinal_status=23\n",
    );
    assert_eq!(f.capture(23).unwrap(), 0);
    assert_eq!(f.saved()["outcome"], "FAIL");
    assert_eq!(f.saved()["primary_status"], 23);
    assert!(f.check().is_err());
}
#[test]
fn stale_retained_and_current_report_bytes_refuse() {
    let f = Fixture::new();
    assert_eq!(f.capture(0).unwrap(), 0);
    f.put("final/.jankurai/repo-score.md", b"changed\n");
    assert!(f.check().is_err());
    let f = Fixture::new();
    f.root_put("target/jankurai/repo-score.md", b"stale\n");
    f.refused("CURRENT_ARTIFACT_DRIFT");
}
#[test]
fn nonregular_report_does_not_block_or_disappear() {
    let f = Fixture::new();
    let p = format!("{}/audit/.jankurai/repo-score.md", f.run);
    fs::remove_file(&p).unwrap();
    rustix::fs::mkfifoat(rustix::fs::CWD, &p, rustix::fs::Mode::from_raw_mode(0o600)).unwrap();
    f.refused("ARTIFACT_KIND_OR_LIMIT");
    assert!(f.saved()["omitted_artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "audit/.jankurai/repo-score.md"));
}
#[test]
fn staging_collision_preserves_both_originals() {
    let f = Fixture::new();
    f.root_put(
        ".ci-artifacts/observations/audit.json",
        b"foreign existing\n",
    );
    assert!(f.capture(0).is_err());
    assert_eq!(f.saved()["outcome"], "PASS");
    assert_eq!(
        fs::read(format!("{}/.ci-artifacts/observations/audit.json", f.root)).unwrap(),
        b"foreign existing\n"
    );
    assert!(f.check().is_err());
}
#[test]
fn missing_policy_still_preserves_all_failed_diagnostic_hashes() {
    let f = Fixture::new();
    fs::remove_file(format!("{}/agent/audit-policy.toml", f.root)).unwrap();
    assert_eq!(f.capture(0).unwrap(), 75);
    assert_eq!(f.saved()["outcome"], "FAIL");
    assert!(!f.saved()["artifact_hashes"].as_array().unwrap().is_empty());
}
#[test]
fn exact_parent_and_private_invocation_are_required() {
    let f = Fixture::new();
    let mut row = report_policy::decode(&f.read("invocation.json")).unwrap();
    row["parent_pid"] = json!(std::process::id() + 1);
    f.put("invocation.json", &json_bytes(&row));
    assert!(f.capture(0).unwrap_err().contains("PARENT_MISMATCH"));
    assert!(!Path::new(&format!("{}/observation.json", f.run)).exists());
}
#[test]
fn tool_hash_and_version_evidence_cannot_be_forged() {
    let f = Fixture::new();
    let mut rows = f.rows("audit");
    rows[3]["sha256"] = json!("0".repeat(64));
    f.save_rows("audit", &rows);
    f.refused("ADMITTED_TOOL_MISMATCH");
    let f = Fixture::new();
    f.put("doctor.tool.jsonl.stdout", b"jankurai 1.6.11 forged\n");
    f.refused("ACTUAL_VERSION_MISMATCH");
}
#[test]
fn duplicate_json_keys_and_result_fields_refuse() {
    let f = Fixture::new();
    let raw = f.read("audit/.jankurai/repo-score.json");
    let text = String::from_utf8(raw)
        .unwrap()
        .replace("\"score\":90", "\"score\":90,\"score\":70");
    f.put("audit/.jankurai/repo-score.json", text.as_bytes());
    f.refused("DUPLICATE_JSON_KEY");
    let f = Fixture::new();
    f.put(
        "result.txt",
        b"stage=complete\nprimary_status=0\nretention_status=0\nfinal_status=0\nfinal_status=0\n",
    );
    f.refused("DUPLICATE_RESULT_FIELD");
}
#[test]
fn fixed_inventory_refuses_unknown_directories_without_traversal() {
    let f = Fixture::new();
    f.put("unrelated/subdir/secret", b"not an audit artifact");
    f.refused("EXTRA_DIRECTORY:unrelated");
    assert!(f.saved()["omitted_artifacts"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v == "unrelated/"));
    assert!(!f.saved()["artifact_hashes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|v| v["path"] == "unrelated/subdir/secret"));
}

#[test]
fn executed_audit_requires_original_native_and_validation_streams() {
    for suffix in ["stdout", "stderr", "validation.stdout", "validation.stderr"] {
        let f = Fixture::new();
        let path = format!("audit.{suffix}");
        fs::remove_file(format!("{}/{path}", f.run)).unwrap();
        f.refused(&format!("ARTIFACT_MISSING:{path}"));
    }
}

#[test]
fn missing_failed_native_stream_retains_original_failure_status() {
    let f = Fixture::new();
    f.tool_rows("audit", &validate::native_argv(&f.run, "audit"), 23);
    f.put("audit.exit", b"23\n");
    f.put("lane.exit", b"23\n");
    f.put(
        "result.txt",
        b"stage=audit\nprimary_status=23\nretention_status=0\nfinal_status=23\n",
    );
    fs::remove_file(format!("{}/audit.stderr", f.run)).unwrap();
    assert_eq!(f.capture(23).unwrap(), 75);
    let saved = f.saved();
    assert_eq!(saved["outcome"], "FAIL");
    assert_eq!(saved["primary_status"], 23);
    assert!(saved["integrity_issues"]
        .to_string()
        .contains("ARTIFACT_MISSING:audit.stderr"));
    assert!(saved["artifact_hashes"]
        .as_array()
        .unwrap()
        .iter()
        .any(|row| row["path"] == "audit.stdout"));
}
