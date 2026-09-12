//! Distinct ratchet/refusal paths and a real child-process CLI capture.
use super::{fixtures::*, *};
use std::fs;

fn ratchet_fixture() -> Fixture {
    let f = Fixture::new();
    let mut baseline = f.report.clone();
    baseline["score"] = json!(89);
    let baseline_path = "target/jankurai/accepted-baseline.json";
    let previous = BTreeMap::from([(baseline_path.to_owned(), json_bytes(&baseline))]);
    f.root_put(baseline_path, &json_bytes(&baseline));
    f.snapshot("before", &previous);
    f.snapshot("ratchet", &previous);
    for phase in ["audit", "final"] {
        let mut files = BTreeMap::new();
        for path in ARTIFACTS {
            let absolute = format!("{}/{phase}/{path}", f.run);
            if Path::new(&absolute).exists() {
                files.insert(path.to_owned(), fs::read(absolute).unwrap());
            }
        }
        files.extend(previous.clone());
        f.snapshot(phase, &files);
    }
    let mut report = f.report.clone();
    report["policy"]["mode"] = json!("ratchet");
    report["decision"]["ratchet"] = json!({"passed":true,"allowed_drop":0,"baseline_score":89,"score_delta":1,
        "new_caps":[],"new_hard_findings":[],"policy_changed":false,
        "baseline_report_fingerprint":baseline["report_fingerprint"],"baseline_input_fingerprint":baseline["input_fingerprint"],"baseline_policy_fingerprint":baseline["policy_fingerprint"]});
    f.put("ratchet.json", &json_bytes(&report));
    f.put("ratchet.md", b"fixture ratchet\n");
    f.tool_rows("ratchet", &validate::native_argv(&f.run, "ratchet"), 0);
    for suffix in ["stdout", "stderr", "validation.stdout", "validation.stderr"] {
        f.put(&format!("ratchet.{suffix}"), b"");
    }
    for suffix in ["exit", "validation.exit"] {
        f.put(&format!("ratchet.{suffix}"), b"0\n");
    }
    f.validation_command("ratchet");
    f
}

#[test]
fn full_ratchet_binds_distinct_native_record_and_baseline() {
    let f = ratchet_fixture();
    assert_eq!(f.capture(0).unwrap(), 0);
    f.check().unwrap();
    assert_eq!(
        f.saved()["tools"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["audit", "doctor", "ratchet"]
    );
    let mut rows = f.rows("ratchet");
    rows[0]["record_path"] = json!(format!("{}/audit.tool.jsonl", f.run));
    f.save_rows("ratchet", &rows);
    assert!(f.check().is_err());
}

#[test]
fn doctor_refusal_preserves_prelaunch_failed_diagnostic() {
    let f = Fixture::new();
    let request = f.rows("doctor")[0].clone();
    for entry in fs::read_dir(&f.run).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name();
        if [
            "invocation.json",
            "doctor.argv",
            "doctor.stdout",
            "doctor.stderr",
            "bootstrap.argv",
            "bootstrap.stdout",
            "bootstrap.stderr",
            "bootstrap.exit",
        ]
        .contains(&name.to_str().unwrap())
        {
            continue;
        }
        if entry.file_type().unwrap().is_dir() {
            fs::remove_dir_all(entry.path()).unwrap();
        } else {
            fs::remove_file(entry.path()).unwrap();
        }
    }
    f.put("doctor.exit", b"75\n");
    let refusal = json!({"schema":"bullet.local-auditor-tool.v1","sequence":1,"time_ns":"2","event":"refused","evidence_class":"LOCAL_TOOL_DIAGNOSTIC","reason":"synthetic checksum refusal","native_status":null,"exit_status":75});
    f.save_rows("doctor", &[request, refusal]);
    assert_eq!(f.capture(75).unwrap(), 0);
    let saved = f.saved();
    assert_eq!(saved["outcome"], "FAIL");
    assert_eq!(saved["tools"].as_object().unwrap().len(), 1);
    assert!(saved["tools"]["doctor"]["native_returncode"].is_null());
    assert!(f.check().is_err());
}

#[test]
fn process_failure_and_refusal_native_status_must_agree() {
    let f = Fixture::new();
    let mut rows = f.rows("audit");
    let last = rows.len() - 1;
    rows[last - 1]["native_returncode"] = json!(-9);
    rows[last - 1]["exit_status"] = json!(0);
    f.save_rows("audit", &rows);
    f.refused("NATIVE_STATUS_CONTRADICTION");
    let f = Fixture::new();
    let mut rows = f.rows("doctor");
    let last = rows.len() - 1;
    rows[last]["event"] = json!("refused");
    rows[last]["native_status"] = json!(23);
    rows[last]["exit_status"] = json!(75);
    f.save_rows("doctor", &rows);
    f.put("doctor.exit", b"75\n");
    assert_eq!(f.capture(75).unwrap(), 75);
    assert!(f.saved()["integrity_issues"]
        .to_string()
        .contains("REFUSAL_STATUS_CONTRADICTION"));
}

#[test]
fn cli_options_and_foreign_root_refuse_before_capture() {
    for (command, args) in [
        ("capture", vec!["--root", "relative"]),
        ("capture", vec!["--root", "/tmp", "--root", "/tmp"]),
        (
            "check",
            vec![
                "--root",
                "/tmp",
                "--runtime",
                "/tmp/new",
                "--commit",
                "x",
                "--run",
                "/tmp/run",
            ],
        ),
    ] {
        assert!(entry(
            command,
            &args.into_iter().map(str::to_owned).collect::<Vec<_>>()
        )
        .is_err());
    }
    let f = Fixture::new();
    assert_eq!(f.capture(0).unwrap(), 0);
    let foreign = f.directory.path().join("foreign");
    fs::create_dir(&foreign).unwrap();
    assert!(check(
        foreign.to_str().unwrap(),
        &f.commit,
        f.directory.path().join("foreign-runtime").to_str().unwrap()
    )
    .is_err());
}

#[test]
fn cli_capture_child() {
    let Ok(root) = std::env::var("BULLET_TEST_CAPTURE_ROOT") else {
        return;
    };
    let run = std::env::var("BULLET_TEST_CAPTURE_RUN").unwrap();
    let runtime = std::env::var("BULLET_TEST_CAPTURE_RUNTIME").unwrap();
    let status = super::super::entry(
        [
            "capture",
            "--root",
            &root,
            "--runtime",
            &runtime,
            "--run",
            &run,
            "--status",
            "0",
        ]
        .into_iter()
        .map(std::ffi::OsString::from)
        .collect(),
    );
    assert_eq!(status, 0);
}

#[test]
fn actual_cli_child_validates_dispatcher_parent_and_publishes() {
    let f = Fixture::new();
    let runtime = f.directory.path().join("child-runtime");
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "tool::observation::advanced_tests::cli_capture_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("TMPDIR", f.directory.path())
        .env("BULLET_TEST_CAPTURE_ROOT", &f.root)
        .env("BULLET_TEST_CAPTURE_RUN", &f.run)
        .env("BULLET_TEST_CAPTURE_RUNTIME", runtime)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("audit-observation: PASS"));
    assert_eq!(f.saved()["invocation"]["parent_pid"], std::process::id());
    f.check().unwrap();
}

#[test]
fn executed_ratchet_requires_original_native_and_validation_streams() {
    for suffix in ["stdout", "stderr", "validation.stdout", "validation.stderr"] {
        let f = ratchet_fixture();
        let path = format!("ratchet.{suffix}");
        fs::remove_file(format!("{}/{path}", f.run)).unwrap();
        f.refused(&format!("ARTIFACT_MISSING:{path}"));
    }
}
