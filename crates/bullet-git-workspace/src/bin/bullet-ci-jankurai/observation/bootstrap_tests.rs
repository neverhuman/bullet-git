use super::{bootstrap, fixtures::*, inventory::Inventory, *};
use std::fs;
use std::os::unix::fs::symlink;

fn rewrite_json(f: &Fixture, name: &str, change: impl FnOnce(&mut Value)) {
    let path = format!("{}/{name}", f.build_directory());
    let mut row = report_policy::decode(&fs::read(&path).unwrap()).unwrap();
    change(&mut row);
    fs::write(path, json_bytes(&row)).unwrap();
    f.refresh_build_checksums();
}

#[test]
fn missing_build_stream_keeps_other_originals_and_failed_primary() {
    let f = Fixture::new();
    fs::remove_file(format!("{}/cargo.stdout", f.build_directory())).unwrap();
    assert_eq!(f.capture(23).unwrap(), 75);
    let saved = f.saved();
    assert_eq!(saved["primary_status"], 23);
    assert_eq!(saved["outcome"], "FAIL");
    assert!(
        saved["integrity_issues"]
            .to_string()
            .contains("BOOTSTRAP_ARTIFACT_UNREADABLE:cargo.stdout")
    );
    assert!(
        saved["artifact_hashes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|row| row["path"] == "build/cargo.stderr")
    );
    assert!(
        saved["omitted_artifacts"]
            .as_array()
            .unwrap()
            .contains(&json!("build/cargo.stdout"))
    );
}

#[test]
fn missing_build_binary_cannot_be_replaced_by_receipt() {
    let f = Fixture::new();
    fs::remove_file(format!(
        "{}/target/debug/bullet-ci-jankurai",
        f.build_directory()
    ))
    .unwrap();
    f.refused("BOOTSTRAP_ARTIFACT_UNREADABLE:target/debug/bullet-ci-jankurai");
}

#[test]
fn forged_foreign_bootstrap_subject_refuses() {
    let f = Fixture::new();
    rewrite_json(&f, "artifact.json", |v| {
        v["executable"] = json!("/tmp/foreign-helper")
    });
    f.refused("BOOTSTRAP_BINARY_SUBJECT_MISMATCH");
}

#[test]
fn checker_purpose_cannot_authorize_live_capture() {
    let f = Fixture::new();
    rewrite_json(&f, "artifact.json", |v| v["purpose"] = json!("check"));
    f.refused("BOOTSTRAP_BINARY_SUBJECT_MISMATCH");
}

#[test]
fn changed_compiled_source_and_omitted_selection_refuse() {
    let f = Fixture::new();
    fs::write(
        format!("{}/crates/bullet-git-workspace/src/fixture.rs", f.root),
        b"changed source",
    )
    .unwrap();
    f.refused("BOOTSTRAP_SOURCE_DRIFT");
    let f = Fixture::new();
    let path = format!("{}/source.before.sha256z", f.build_directory());
    let mut source = fs::read(path).unwrap();
    source.pop();
    source.truncate(source.iter().rposition(|b| *b == 0).unwrap() + 1);
    for name in ["source.before.sha256z", "source.after.sha256z"] {
        fs::write(format!("{}/{name}", f.build_directory()), &source).unwrap();
    }
    f.refresh_build_checksums();
    f.refused("BOOTSTRAP_SOURCE_DRIFT");
}

#[test]
fn source_symlink_refuses_without_reading_destination() {
    let f = Fixture::new();
    let path = format!("{}/crates/bullet-git-workspace/src/fixture.rs", f.root);
    fs::remove_file(&path).unwrap();
    symlink("/definitely-absent-bootstrap-fixture", path).unwrap();
    f.refused("BOOTSTRAP_SOURCE_NOT_REGULAR");
}

#[test]
fn compiler_byte_drift_refuses_even_with_valid_build_checksums() {
    let f = Fixture::new();
    let sysroot = fs::read_to_string(format!("{}/sysroot.stdout", f.build_directory())).unwrap();
    fs::write(
        format!("{}/bin/rustc", sysroot.trim()),
        b"different tool bytes",
    )
    .unwrap();
    f.refused("BOOTSTRAP_TOOL_DRIFT");
}

#[test]
fn cached_or_duplicate_compiler_artifacts_refuse() {
    for duplicate in [false, true] {
        let f = Fixture::new();
        let path = format!("{}/cargo.stdout", f.build_directory());
        let source = fs::read_to_string(&path).unwrap();
        let mut rows: Vec<Value> = source
            .lines()
            .map(|s| report_policy::decode(s.as_bytes()).unwrap())
            .collect();
        if duplicate {
            rows.push(rows[0].clone());
        } else {
            rows[0]["fresh"] = json!(true);
        }
        let mut bytes = vec![];
        for row in rows {
            bytes.extend(json_bytes(&row));
        }
        fs::write(path, bytes).unwrap();
        f.refresh_build_checksums();
        f.refused(if duplicate {
            "BOOTSTRAP_CARGO_SELECTION_INCOMPLETE"
        } else {
            "BOOTSTRAP_CARGO_ARTIFACT_MISMATCH"
        });
    }
}

#[test]
fn changed_cargo_argv_and_extra_environment_refuse() {
    let f = Fixture::new();
    fs::write(
        format!("{}/cargo.argv", f.build_directory()),
        b"cargo\0--version\0",
    )
    .unwrap();
    f.refresh_build_checksums();
    f.refused("BOOTSTRAP_CARGO_ARGV_MISMATCH");
    let f = Fixture::new();
    rewrite_json(&f, "cargo.environment.json", |v| {
        v["LD_PRELOAD"] = json!("/tmp/inject.so")
    });
    f.refused("BOOTSTRAP_ENVIRONMENT_MISMATCH");
}

#[test]
fn failed_bootstrap_status_cannot_promote_native_result() {
    let f = Fixture::new();
    f.put("bootstrap.exit", b"1\n");
    f.refused("BOOTSTRAP_NOT_PASSING");
}

#[test]
fn required_validation_argv_is_bound_and_present() {
    let f = Fixture::new();
    fs::remove_file(format!("{}/audit.validation.argv", f.run)).unwrap();
    f.refused("ARTIFACT_MISSING");
    let f = Fixture::new();
    let path = format!("{}/audit.validation.argv", f.run);
    let bytes = fs::read_to_string(&path)
        .unwrap()
        .replace("--report", "--foreign-report");
    fs::write(path, bytes).unwrap();
    f.refused("VALIDATION_ARGV_MISMATCH");
}

#[test]
fn build_input_handles_detect_later_source_change() {
    let f = Fixture::new();
    let mut inventory = Inventory::default();
    inventory.scan(&f.run).unwrap();
    bootstrap::collect(&mut inventory, &f.root, &f.run).unwrap();
    let inputs = bootstrap::validate(&inventory, &f.root, &f.run).unwrap();
    assert!(!inputs.is_empty());
    fs::write(
        format!("{}/crates/bullet-git-workspace/src/fixture.rs", f.root),
        b"later longer changed source bytes",
    )
    .unwrap();
    assert!(inputs.iter().any(|input| input.recheck().is_err()));
}
