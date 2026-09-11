//! Retained actual-filesystem/ELF fixtures, never installed auditor acceptance.
#[path = "admission_tests.rs"]
mod admission_tests;
use super::*;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::sync::{Mutex, MutexGuard};

static SERIAL: Mutex<()> = Mutex::new(());
pub(super) struct Fixture {
    pub(super) root: PathBuf,
    pub(super) candidate: String,
    pub(super) record: String,
    hash: String,
    size: u64,
    _serial: MutexGuard<'static, ()>,
}

impl Fixture {
    pub(super) fn new(name: &str) -> Self {
        // The production binary is single-threaded. Serialize fixture-owned
        // inheritable FDs so another test cannot invalidate its spawn boundary.
        let serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        let root = tempfile::Builder::new()
            .prefix(&format!("bullet-ci-rust-{name}-"))
            .tempdir()
            .expect("private fixture")
            .keep();
        eprintln!("retained CI fixture: {}", root.display());
        let candidate = root.join("candidate");
        fs::copy("/usr/bin/true", &candidate).expect("actual local ELF fixture");
        fs::set_permissions(&candidate, fs::Permissions::from_mode(0o755)).unwrap();
        let bytes = fs::read(&candidate).unwrap();
        Self {
            candidate: candidate.to_str().unwrap().into(),
            record: root.join("tool.jsonl").to_str().unwrap().into(),
            root,
            hash: hex::encode(Sha256::digest(&bytes)),
            size: bytes.len() as u64,
            _serial: serial,
        }
    }
    pub(super) fn refresh(&mut self) {
        let bytes = fs::read(&self.candidate).unwrap();
        self.hash = hex::encode(Sha256::digest(&bytes));
        self.size = bytes.len() as u64;
    }
    pub(super) fn profile(&self) -> Profile<'_> {
        Profile {
            sha256: &self.hash,
            size: self.size,
            version: PIN.version,
        }
    }
    pub(super) fn environment(&self) -> Environment {
        [
            ("PATH", "/usr/bin:/bin"),
            ("LANG", "C"),
            ("LC_ALL", "C"),
            ("TZ", "UTC0"),
        ]
        .into_iter()
        .map(|(key, value)| (key.into(), value.into()))
        .chain([(OsString::from("HOME"), self.root.clone().into_os_string())])
        .collect()
    }
    pub(super) fn request(&self) -> Request {
        Request {
            candidate: self.candidate.clone(),
            record: self.record.clone(),
            argv: audit(),
        }
    }
    pub(super) fn invoke(&self) -> i32 {
        invoke(&self.request(), self.profile(), self.environment())
    }
    pub(super) fn rows(&self) -> Vec<Value> {
        let rows: Vec<Value> = fs::read_to_string(&self.record)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for (index, row) in rows.iter().enumerate() {
            assert_eq!(row["sequence"], index);
        }
        rows
    }
    pub(super) fn no_start(&self) {
        assert!(self.rows().iter().all(|row| row["event"] != "started"));
    }
}

pub(super) fn audit() -> Vec<String> {
    [
        "audit",
        ".",
        "--full",
        "--no-score-history",
        "--json",
        "report.json",
        "--md",
        "report.md",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[test]
fn production_pin_refuses_marker_before_execution() {
    let fixture = Fixture::new("production-pin");
    let marker = fixture.root.join("WRONG_CANDIDATE_STARTED");
    fs::write(
        &fixture.candidate,
        format!("#!/bin/sh\nprintf started > '{}'\n", marker.display()),
    )
    .unwrap();
    fs::OpenOptions::new()
        .write(true)
        .open(&fixture.candidate)
        .unwrap()
        .set_len(PIN.size)
        .unwrap();
    let mut environment = fixture.environment();
    environment.insert("JANKURAI_SHA256".into(), "0".repeat(64).into());
    let mut request = fixture.request();
    request.argv = vec!["--version".into()];
    assert_eq!(invoke(&request, PIN, environment), 75);
    assert!(!marker.exists());
    fixture.no_start();
    assert_eq!(fixture.rows()[0]["pinned_sha256"], PIN.sha256);
    assert!(fixture.rows().last().unwrap()["reason"]
        .as_str()
        .unwrap()
        .contains("CANDIDATE_SHA256_MISMATCH"));
}

#[test]
fn actual_sealed_execution_and_one_use_record() {
    let fixture = Fixture::new("one-use");
    assert_eq!(fixture.invoke(), 0);
    let rows = fixture.rows();
    assert_eq!(rows[0]["record_path"], fixture.record);
    assert_eq!(rows.last().unwrap()["event"], "complete");
    assert_eq!(
        rows.iter().find(|r| r["event"] == "terminated").unwrap()["native_returncode"],
        0
    );
    let original = fs::read(&fixture.record).unwrap();
    assert_eq!(fixture.invoke(), 75);
    assert_eq!(fs::read(&fixture.record).unwrap(), original);
    assert_eq!(
        fs::metadata(&fixture.record).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn actual_native_failure_is_preserved() {
    let mut fixture = Fixture::new("native-failure");
    fs::copy("/usr/bin/false", &fixture.candidate).unwrap();
    fixture.refresh();
    assert_eq!(fixture.invoke(), 1);
    assert_eq!(fixture.rows().last().unwrap()["exit_status"], 1);
}

#[test]
fn unknown_audit_flags_refuse_before_admission() {
    let fixture = Fixture::new("unknown-flags");
    let mut request = fixture.request();
    request.argv.extend(["--fail-under".into(), "1".into()]);
    assert_eq!(
        invoke(&request, fixture.profile(), fixture.environment()),
        75
    );
    assert_eq!(
        fixture
            .rows()
            .iter()
            .map(|row| row["event"].as_str().unwrap())
            .collect::<Vec<_>>(),
        ["request", "refused"]
    );
}

#[test]
fn cli_digest_override_is_not_an_option() {
    let fixture = Fixture::new("no-pin-override");
    let args = [
        "--candidate",
        &fixture.candidate,
        "--record",
        &fixture.record,
        "--sha256",
        "0",
    ]
    .into_iter()
    .map(OsString::from)
    .collect();
    assert_eq!(entry(args), 2);
    assert!(!std::path::Path::new(&fixture.record).exists());
}

#[test]
fn exact_audit_argv_requires_reports_and_paired_ratchet() {
    assert!(validate_argv(&audit()).is_ok());
    let mut ratchet = audit();
    ratchet.extend(["--mode", "ratchet", "--baseline", "before.json"].map(str::to_owned));
    assert!(validate_argv(&ratchet).is_ok());
    for extra in [
        vec!["--mode", "ratchet"],
        vec!["--baseline", "x"],
        vec!["--json", "x"],
        vec!["--mode", "standard", "--baseline", "x"],
        vec!["--md", ""],
        vec!["--new", "value"],
    ] {
        let mut argv = audit();
        argv.extend(extra.into_iter().map(str::to_owned));
        assert!(validate_argv(&argv).is_err(), "accepted {argv:?}");
    }
    assert!(validate_argv(&audit()[..6]).is_err());
    assert!(validate_argv(&[]).is_err());
}

#[test]
fn normalized_paths_refuse_ambiguous_components() {
    for path in [
        "relative",
        "/",
        "/tmp//x",
        "/tmp/./x",
        "/tmp/../x",
        "/tmp/x/",
        "/tmp/\0x",
    ] {
        assert!(paths::absolute_parts(path).is_err(), "accepted {path:?}");
    }
    assert_eq!(
        paths::absolute_parts("/tmp/path with spaces/x").unwrap(),
        ["tmp", "path with spaces", "x"]
    );
}
