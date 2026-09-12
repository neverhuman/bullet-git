use super::*;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::symlink;

const POLICY: &str =
    "minimum_score = 85\nfail_on = [\"critical\", \"high\"]\nadvisory_on = [\"medium\", \"low\"]\n";

struct Fixture {
    directory: tempfile::TempDir,
    root: String,
    report: String,
    git: SafeGit,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().join("source").to_str().unwrap().to_owned();
        let report = directory
            .path()
            .join("report.json")
            .to_str()
            .unwrap()
            .to_owned();
        let git = SafeGit::new(&directory.path().join("fixture-git")).unwrap();
        git.run(
            None,
            FileProtocol::Never,
            &["init", "--template=", "--initial-branch=main", &root],
            &[],
        )
        .unwrap();
        fs::create_dir(Path::new(&root).join("agent")).unwrap();
        fs::write(Path::new(&root).join("agent/audit-policy.toml"), POLICY).unwrap();
        let fixture = Self {
            directory,
            root,
            report,
            git,
        };
        fixture.commit();
        let data = json!({"score":90,
            "policy":{"minimum_score":85,"fail_on":["critical","high"],"advisory_on":["medium","low"],"mode":"standard"},
            "policy_fingerprint":format!("sha256:{}",hex::encode(Sha256::digest(POLICY.as_bytes()))),
            "decision":{"passed":true,"status":"pass","minimum_score":85,"hard_findings":0},
            "findings":[]});
        fs::write(&fixture.report, serde_json::to_vec(&data).unwrap()).unwrap();
        fixture
    }

    fn commit(&self) {
        self.git
            .run(
                Some(Path::new(&self.root)),
                FileProtocol::Never,
                &["add", "--", "agent/audit-policy.toml"],
                &[],
            )
            .unwrap();
        let identity = [
            ("GIT_AUTHOR_NAME", OsString::from("fixture")),
            (
                "GIT_AUTHOR_EMAIL",
                OsString::from("fixture@example.invalid"),
            ),
            ("GIT_COMMITTER_NAME", OsString::from("fixture")),
            (
                "GIT_COMMITTER_EMAIL",
                OsString::from("fixture@example.invalid"),
            ),
        ];
        self.git
            .run(
                Some(Path::new(&self.root)),
                FileProtocol::Never,
                &["commit", "--no-gpg-sign", "-m", "fixture policy"],
                &identity,
            )
            .unwrap();
    }

    fn args(&self) -> Vec<String> {
        vec![
            "--root".into(),
            self.root.clone(),
            "--runtime".into(),
            self.directory
                .path()
                .join("report-runtime")
                .to_str()
                .unwrap()
                .into(),
            "--report".into(),
            self.report.clone(),
        ]
    }
}

#[test]
fn actual_committed_policy_and_report_validate_with_diagnostic_git() {
    let fixture = Fixture::new();
    entry(&fixture.args()).unwrap();
    assert!(fixture
        .directory
        .path()
        .join("report-runtime/hooks-empty")
        .is_dir());
}

#[test]
fn uncommitted_lower_policy_refuses_even_matching_report() {
    let fixture = Fixture::new();
    fs::write(
        Path::new(&fixture.root).join("agent/audit-policy.toml"),
        POLICY.replace("85", "70"),
    )
    .unwrap();
    assert_eq!(entry(&fixture.args()).unwrap_err(), "UNCOMMITTED_POLICY");
}

#[test]
fn native_report_lower_threshold_cannot_replace_committed_threshold() {
    let fixture = Fixture::new();
    let mut report: Value = serde_json::from_slice(&fs::read(&fixture.report).unwrap()).unwrap();
    report["policy"]["minimum_score"] = json!(70);
    report["decision"]["minimum_score"] = json!(70);
    fs::write(&fixture.report, serde_json::to_vec(&report).unwrap()).unwrap();
    assert!(entry(&fixture.args()).is_err());
}

#[test]
fn source_runtime_reuse_and_nonabsolute_operands_refuse() {
    let fixture = Fixture::new();
    let mut args = fixture.args();
    args[3] = Path::new(&fixture.root)
        .join("scratch")
        .to_str()
        .unwrap()
        .into();
    assert_eq!(entry(&args).unwrap_err(), "RUNTIME_MUST_BE_OUTSIDE_SOURCE");
    args = fixture.args();
    args[5] = "relative.json".into();
    assert_eq!(entry(&args).unwrap_err(), "NONNORMAL_ABSOLUTE_PATH");
    entry(&fixture.args()).unwrap();
    assert!(entry(&fixture.args()).is_err());
}

#[test]
fn symlink_policy_and_nonrepository_root_refuse() {
    let fixture = Fixture::new();
    let policy = Path::new(&fixture.root).join("agent/audit-policy.toml");
    let moved = fixture.directory.path().join("policy");
    fs::rename(&policy, &moved).unwrap();
    symlink(&moved, &policy).unwrap();
    assert!(entry(&fixture.args()).is_err());
    let mut args = fixture.args();
    args[1] = fixture.directory.path().to_str().unwrap().into();
    assert!(entry(&args).is_err());
}

#[test]
fn hostile_local_git_configuration_is_refused() {
    let fixture = Fixture::new();
    let config = Path::new(&fixture.root).join(".git/config");
    use std::io::Write;
    fs::OpenOptions::new()
        .append(true)
        .open(config)
        .unwrap()
        .write_all(
            format!(
                "\n[alias]\n forged = !touch {}\n",
                fixture.directory.path().join("forbidden-marker").display()
            )
            .as_bytes(),
        )
        .unwrap();
    assert!(entry(&fixture.args())
        .unwrap_err()
        .contains("forbidden key"));
    assert!(!fixture.directory.path().join("forbidden-marker").exists());
}

#[test]
fn duplicate_report_keys_fail_through_command_entry() {
    let fixture = Fixture::new();
    fs::write(&fixture.report, b"{\"score\":90,\"score\":100}").unwrap();
    assert!(entry(&fixture.args())
        .unwrap_err()
        .contains("DUPLICATE_JSON_KEY"));
}

#[test]
fn unknown_or_duplicate_cli_options_fail_without_runtime_creation() {
    let fixture = Fixture::new();
    for option in ["--score-floor", "--root"] {
        let mut args = fixture.args();
        args.extend([option.into(), fixture.root.clone()]);
        assert_eq!(
            entry(&args).unwrap_err(),
            "UNSUPPORTED_OR_DUPLICATE_REPORT_OPTION"
        );
    }
    assert!(!fixture.directory.path().join("report-runtime").exists());
}
