//! Real filesystem/Git fixtures; native event rows are explicitly synthetic.
use super::{common::*, *};
use base64::Engine;
use bullet_git_workspace::{FileProtocol, SafeGit};
use sha2::{Digest, Sha256};
use std::cell::Cell;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;

pub(super) const POLICY: &[u8] = b"minimum_score = 85\nfail_on = [\"critical\", \"high\"]\nadvisory_on = [\"medium\", \"low\"]\n";

pub(super) struct Fixture {
    pub(super) directory: tempfile::TempDir,
    pub(super) root: String,
    pub(super) run: String,
    pub(super) commit: String,
    pub(super) report: Value,
    serial: Cell<usize>,
}
impl Fixture {
    pub(super) fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory
            .path()
            .join("repo with spaces")
            .to_str()
            .unwrap()
            .to_owned();
        let run = format!("{root}/target/jankurai/audit-runs/run.ABCD1234");
        let git = SafeGit::new(&directory.path().join("setup-git")).unwrap();
        git.run(
            None,
            FileProtocol::Never,
            &["init", "--template=", "--initial-branch=main", &root],
            &[],
        )
        .unwrap();
        fs::create_dir(Path::new(&root).join("agent")).unwrap();
        fs::write(Path::new(&root).join("agent/audit-policy.toml"), POLICY).unwrap();
        fs::write(
            Path::new(&root).join(".gitignore"),
            b"target/\n.ci-artifacts/\n.jankurai/\n",
        )
        .unwrap();
        git.run(
            Some(Path::new(&root)),
            FileProtocol::Never,
            &["add", "."],
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
        git.run(
            Some(Path::new(&root)),
            FileProtocol::Never,
            &["commit", "--no-gpg-sign", "-m", "fixture"],
            &identity,
        )
        .unwrap();
        let commit = git
            .run(
                Some(Path::new(&root)),
                FileProtocol::Never,
                &["rev-parse", "HEAD"],
                &[],
            )
            .unwrap()
            .text();
        fs::create_dir_all(&run).unwrap();
        fs::set_permissions(&run, fs::Permissions::from_mode(0o700)).unwrap();
        let report = json!({"score":90,"policy":{"minimum_score":85,"fail_on":["critical","high"],"advisory_on":["medium","low"],"mode":"standard"},
            "policy_fingerprint":format!("sha256:{}",hex::encode(Sha256::digest(POLICY))),
            "decision":{"passed":true,"status":"pass","minimum_score":85,"hard_findings":0},"findings":[],"caps_applied":[],
            "report_fingerprint":"sha256:fixture-report","input_fingerprint":"sha256:fixture-input","schema_version":"fixture-schema","standard_version":"fixture-standard"});
        let result = Self {
            directory,
            root,
            run,
            commit,
            report,
            serial: Cell::new(0),
        };
        result.put("invocation.json",&json_bytes(&json!({"schema":"bullet.audit-invocation.v1","id":"run.ABCD1234","repository":result.root,"origin":"dispatcher","parent_pid":std::process::id()})));
        result.stage(
            "doctor",
            &[
                "bash",
                "scripts/ci-doctor.sh",
                "audit",
                "--audit-run",
                &result.run,
            ],
            0,
        );
        result.stage(
            "lane",
            &["bash", "ops/ci/audit.sh", "--audit-run", &result.run],
            0,
        );
        result.put("audit.started", b"pid=1234\n");
        result.put(
            "result.txt",
            b"stage=complete\nprimary_status=0\nretention_status=0\nfinal_status=0\n",
        );
        result.tool_rows("doctor", &["--version".into()], 0);
        result.tool_rows("audit", &validate::native_argv(&result.run, "audit"), 0);
        for (suffix, bytes) in [
            ("stdout", b"fixture native stdout\n".as_slice()),
            ("stderr", b""),
            ("exit", b"0\n"),
            ("validation.stdout", b"true\n"),
            ("validation.stderr", b""),
            ("validation.exit", b"0\n"),
        ] {
            result.put(&format!("audit.{suffix}"), bytes);
        }
        result.snapshot("before", &BTreeMap::new());
        result.refresh();
        result
    }
    pub(super) fn put(&self, name: &str, bytes: &[u8]) {
        write(&format!("{}/{name}", self.run), bytes);
    }
    pub(super) fn root_put(&self, name: &str, bytes: &[u8]) {
        write(&format!("{}/{name}", self.root), bytes);
    }
    pub(super) fn read(&self, name: &str) -> Vec<u8> {
        fs::read(format!("{}/{name}", self.run)).unwrap()
    }
    pub(super) fn stage(&self, name: &str, argv: &[&str], status: u8) {
        self.put(
            &format!("{name}.argv"),
            &argv
                .iter()
                .flat_map(|s| s.bytes().chain([0]))
                .collect::<Vec<_>>(),
        );
        self.put(&format!("{name}.stdout"), b"fixture stage stdout\n");
        self.put(&format!("{name}.stderr"), b"");
        self.put(&format!("{name}.exit"), format!("{status}\n").as_bytes());
    }
    pub(super) fn rows(&self, name: &str) -> Vec<Value> {
        self.read(&format!("{name}.tool.jsonl"))
            .split(|b| *b == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| report_policy::decode(line).unwrap())
            .collect()
    }
    pub(super) fn save_rows(&self, name: &str, rows: &[Value]) {
        self.put(
            &format!("{name}.tool.jsonl"),
            &rows.iter().flat_map(json_bytes).collect::<Vec<_>>(),
        );
    }
    pub(super) fn tool_rows(&self, name: &str, argv: &[String], status: u8) {
        use super::super::{INSTALL_RECEIPT, PIN, PROFILE_NAME, SOURCE_COMMIT};
        let candidate = "/component/fixture/jankurai";
        let mut arguments = vec!["jankurai".to_owned()];
        arguments.extend_from_slice(argv);
        let mut events = vec![
            (
                "request",
                json!({"profile":PROFILE_NAME,"record_path":format!("{}/{}.tool.jsonl",self.run,name),"candidate":candidate,"argv":argv,"pinned_sha256":PIN.sha256,"pinned_size":PIN.size,"install_receipt_sha256":INSTALL_RECEIPT,"source_commit":SOURCE_COMMIT,"provenance_is_distribution_acceptance":false}),
            ),
            ("candidate_opened", json!({"path":candidate})),
            (
                "candidate_read",
                json!({"path":candidate,"sha256":PIN.sha256,"copied_bytes":PIN.size}),
            ),
            (
                "admitted",
                json!({"sha256":PIN.sha256,"size":PIN.size,"seals":15}),
            ),
            (
                "launch_intent",
                json!({"argv":arguments,"executable":"/proc/self/fd/9","passed_executable_fd":9,"update_check":"disabled_by_JANKURAI_NO_UPDATE_CHECK_1"}),
            ),
            ("started", json!({"pid":1234})),
            (
                "terminated",
                json!({"native_returncode":status,"exit_status":status}),
            ),
        ];
        if name == "doctor" {
            let stdout = [PIN.version, b"\n"].concat();
            events.push(("version_output",json!({"stdout_base64":base64::engine::general_purpose::STANDARD.encode(&stdout),"stderr_base64":""})));
            self.put("doctor.tool.jsonl.stdout", &stdout);
            self.put("doctor.tool.jsonl.stderr", b"");
        }
        events.push(("complete", json!({"exit_status":status})));
        let rows: Vec<_> = events
            .into_iter()
            .enumerate()
            .map(|(i, (event, mut fields))| {
                fields["schema"] = json!("bullet.local-auditor-tool.v1");
                fields["sequence"] = json!(i);
                fields["time_ns"] = json!((i + 1).to_string());
                fields["event"] = json!(event);
                fields["evidence_class"] = json!("LOCAL_TOOL_DIAGNOSTIC");
                fields
            })
            .collect();
        self.save_rows(name, &rows);
    }
    pub(super) fn snapshot(&self, phase: &str, files: &BTreeMap<String, Vec<u8>>) {
        for (path, bytes) in files {
            self.put(&format!("{phase}/{path}"), bytes);
        }
        let absent = ARTIFACTS
            .into_iter()
            .filter(|path| !files.contains_key(*path))
            .map(|path| format!("{path}\n"))
            .collect::<String>();
        self.put(&format!("{phase}.absent"), absent.as_bytes());
    }
    pub(super) fn refresh(&self) {
        let mut files = BTreeMap::from([
            (".jankurai/repo-score.json".into(), json_bytes(&self.report)),
            (
                ".jankurai/repo-score.md".into(),
                b"fixture report\n".to_vec(),
            ),
            (".jankurai/repair-queue.jsonl".into(), vec![]),
        ]);
        self.snapshot("audit", &files);
        for name in REPORTS {
            files.insert(
                format!("target/jankurai/{name}"),
                files[&format!(".jankurai/{name}")].clone(),
            );
        }
        self.snapshot("final", &files);
        for (path, bytes) in files {
            self.root_put(&path, &bytes);
        }
    }
    fn runtime(&self) -> String {
        let n = self.serial.get();
        self.serial.set(n + 1);
        self.directory
            .path()
            .join(format!("runtime-{n}"))
            .to_str()
            .unwrap()
            .into()
    }
    pub(super) fn capture(&self, status: u8) -> Result<u8> {
        capture(
            &self.root,
            &self.run,
            status,
            std::process::id(),
            &self.runtime(),
        )
    }
    pub(super) fn check(&self) -> Result<()> {
        check(&self.root, &self.commit, &self.runtime())
    }
    pub(super) fn saved(&self) -> Value {
        report_policy::decode(&self.read("observation.json")).unwrap()
    }
    pub(super) fn refused(&self, reason: &str) {
        assert_eq!(self.capture(0).unwrap(), 75);
        let saved = self.saved();
        assert_eq!(saved["outcome"], "FAIL");
        assert!(
            saved["integrity_issues"].to_string().contains(reason),
            "{}",
            saved["integrity_issues"]
        );
    }
}
fn write(path: &str, bytes: &[u8]) {
    fs::create_dir_all(Path::new(path).parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
pub(super) fn json_bytes(value: &Value) -> Vec<u8> {
    let mut bytes = serde_json::to_vec(value).unwrap();
    bytes.push(b'\n');
    bytes
}
