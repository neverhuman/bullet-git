//! Daemon-level proof that cleanup is authorized by its sealed preservation
//! receipt and never by a Kernel permit the protocol requires to be gone.

use super::*;
use crate::mutation_ledger::MutationSubject;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

const ATTEMPT: &str = "atm_1111111111111111111111111111111111111111111111111111111111111111";
const VARIANT: &str = "var_2222222222222222222222222222222222222222222222222222222222222222";
const NONCE: [u8; 32] = [9; 32];
const FENCE: u64 = 7;
const DELETED_AT: &str = "2026-09-09T00:00:00Z";

fn token() -> Value {
    json!({
        "variant_id": VARIANT,
        "attempt_id": ATTEMPT,
        "attempt_fence": FENCE,
        "workspace_nonce": NONCE,
    })
}

fn handle(daemon: &mut Daemon, request: &Value) -> Value {
    serde_json::from_str(&daemon.handle_line(&request.to_string())).expect("response json")
}

fn cleanup_request(receipt: &str) -> Value {
    json!({
        "id": 1,
        "method": "cleanup",
        "token": token(),
        "params": {"preservation_receipt": receipt, "deleted_at": DELETED_AT},
    })
}

fn private_dir(path: &Path) -> PathBuf {
    std::fs::create_dir_all(path).expect("create private directory");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).expect("0700");
    path.to_path_buf()
}

fn git(home: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("PATH"))
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_DATE", "2026-08-20T00:00:00+00:00")
        .env("GIT_COMMITTER_DATE", "2026-08-20T00:00:00+00:00")
        .args(args)
        .output()
        .expect("spawn git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn init_source(base: &Path) -> (PathBuf, String) {
    let home = private_dir(&base.join("git-home"));
    let src = base.join("source");
    std::fs::create_dir_all(&src).expect("source");
    let src_str = src.to_string_lossy().into_owned();
    git(&home, &["init", "-q", "-b", "main", &src_str]);
    std::fs::create_dir_all(src.join("src")).expect("src");
    std::fs::write(src.join("src").join("lib.rs"), "pub fn seed() {}\n").expect("lib");
    git(&home, &["-C", &src_str, "add", "-A"]);
    git(
        &home,
        &[
            "-C",
            &src_str,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@test.local",
            "commit",
            "-q",
            "-m",
            "init",
        ],
    );
    let hex = git(&home, &["-C", &src_str, "rev-parse", "HEAD"]);
    (src, format!("sha1:{hex}"))
}

/// One cloned session whose gateway checker can never issue a permit.
struct Fixture {
    _temp: TempDir,
    base: PathBuf,
    root: PathBuf,
    daemon: Daemon,
}

impl Fixture {
    fn new() -> Self {
        let temp = TempDir::new().expect("tempdir");
        let base = std::fs::canonicalize(temp.path()).expect("canonical tempdir");
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).expect("0700");
        let (source, base_sha) = init_source(&base);
        let root = private_dir(&base.join("farm"));
        let workspace = PrivateClone::create(&CloneRequest {
            source_repo: &source,
            base_sha: &base_sha,
            variant_id: VARIANT,
            attempt_id: ATTEMPT,
            root: &root,
            created_at: "2026-08-24T00:00:00Z",
            nonce: NONCE,
        })
        .expect("private clone");
        let expected = ExpectedAuthority {
            attempt_id: ATTEMPT.into(),
            attempt_fence: FENCE,
            workspace_nonce: NONCE,
        };
        let preservation = PreservationAuthority::open(workspace.runtime_dir()).expect("seal");
        let repo = RealRepository::new(
            workspace,
            ScopeGrant::new(&["src".to_string()]).expect("scope"),
            expected.clone(),
            CommitIdentity::farm("2026-08-24T00:00:00+00:00"),
        )
        .expect("repository");
        let mut daemon = Daemon::new();
        // The production checker is replaced by one that can return no permit
        // under any input: cleanup must still succeed on its sealed receipt.
        daemon.authority = AuthorityGateway::unavailable();
        daemon.authority.attach_ledger_root(&root);
        daemon.session = Some(Session {
            repo,
            expected,
            preservation,
        });
        Self {
            _temp: temp,
            base,
            root,
            daemon,
        }
    }

    fn session(&self) -> &Session {
        self.daemon.session.as_ref().expect("live session")
    }

    fn runtime_dir(&self) -> PathBuf {
        self.session().repo.workspace().runtime_dir().to_path_buf()
    }

    fn work_root(&self) -> PathBuf {
        self.root.join("work").join(ATTEMPT)
    }

    /// Issue a real sealed receipt exactly as `preserve` would.
    fn preserve(&self, destination: &Path) -> String {
        let session = self.session();
        session
            .preservation
            .issue(&session.repo, &protocol::envelope(&token()), destination)
            .expect("preserve")
            .token()
            .to_string()
    }

    /// Issue a receipt sealed by a different daemon session.
    fn foreign_receipt(&self, destination: &Path) -> String {
        let foreign = PreservationAuthority::open(&private_dir(&self.base.join("foreign-runtime")))
            .expect("foreign seal");
        let session = self.session();
        foreign
            .issue(&session.repo, &protocol::envelope(&token()), destination)
            .expect("foreign preserve")
            .token()
            .to_string()
    }
}

#[test]
fn sealed_receipt_cleans_up_while_no_kernel_permit_can_be_issued() {
    let mut fixture = Fixture::new();
    let destination = fixture.base.join("salvage");
    let receipt = fixture.preserve(&destination);
    let runtime_dir = fixture.runtime_dir();
    let work_dir = fixture.work_root();

    // Every other mutation still requires the Kernel permit path.
    let refused = handle(
        &mut fixture.daemon,
        &json!({"id": 1, "method": "checkpoint", "token": token(), "params": {}}),
    );
    assert_eq!(
        refused["err"]["code"], "AUTHORITY_CONTRACT_UNAVAILABLE",
        "{refused}"
    );

    let response = handle(&mut fixture.daemon, &cleanup_request(&receipt));
    let ok = response.get("ok").unwrap_or_else(|| panic!("{response}"));
    assert_eq!(ok["verified"], json!(true), "{response}");
    assert_eq!(
        ok["preservation_receipt_digest"],
        json!(bullet_git_types::Digest::of(receipt.as_bytes()).to_hex()),
        "{response}"
    );
    assert_eq!(
        ok.as_object().map(serde_json::Map::len),
        Some(3),
        "{response}"
    );
    assert_eq!(
        ok["tombstone"],
        json!(runtime_dir.join("tombstone.json").display().to_string())
    );
    assert!(runtime_dir.join("tombstone.json").is_file());
    assert!(!work_dir.exists(), "workspace was not deleted");
    assert!(destination.join("repository.bundle").is_file());
    assert!(!fixture.daemon.mutation_frozen);
    assert!(fixture.daemon.session.is_none());
}

#[test]
fn a_forged_foreign_or_mismatched_receipt_is_refused_and_leaves_the_daemon_usable() {
    let mut fixture = Fixture::new();
    let destination = fixture.base.join("salvage");
    let receipt = fixture.preserve(&destination);
    let foreign = fixture.foreign_receipt(&fixture.base.join("foreign-salvage"));
    let mut tampered = receipt.clone().into_bytes();
    let last = tampered.len() - 1;
    tampered[last] = if tampered[last] == b'0' { b'1' } else { b'0' };
    let tampered = String::from_utf8(tampered).expect("hex stays utf-8");

    for bad in [
        "not-a-sealed-receipt".to_string(),
        String::new(),
        tampered,
        foreign,
    ] {
        let response = handle(&mut fixture.daemon, &cleanup_request(&bad));
        assert_eq!(
            response["err"]["code"], "PRESERVATION_RECEIPT_REFUSED",
            "{response}"
        );
        assert!(!fixture.daemon.mutation_frozen, "refusal froze the daemon");
        assert!(
            fixture.daemon.session.is_some(),
            "refusal ended the session"
        );
    }

    // The daemon is still usable: the real receipt still cleans up.
    let response = handle(&mut fixture.daemon, &cleanup_request(&receipt));
    assert!(response.get("ok").is_some(), "{response}");
    assert!(!fixture.work_root().exists());
}

#[test]
fn a_second_cleanup_call_never_deletes_again() {
    let mut fixture = Fixture::new();
    let destination = fixture.base.join("salvage");
    let receipt = fixture.preserve(&destination);
    let runtime_dir = fixture.runtime_dir();
    assert!(handle(&mut fixture.daemon, &cleanup_request(&receipt))
        .get("ok")
        .is_some());
    let tombstone = std::fs::read(runtime_dir.join("tombstone.json")).expect("tombstone");
    let artifact = std::fs::read(destination.join("subject.json")).expect("artifact subject");

    let response = handle(&mut fixture.daemon, &cleanup_request(&receipt));
    assert_eq!(response["err"]["code"], "NOT_CLONED", "{response}");
    assert_eq!(
        std::fs::read(runtime_dir.join("tombstone.json")).expect("tombstone"),
        tombstone
    );
    assert_eq!(
        std::fs::read(destination.join("subject.json")).expect("artifact subject"),
        artifact
    );
}

#[test]
fn a_repository_failure_after_the_permit_is_unknown_and_freezes() {
    let mut fixture = Fixture::new();
    let destination = fixture.base.join("salvage");
    let receipt = fixture.preserve(&destination);
    // Occupy the tombstone path so the durable record cannot be written after
    // the workspace has already been removed.
    std::fs::write(fixture.runtime_dir().join("tombstone.json"), b"occupied").expect("occupy");

    let response = handle(&mut fixture.daemon, &cleanup_request(&receipt));
    assert_eq!(
        response["err"]["code"], "MUTATION_OUTCOME_UNKNOWN",
        "{response}"
    );
    assert!(fixture.daemon.mutation_frozen);
    let response = handle(&mut fixture.daemon, &cleanup_request(&receipt));
    assert_eq!(
        response["err"]["code"], "MUTATION_OUTCOME_UNKNOWN",
        "{response}"
    );
}

fn settled(outcome: MutationOutcome, result_digest: String) -> MutationResult {
    MutationResult {
        subject: MutationSubject {
            authority_envelope_digest: "a".repeat(64),
            authority_token_nonce: "b".repeat(64),
            mutation_id: format!("mut_{}", "1".repeat(64)),
            reservation_id: format!("rsv_{}", "2".repeat(64)),
            operation: MutationOperation::CleanupWorkspace,
            request_digest: "c".repeat(64),
            repository_id: format!("rep_{}", "3".repeat(64)),
            workspace_id: format!("wsp_{}", "4".repeat(64)),
            workspace_generation: 1,
            workspace_nonce: hex::encode(NONCE),
            attempt_id: ATTEMPT.into(),
            attempt_fence: FENCE,
            authority_epoch: 1,
            freeze_generation: 0,
            permit_nonce: "d".repeat(64),
            permit_digest: "e".repeat(64),
        },
        outcome,
        result_digest,
        completed_at_unix_ms: 1,
    }
}

fn durable_digest(runtime_dir: &Path, receipt_digest: &str) -> String {
    let payload = handlers::cleanup_result(&runtime_dir.join("tombstone.json"), receipt_digest);
    framed_digest(&[
        b"bullet-gitd.mutation-result.v1",
        MutationOperation::CleanupWorkspace.as_str().as_bytes(),
        b"committed",
        &serde_json::to_vec(&payload).expect("encode payload"),
    ])
    .to_hex()
}

#[test]
fn a_committed_replay_returns_the_exact_durable_result() {
    let mut fixture = Fixture::new();
    let runtime_dir = fixture.runtime_dir();
    let receipt_digest = "f".repeat(64);
    let digest = durable_digest(&runtime_dir, &receipt_digest);
    let replay = fixture
        .daemon
        .replay_cleanup(
            &runtime_dir,
            &receipt_digest,
            &settled(MutationOutcome::Committed, digest),
        )
        .expect("durable result");
    assert_eq!(replay["verified"], json!(true));
    assert_eq!(replay["preservation_receipt_digest"], json!(receipt_digest));
    assert_eq!(
        replay["tombstone"],
        json!(runtime_dir.join("tombstone.json").display().to_string())
    );
    assert!(fixture.daemon.session.is_none());
    assert!(!fixture.daemon.mutation_frozen);
}

#[test]
fn a_replay_that_cannot_reproduce_its_durable_digest_is_refused() {
    let mut fixture = Fixture::new();
    let runtime_dir = fixture.runtime_dir();
    let error = fixture
        .daemon
        .replay_cleanup(
            &runtime_dir,
            &"f".repeat(64),
            &settled(MutationOutcome::Committed, "0".repeat(64)),
        )
        .expect_err("mismatched durable digest");
    assert_eq!(error.0, "AUTHORITY_REPLAY_CONFLICT");
    assert!(fixture.daemon.session.is_some());
}

#[test]
fn an_aborted_replay_refuses_and_an_unknown_replay_freezes() {
    let mut fixture = Fixture::new();
    let runtime_dir = fixture.runtime_dir();
    let error = fixture
        .daemon
        .replay_cleanup(
            &runtime_dir,
            &"f".repeat(64),
            &settled(MutationOutcome::Aborted, "0".repeat(64)),
        )
        .expect_err("aborted replay");
    assert_eq!(error.0, "AUTHORITY_REFUSED");
    assert!(!fixture.daemon.mutation_frozen);
    let error = fixture
        .daemon
        .replay_cleanup(
            &runtime_dir,
            &"f".repeat(64),
            &settled(MutationOutcome::Unknown, "0".repeat(64)),
        )
        .expect_err("unknown replay");
    assert_eq!(error.0, "MUTATION_OUTCOME_UNKNOWN");
    assert!(fixture.daemon.mutation_frozen);
}
