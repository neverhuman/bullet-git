//! Production `Daemon::new()` coverage for the env-driven Kernel authority RPC.
#![cfg(target_os = "linux")]

#[path = "kernel_final_check/support.rs"]
mod support;

use bullet_git_types::framed_digest;
use bullet_gitd::daemon::Daemon;
use bullet_gitd::mutation_ledger::MutationLedger;
use serde_json::Value;
use std::env;
use std::os::unix::fs::{symlink, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use support::{clone_request, configured, other_id, BoundSocket, Expected, Plan, Server, MUTATION};

fn handle(daemon: &mut Daemon, request: &Value) -> Value {
    serde_json::from_str(&daemon.handle_line(&request.to_string())).expect("daemon response")
}

fn assert_code(response: &Value, code: &str) {
    assert_eq!(response["err"]["code"], code, "{response}");
}

fn assert_inert(root: &Path) {
    assert!(
        !root.exists(),
        "authority refusal created {}",
        root.display()
    );
    assert!(!root.join(".bullet-mutation-ledger").exists());
}

fn server_case(
    case: &Path,
    label: &str,
    source: &Path,
    base: &str,
    plan: Plan,
    code: &str,
) -> Value {
    let root = case.join(label);
    let request = clone_request(source, base, &root);
    let server = Server::start(plan, Expected::new(&request));
    let response = handle(&mut server.daemon(), &request);
    assert_eq!(server.finish().len(), 1, "{plan:?} reached settlement");
    assert_code(&response, code);
    assert_inert(&root);
    response
}

#[allow(clippy::too_many_arguments)]
fn env_case(
    case: &Path,
    label: &str,
    source: &Path,
    base: &str,
    socket: Option<&Path>,
    uid: Option<&str>,
    gid: Option<&str>,
    code: &str,
) {
    let root = case.join(label);
    let request = clone_request(source, base, &root);
    let response = handle(&mut configured(socket, uid, gid), &request);
    assert_code(&response, code);
    assert_inert(&root);
}

fn git(home: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .env_clear()
        .env("PATH", env::var_os("PATH").expect("PATH"))
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_DATE", "2026-08-20T00:00:00+00:00")
        .env("GIT_COMMITTER_DATE", "2026-08-20T00:00:00+00:00")
        .args(args)
        .output()
        .expect("fixture git");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn init_source(root: &Path) -> (PathBuf, String, String) {
    let home = root.join("home");
    let source = root.join("source");
    std::fs::create_dir_all(&home).expect("home");
    std::fs::create_dir_all(source.join("src")).expect("source");
    let path = source.to_string_lossy();
    git(&home, &["init", "-q", "-b", "main", &path]);
    std::fs::write(source.join("src/lib.rs"), "pub fn seed() {}\n").expect("seed");
    git(&home, &["-C", &path, "add", "-A"]);
    git(
        &home,
        &[
            "-C",
            &path,
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
    let base = git(&home, &["-C", &path, "rev-parse", "HEAD"]);
    let tree = git(&home, &["-C", &path, "rev-parse", "HEAD^{tree}"]);
    (source, base, tree)
}

#[test]
fn production_kernel_final_check_is_exact_bounded_and_fail_closed() {
    let temp = tempfile::tempdir().expect("case");
    std::fs::set_permissions(temp.path(), std::fs::Permissions::from_mode(0o700)).expect("mode");
    let case = std::fs::canonicalize(temp.path()).expect("canonical case");
    let home = case.join("home");
    let (source, base, tree) = init_source(&case);

    let root = case.join("approved");
    std::fs::create_dir(&root).expect("workspace root");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).expect("root mode");
    let request = clone_request(&source, &base, &root);
    let expected = Expected::new(&request);
    let issued = expected.subject.clone();
    let server = Server::start(Plan::Exact, expected);
    let response = handle(&mut server.daemon(), &request);
    assert!(response.get("ok").is_some(), "{response}");
    assert!(Path::new(response["ok"]["repo_dir"].as_str().expect("repo path")).is_dir());
    let requests = server.finish();
    assert_eq!(requests.len(), 2);
    let settle = &requests[1]["params"];
    let encoded = serde_json::to_vec(&response["ok"]).expect("result JSON");
    let result = framed_digest(&[
        b"bullet-gitd.mutation-result.v1",
        b"clone-workspace",
        b"committed",
        &encoded,
    ])
    .to_hex();
    assert_eq!(settle["result_digest"], result);
    let record = std::fs::read_to_string(
        root.join(".bullet-mutation-ledger")
            .join(format!("{MUTATION}.jsonl")),
    )
    .expect("settled ledger");
    let events = record
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("ledger row"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["event"], "reserved");
    assert_eq!(events[0]["subject"], serde_json::to_value(&issued).unwrap());
    assert_eq!(events[1]["event"], "settled");
    for field in ["subject", "result_digest", "completed_at_unix_ms"] {
        assert_eq!(events[1][field], settle[field], "ledger field {field}");
    }
    assert_eq!(events[1]["outcome"], "committed");

    let expired_root = case.join("expired");
    let expired_request = clone_request(&source, &base, &expired_root);
    let expired_expected = Expected::new(&expired_request);
    let expired_server = Server::start(Plan::Expired, expired_expected);
    let expired_response = handle(&mut expired_server.daemon(), &expired_request);
    assert_code(&expired_response, "MUTATION_PERMIT_EXPIRED");
    let expired_requests = expired_server.finish();
    assert_eq!(expired_requests.len(), 2);
    assert_eq!(expired_requests[1]["params"]["outcome"], "aborted");
    let expired_record = std::fs::read_to_string(
        expired_root
            .join(".bullet-mutation-ledger")
            .join(format!("{MUTATION}.jsonl")),
    )
    .expect("expired settlement ledger");
    let expired_events = expired_record
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("expired ledger row"))
        .collect::<Vec<_>>();
    assert_eq!(expired_events.len(), 2);
    assert_eq!(expired_events[1]["outcome"], "aborted");
    assert_eq!(expired_root.read_dir().expect("expired root").count(), 1);
    assert!(
        !MutationLedger::open(expired_root.join(".bullet-mutation-ledger"))
            .expect("reopen expired ledger")
            .recovery_status()
            .is_frozen()
    );

    let denied = server_case(
        &case,
        "deny",
        &source,
        &base,
        Plan::Deny,
        "AUTHORITY_REFUSED",
    );
    assert!(denied["err"]["message"]
        .as_str()
        .unwrap()
        .contains("POLICY_REFUSED"));
    server_case(
        &case,
        "digest",
        &source,
        &base,
        Plan::DigestMismatch,
        "AUTHORITY_SUBJECT_MISMATCH",
    );
    for plan in [
        Plan::WrongProto,
        Plan::WrongId,
        Plan::Unknown,
        Plan::Ambiguous,
        Plan::Malformed,
        Plan::Oversized,
        Plan::Eof,
        Plan::Slow,
    ] {
        let started = Instant::now();
        server_case(
            &case,
            &format!("hostile-{plan:?}"),
            &source,
            &base,
            plan,
            "AUTHORITY_REFUSED",
        );
        assert!(plan != Plan::Slow || started.elapsed() < Duration::from_secs(4));
    }

    env_case(
        &case,
        "missing-all",
        &source,
        &base,
        None,
        None,
        None,
        "AUTHORITY_CONTRACT_UNAVAILABLE",
    );
    env_case(
        &case,
        "relative",
        &source,
        &base,
        Some(Path::new("authority.sock")),
        Some("1"),
        Some("1"),
        "AUTHORITY_REFUSED",
    );
    let socket = BoundSocket::new();
    let uid = socket.uid.to_string();
    let gid = socket.gid.to_string();
    env_case(
        &case,
        "missing-socket",
        &source,
        &base,
        None,
        Some(&uid),
        Some(&gid),
        "AUTHORITY_CONTRACT_UNAVAILABLE",
    );
    env_case(
        &case,
        "missing-uid",
        &source,
        &base,
        Some(&socket.path),
        None,
        Some(&gid),
        "AUTHORITY_CONTRACT_UNAVAILABLE",
    );
    socket.assert_unreached();
    env_case(
        &case,
        "missing-gid",
        &source,
        &base,
        Some(&socket.path),
        Some(&uid),
        None,
        "AUTHORITY_CONTRACT_UNAVAILABLE",
    );
    socket.assert_unreached();
    env_case(
        &case,
        "bad-uid",
        &source,
        &base,
        Some(&socket.path),
        Some("not-a-uid"),
        Some(&gid),
        "AUTHORITY_CONTRACT_UNAVAILABLE",
    );
    socket.assert_unreached();
    env_case(
        &case,
        "bad-gid",
        &source,
        &base,
        Some(&socket.path),
        Some(&uid),
        Some("not-a-gid"),
        "AUTHORITY_CONTRACT_UNAVAILABLE",
    );
    socket.assert_unreached();
    env_case(
        &case,
        "absent",
        &source,
        &base,
        Some(&case.join("absent.sock")),
        Some(&uid),
        Some(&gid),
        "AUTHORITY_REFUSED",
    );
    std::fs::set_permissions(&socket.path, std::fs::Permissions::from_mode(0o600)).unwrap();
    env_case(
        &case,
        "wrong-mode",
        &source,
        &base,
        Some(&socket.path),
        Some(&uid),
        Some(&gid),
        "AUTHORITY_REFUSED",
    );
    socket.assert_unreached();
    std::fs::set_permissions(&socket.path, std::fs::Permissions::from_mode(0o660)).unwrap();
    env_case(
        &case,
        "wrong-uid",
        &source,
        &base,
        Some(&socket.path),
        Some(&other_id(socket.uid)),
        Some(&gid),
        "AUTHORITY_REFUSED",
    );
    socket.assert_unreached();
    env_case(
        &case,
        "wrong-gid",
        &source,
        &base,
        Some(&socket.path),
        Some(&uid),
        Some(&other_id(socket.gid)),
        "AUTHORITY_REFUSED",
    );
    socket.assert_unreached();
    let link = socket.path.with_file_name("authority-link.sock");
    symlink(&socket.path, &link).expect("socket symlink");
    env_case(
        &case,
        "symlink",
        &source,
        &base,
        Some(&link),
        Some(&uid),
        Some(&gid),
        "AUTHORITY_REFUSED",
    );
    socket.assert_unreached();

    let source_path = source.to_string_lossy();
    assert_eq!(git(&home, &["-C", &source_path, "rev-parse", "HEAD"]), base);
    assert_eq!(
        git(&home, &["-C", &source_path, "rev-parse", "HEAD^{tree}"]),
        tree
    );
    assert!(git(&home, &["-C", &source_path, "status", "--porcelain"]).is_empty());
}
