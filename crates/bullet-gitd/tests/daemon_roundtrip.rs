//! Full stdio conversation against the built bullet-gitd binary, spawned in a
//! hostile environment (poisoned HOME, GIT_* variables) that it must ignore.

use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};

const NONCE: [u8; 32] = [3u8; 32];
const ATTEMPT: &str = "atm_roundtrip1";
const FENCE: u64 = 7;

fn fixture_git(home: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("PATH"))
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_DATE", "2026-08-20T00:00:00+00:00")
        .env("GIT_COMMITTER_DATE", "2026-08-20T00:00:00+00:00")
        .args(args)
        .output()
        .expect("spawn fixture git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

fn init_source(root: &Path) -> (String, String) {
    let home = root.join("fixture-home");
    std::fs::create_dir_all(&home).expect("home");
    let src = root.join("source");
    std::fs::create_dir_all(&src).expect("src");
    let src_str = src.to_string_lossy().into_owned();
    fixture_git(&home, &["init", "-q", "-b", "main", &src_str]);
    std::fs::write(src.join("README.md"), "seed\n").expect("seed");
    fixture_git(&home, &["-C", &src_str, "add", "-A"]);
    fixture_git(
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
    let base = fixture_git(&home, &["-C", &src_str, "rev-parse", "HEAD"]);
    (src_str, base)
}

fn token(attempt: &str, fence: u64) -> Value {
    json!({
        "organization_id": "org_fixture",
        "variant_id": "var_roundtrip1",
        "attempt_id": attempt,
        "attempt_fence": fence,
        "workspace_nonce": NONCE.to_vec(),
        "runner_epoch": 1,
    })
}

struct Conversation {
    child: Child,
    stdin: ChildStdin,
    reader: BufReader<std::process::ChildStdout>,
}

impl Conversation {
    fn send(&mut self, request: &Value) -> Value {
        writeln!(self.stdin, "{request}").expect("write request");
        self.stdin.flush().expect("flush request");
        let mut line = String::new();
        self.reader.read_line(&mut line).expect("read response");
        assert!(!line.is_empty(), "daemon closed the stream");
        serde_json::from_str(&line).expect("response json")
    }

    fn finish(mut self) {
        drop(self.stdin);
        let status = self.child.wait().expect("daemon exit");
        assert!(status.success(), "daemon exited with {status:?}");
    }
}

fn spawn_daemon(hostile_home: &Path) -> Conversation {
    let mut child = Command::new(env!("CARGO_BIN_EXE_bullet-gitd"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .env("HOME", hostile_home)
        .env("GIT_DIR", "/nonexistent-git-dir")
        .env("GIT_WORK_TREE", "/nonexistent-work-tree")
        .env("GIT_INDEX_FILE", "/nonexistent-index")
        .env(
            "GIT_CONFIG_GLOBAL",
            hostile_home.join(".gitconfig").as_os_str(),
        )
        .spawn()
        .expect("spawn bullet-gitd");
    let stdin = child.stdin.take().expect("stdin");
    let reader = BufReader::new(child.stdout.take().expect("stdout"));
    Conversation {
        child,
        stdin,
        reader,
    }
}

fn hostile_home(root: &Path, canary: &Path) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let home = root.join("hostile-home");
    let hooks = home.join("hostile-hooks");
    std::fs::create_dir_all(&hooks).expect("hostile hooks");
    let script = hooks.join("pre-commit");
    std::fs::write(&script, format!("#!/bin/sh\ntouch {}\n", canary.display()))
        .expect("hook script");
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).expect("chmod");
    std::fs::write(
        home.join(".gitconfig"),
        format!("[core]\n\thooksPath = {}\n", hooks.display()),
    )
    .expect("hostile config");
    home
}

fn clone_and_read(conv: &mut Conversation, src: &str, base: &str, root: &Path) {
    // Before clone, everything else is refused.
    let resp = conv.send(&json!({
        "id": 0, "method": "read_tree", "token": token(ATTEMPT, FENCE), "params": {}
    }));
    assert_eq!(resp["err"]["code"], "NOT_CLONED");

    let resp = conv.send(&json!({
        "id": 1, "method": "clone", "token": token(ATTEMPT, FENCE),
        "params": {
            "source_repo": src,
            "base_sha": base,
            "root": root.to_string_lossy(),
            "created_at": "2026-08-24T00:00:00Z",
            "allowed_prefixes": ["src"],
            "commit_date": "2026-08-24T00:00:00+00:00",
        }
    }));
    assert_eq!(resp["ok"]["base_sha"], base, "clone failed: {resp}");
    assert_eq!(
        resp["ok"]["branch"],
        format!("bullet/var_roundtrip1/{ATTEMPT}")
    );

    let resp = conv.send(&json!({
        "id": 2, "method": "read_tree", "token": token(ATTEMPT, FENCE), "params": {}
    }));
    let files = resp["ok"]["files"].as_array().expect("files");
    assert!(files.iter().any(|f| f == "README.md"));
}

fn apply_and_checkpoint(conv: &mut Conversation) {
    let resp = conv.send(&json!({
        "id": 3, "method": "apply_change", "token": token(ATTEMPT, FENCE),
        "params": {"patches": [
            {"path": "src/lib.rs", "contents_hex": hex::encode("pub fn hello() {}\n")}
        ]}
    }));
    assert_eq!(resp["ok"]["applied"], 1, "apply failed: {resp}");

    let resp = conv.send(&json!({
        "id": 4, "method": "checkpoint", "token": token(ATTEMPT, FENCE), "params": {}
    }));
    let git_tree = resp["ok"]["git_tree"].as_str().expect("git tree");
    assert_eq!(git_tree.len(), 40);
}

fn refused_tokens_and_scope(conv: &mut Conversation) {
    // Stale fence, empty token, and garbage token are refused mid-session.
    let resp = conv.send(&json!({
        "id": 5, "method": "checkpoint", "token": token(ATTEMPT, FENCE + 1), "params": {}
    }));
    assert_eq!(resp["err"]["code"], "STALE_AUTHORITY");
    let resp = conv.send(&json!({
        "id": 6, "method": "checkpoint", "token": "", "params": {}
    }));
    assert_eq!(resp["err"]["code"], "UNAUTHORIZED");
    let resp = conv.send(&json!({
        "id": 7, "method": "checkpoint", "token": "x", "params": {}
    }));
    assert_eq!(resp["err"]["code"], "UNAUTHORIZED");

    // Out-of-scope patch names the path and applies nothing.
    let resp = conv.send(&json!({
        "id": 8, "method": "apply_change", "token": token(ATTEMPT, FENCE),
        "params": {"patches": [
            {"path": "README.md", "contents_hex": hex::encode("hijack")}
        ]}
    }));
    assert_eq!(resp["err"]["code"], "OUT_OF_SCOPE");
    assert!(resp["err"]["message"]
        .as_str()
        .expect("message")
        .contains("README.md"));
}

fn prepare_and_cleanup(conv: &mut Conversation, base: &str, root: &Path, bundle: &Path) {
    let resp = conv.send(&json!({
        "id": 9, "method": "prepare_candidate", "token": token(ATTEMPT, FENCE),
        "params": {"change_seed": "feat", "mission": "roundtrip demo"}
    }));
    let candidate = &resp["ok"];
    assert_eq!(candidate["base_commit"], base, "prepare failed: {resp}");
    let head = candidate["head_commit"].as_str().expect("head");
    assert_eq!(head.len(), 40);
    assert_ne!(head, base);
    assert!(candidate["id"].as_str().expect("id").starts_with("can_"));
    assert_eq!(
        candidate["patch_hash"].as_str().expect("patch hash").len(),
        64
    );

    // Cleanup without a preservation receipt is refused.
    let resp = conv.send(&json!({
        "id": 10, "method": "cleanup", "token": token(ATTEMPT, FENCE),
        "params": {"deleted_at": "2026-08-24T01:00:00Z"}
    }));
    assert_eq!(resp["err"]["code"], "CLEANUP_RECEIPT_REQUIRED");

    let resp = conv.send(&json!({
        "id": 11, "method": "cleanup", "token": token(ATTEMPT, FENCE),
        "params": {
            "bundle_path": bundle.to_string_lossy(),
            "deleted_at": "2026-08-24T01:00:00Z",
        }
    }));
    assert_eq!(resp["ok"]["verified"], true, "cleanup failed: {resp}");
    assert!(bundle.is_file(), "preservation bundle written");
    assert!(
        !root.join("work").join(ATTEMPT).exists(),
        "workspace deleted"
    );
    let tombstone = resp["ok"]["tombstone"].as_str().expect("tombstone");
    assert!(Path::new(tombstone).is_file());
}

#[test]
fn stdio_conversation_covers_the_full_lifecycle() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let canary = tmp.path().join("canary");
    let home = hostile_home(tmp.path(), &canary);
    let root = tmp.path().join("farm");
    let bundle = tmp.path().join("preserve.bundle");
    let mut conv = spawn_daemon(&home);
    clone_and_read(&mut conv, &src, &base, &root);
    apply_and_checkpoint(&mut conv);
    refused_tokens_and_scope(&mut conv);
    prepare_and_cleanup(&mut conv, &base, &root, &bundle);
    assert!(!canary.exists(), "hostile hook executed inside the daemon");
    conv.finish();
}
