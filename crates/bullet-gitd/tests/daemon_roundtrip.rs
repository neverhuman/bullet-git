//! Production-binary negatives for the fail-closed stdio boundary.
//!
//! The frozen authority contract is not yet available from an immutable
//! permitted dependency, so no self-authored JSON token may reach a mutation.

use bullet_gitd::protocol::MAX_FRAME_BYTES;
use serde_json::{json, Value};
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, ChildStdin, Command, Stdio};

const NONCE: [u8; 32] = [3u8; 32];

fn token() -> Value {
    json!({
        "organization_id": "org_fixture",
        "variant_id": "var_roundtrip1",
        "attempt_id": "atm_roundtrip1",
        "attempt_fence": 7,
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

#[test]
fn self_authored_token_cannot_create_a_workspace() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("farm");
    let mut conversation = spawn_daemon(temp.path());
    let response = conversation.send(&json!({
        "id": 1,
        "method": "clone",
        "token": token(),
        "params": {
            "source_repo": "/does/not/matter",
            "base_sha": "a".repeat(40),
            "root": root,
            "created_at": "2026-08-24T00:00:00Z",
            "allowed_prefixes": ["src"],
            "commit_date": "2026-08-24T00:00:00+00:00"
        }
    }));
    assert_eq!(response["err"]["code"], "AUTHORITY_CONTRACT_UNAVAILABLE");
    assert!(!root.exists(), "authority refusal must precede clone I/O");
    conversation.finish();
}

#[test]
fn oversized_stdio_frame_is_refused_before_json_parsing() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut conversation = spawn_daemon(temp.path());
    conversation
        .stdin
        .write_all(&vec![b'x'; MAX_FRAME_BYTES + 1])
        .expect("write oversized frame");
    conversation.stdin.write_all(b"\n").expect("delimiter");
    conversation.stdin.flush().expect("flush frame");
    let mut line = String::new();
    conversation
        .reader
        .read_line(&mut line)
        .expect("read refusal");
    let response: Value = serde_json::from_str(&line).expect("response json");
    assert_eq!(response["id"], Value::Null);
    assert_eq!(response["err"]["code"], "FRAME_TOO_LARGE");
    conversation.finish();
}
