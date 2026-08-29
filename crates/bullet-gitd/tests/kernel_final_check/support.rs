use bullet_git_types::{framed_digest, Digest};
use bullet_gitd::daemon::Daemon;
use bullet_gitd::mutation_ledger::{MutationOperation, MutationSubject};
use serde_json::{json, Value};
use std::env;
use std::ffi::OsString;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const PROTO: &str = "bullet-farm.kernel-authority.rpc.v1";
const ENV_SOCKET: &str = "BULLET_KERNEL_AUTHORITY_SOCKET";
const ENV_UID: &str = "BULLET_KERNEL_AUTHORITY_SERVER_UID";
const ENV_GID: &str = "BULLET_KERNEL_AUTHORITY_SOCKET_GID";
const ATTEMPT: &str = "atm_1111111111111111111111111111111111111111111111111111111111111111";
const VARIANT: &str = "var_2222222222222222222222222222222222222222222222222222222222222222";
pub const MUTATION: &str = "mut_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const NONCE: [u8; 32] = [9; 32];
const FENCE: u64 = 7;
const LINE_MAX: usize = 65_536;

struct EnvGuard([Option<OsString>; 3]);

impl EnvGuard {
    fn install(socket: Option<&Path>, uid: Option<&str>, gid: Option<&str>) -> Self {
        let prior = [ENV_SOCKET, ENV_UID, ENV_GID].map(env::var_os);
        set_env(ENV_SOCKET, socket.map(Path::as_os_str));
        set_env(ENV_UID, uid.map(AsRef::as_ref));
        set_env(ENV_GID, gid.map(AsRef::as_ref));
        Self(prior)
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        for (name, prior) in [ENV_SOCKET, ENV_UID, ENV_GID].into_iter().zip(&self.0) {
            set_env(name, prior.as_deref());
        }
    }
}

fn set_env(name: &str, value: Option<&std::ffi::OsStr>) {
    match value {
        Some(value) => env::set_var(name, value),
        None => env::remove_var(name),
    }
}

pub fn configured(socket: Option<&Path>, uid: Option<&str>, gid: Option<&str>) -> Daemon {
    let _guard = EnvGuard::install(socket, uid, gid);
    Daemon::new()
}

pub struct BoundSocket {
    _dir: tempfile::TempDir,
    pub path: PathBuf,
    listener: UnixListener,
    pub uid: u32,
    pub gid: u32,
}

impl BoundSocket {
    pub fn new() -> Self {
        let dir = tempfile::tempdir().expect("socket tempdir");
        let parent = std::fs::canonicalize(dir.path()).expect("canonical socket directory");
        let path = parent.join("authority.sock");
        let listener = UnixListener::bind(&path).expect("bind fake Kernel");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).expect("mode");
        let meta = std::fs::metadata(&path).expect("socket metadata");
        Self {
            _dir: dir,
            path,
            listener,
            uid: meta.uid(),
            gid: meta.gid(),
        }
    }

    pub fn assert_unreached(&self) {
        self.listener.set_nonblocking(true).expect("nonblocking");
        match self.listener.accept() {
            Err(error) if error.kind() == ErrorKind::WouldBlock => {}
            other => panic!("identity refusal reached fake Kernel: {other:?}"),
        }
    }
}

#[derive(Clone)]
pub struct Expected {
    authority: Value,
    params: Value,
    permit: Value,
    fingerprint: String,
    pub subject: MutationSubject,
}

impl Expected {
    pub fn new(request: &Value) -> Self {
        let mut authority = request["token"].clone();
        let permit = authority
            .as_object_mut()
            .expect("authority object")
            .remove("kernel_permit")
            .expect("Kernel permit");
        let params = request["params"].clone();
        let authority_bytes = serde_json::to_vec(&authority).expect("authority JSON");
        let params_bytes = serde_json::to_vec(&params).expect("params JSON");
        let fingerprint = framed_digest(&[
            b"bullet-gitd.pre-contract-request-fingerprint.v1",
            b"clone-workspace",
            &authority_bytes,
            &params_bytes,
        ])
        .to_hex();
        Self {
            authority,
            params,
            permit,
            subject: subject(fingerprint.clone()),
            fingerprint,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Plan {
    Exact,
    Expired,
    Deny,
    DigestMismatch,
    WrongProto,
    WrongId,
    Unknown,
    Ambiguous,
    Malformed,
    Oversized,
    Eof,
    Slow,
}

pub struct Server {
    _dir: tempfile::TempDir,
    path: PathBuf,
    uid: u32,
    gid: u32,
    handle: JoinHandle<Vec<Value>>,
}

impl Server {
    pub fn start(plan: Plan, expected: Expected) -> Self {
        let BoundSocket {
            _dir,
            path,
            listener,
            uid,
            gid,
        } = BoundSocket::new();
        let handle = thread::spawn(move || serve(listener, plan, &expected));
        Self {
            _dir,
            path,
            uid,
            gid,
            handle,
        }
    }

    pub fn daemon(&self) -> Daemon {
        let uid = self.uid.to_string();
        let gid = self.gid.to_string();
        configured(Some(&self.path), Some(&uid), Some(&gid))
    }

    pub fn finish(self) -> Vec<Value> {
        self.handle.join().expect("bounded fake Kernel")
    }
}

fn serve(listener: UnixListener, plan: Plan, expected: &Expected) -> Vec<Value> {
    let mut stream = accept_bounded(&listener);
    let check = read_bounded(&mut stream);
    let checked_at = validate_check(&check, expected);
    let mut reply = check_reply(expected, checked_at);
    match plan {
        Plan::Exact => write_json(&mut stream, &reply, true),
        Plan::Expired => {
            reply["result"]["expires_at_unix_ms"] = json!(checked_at);
            write_json(&mut stream, &reply, true);
        }
        Plan::Deny => write_json(
            &mut stream,
            &json!({"proto": PROTO, "id": 1,
                "error": {"code": "POLICY_REFUSED", "message": "operator policy denied"}}),
            true,
        ),
        Plan::DigestMismatch => {
            reply["result"]["subject"]["request_digest"] = json!("0".repeat(64));
            write_json(&mut stream, &reply, true);
        }
        Plan::WrongProto => {
            reply["proto"] = json!("bullet-farm.kernel-authority.rpc.v0");
            write_json(&mut stream, &reply, true);
        }
        Plan::WrongId => {
            reply["id"] = json!(2);
            write_json(&mut stream, &reply, true);
        }
        Plan::Unknown => {
            reply["result"]["subject"]["caller_selected_outcome"] = json!("approve");
            write_json(&mut stream, &reply, true);
        }
        Plan::Ambiguous => {
            reply["error"] = json!({"code": "POLICY_REFUSED", "message": "ambiguous"});
            write_json(&mut stream, &reply, true);
        }
        Plan::Malformed => write_raw(&mut stream, br#"{"proto":"broken""#, true),
        Plan::Oversized => write_raw(&mut stream, &vec![b'x'; LINE_MAX + 1], false),
        Plan::Eof => write_json(&mut stream, &reply, false),
        Plan::Slow => {
            thread::sleep(Duration::from_millis(1_200));
            write_json(&mut stream, &reply, true);
        }
    }
    drop(stream);
    let mut requests = vec![check];
    if matches!(plan, Plan::Exact | Plan::Expired) {
        let mut stream = accept_bounded(&listener);
        let settle = read_bounded(&mut stream);
        let outcome = if plan == Plan::Exact {
            "committed"
        } else {
            "aborted"
        };
        let (result, fingerprint) = validate_settle(&settle, expected, checked_at, outcome);
        write_json(
            &mut stream,
            &json!({"proto": PROTO, "id": 1, "result": {
                "mutation_id": expected.subject.mutation_id,
                "reservation_id": expected.subject.reservation_id,
                "result_digest": result,
                "settlement_fingerprint": fingerprint}}),
            true,
        );
        requests.push(settle);
    }
    requests
}

fn accept_bounded(listener: &UnixListener) -> UnixStream {
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .expect("read timeout");
                stream
                    .set_write_timeout(Some(Duration::from_secs(2)))
                    .expect("write timeout");
                return stream;
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(5));
            }
            other => panic!("bounded fake Kernel accept failed: {other:?}"),
        }
    }
}

fn read_bounded(stream: &mut UnixStream) -> Value {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        assert!(bytes.len() < LINE_MAX, "request exceeded bound");
        match stream.read(&mut byte).expect("bounded request read") {
            0 => panic!("request ended before newline"),
            _ if byte[0] == b'\n' => break,
            _ => bytes.push(byte[0]),
        }
    }
    serde_json::from_slice(&bytes).expect("request JSON")
}

fn write_json(stream: &mut UnixStream, value: &Value, newline: bool) {
    write_raw(
        stream,
        &serde_json::to_vec(value).expect("reply JSON"),
        newline,
    );
}

fn write_raw(stream: &mut UnixStream, bytes: &[u8], newline: bool) {
    let _ = stream.write_all(bytes);
    if newline {
        let _ = stream.write_all(b"\n");
    }
}

fn validate_check(check: &Value, expected: &Expected) -> u64 {
    let now = check["now_unix_ms"].as_u64().expect("check time");
    assert_eq!(
        check,
        &json!({"proto": PROTO, "id": 1, "method": "check", "params": {
            "operation": "clone-workspace", "authority": expected.authority,
            "params": expected.params, "kernel_permit": expected.permit,
            "transport_fingerprint": expected.fingerprint}, "now_unix_ms": now})
    );
    now
}

fn check_reply(expected: &Expected, now: u64) -> Value {
    json!({"proto": PROTO, "id": 1, "result": {
        "subject": expected.subject, "operation": "clone-workspace",
        "transport_fingerprint": expected.fingerprint,
        "expires_at_unix_ms": now.checked_add(900).expect("expiry")}})
}

fn validate_settle(
    settle: &Value,
    expected: &Expected,
    checked_at: u64,
    outcome: &str,
) -> (String, String) {
    let rpc_now = settle["now_unix_ms"].as_u64().expect("settle RPC time");
    let params = &settle["params"];
    let completed = params["completed_at_unix_ms"]
        .as_u64()
        .expect("completion time");
    let result = Digest::from_hex(params["result_digest"].as_str().expect("result digest"))
        .expect("lowercase result digest")
        .to_hex();
    assert!(checked_at <= completed && completed <= rpc_now);
    assert!(rpc_now <= now_ms().saturating_add(1_000));
    if outcome == "aborted" {
        let abort_digest = framed_digest(&[
            b"bullet-gitd.pre-repository-abort.v1",
            b"clone-workspace",
            b"MUTATION_PERMIT_EXPIRED",
        ])
        .to_hex();
        assert_eq!(result, abort_digest);
    }
    let fingerprint = settlement_fingerprint(&expected.subject, outcome, &result, completed);
    assert_eq!(
        settle,
        &json!({"proto": PROTO, "id": 1, "method": "settle", "params": {
            "subject": expected.subject, "outcome": outcome, "result_digest": result,
            "completed_at_unix_ms": completed, "settlement_fingerprint": fingerprint},
            "now_unix_ms": rpc_now})
    );
    (result, fingerprint)
}

fn settlement_fingerprint(
    subject: &MutationSubject,
    outcome: &str,
    result: &str,
    completed: u64,
) -> String {
    let numbers = [
        subject.workspace_generation.to_string(),
        subject.attempt_fence.to_string(),
        subject.authority_epoch.to_string(),
        subject.freeze_generation.to_string(),
        completed.to_string(),
    ];
    framed_digest(&[
        b"bullet-gitd.pre-contract-settlement-fingerprint.v1",
        subject.authority_envelope_digest.as_bytes(),
        subject.authority_token_nonce.as_bytes(),
        subject.mutation_id.as_bytes(),
        subject.reservation_id.as_bytes(),
        subject.operation.as_str().as_bytes(),
        subject.request_digest.as_bytes(),
        subject.repository_id.as_bytes(),
        subject.workspace_id.as_bytes(),
        numbers[0].as_bytes(),
        subject.workspace_nonce.as_bytes(),
        subject.attempt_id.as_bytes(),
        numbers[1].as_bytes(),
        numbers[2].as_bytes(),
        numbers[3].as_bytes(),
        subject.permit_nonce.as_bytes(),
        subject.permit_digest.as_bytes(),
        outcome.as_bytes(),
        result.as_bytes(),
        numbers[4].as_bytes(),
    ])
    .to_hex()
}

fn subject(request_digest: String) -> MutationSubject {
    MutationSubject {
        authority_envelope_digest: "a".repeat(64),
        authority_token_nonce: "b".repeat(64),
        mutation_id: MUTATION.into(),
        reservation_id: format!("rsv_{}", "d".repeat(64)),
        operation: MutationOperation::CloneWorkspace,
        request_digest,
        repository_id: format!("rep_{}", "e".repeat(64)),
        workspace_id: format!("wsp_{}", "f".repeat(64)),
        workspace_generation: 1,
        workspace_nonce: hex::encode(NONCE),
        attempt_id: ATTEMPT.into(),
        attempt_fence: FENCE,
        authority_epoch: 1,
        freeze_generation: 0,
        permit_nonce: "1".repeat(64),
        permit_digest: "2".repeat(64),
    }
}

pub fn clone_request(source: &Path, base: &str, root: &Path) -> Value {
    json!({"id": 1, "method": "clone", "token": {
        "organization_id": "org_fixture", "variant_id": VARIANT, "attempt_id": ATTEMPT,
        "attempt_fence": FENCE, "workspace_nonce": NONCE, "runner_epoch": 1,
        "kernel_permit": {"paseto": "opaque-one-use-permit"},
        "nested": {"kernel_permit": "domain-data"}}, "params": {
        "source_repo": source, "base_sha": format!("sha1:{base}"), "root": root,
        "created_at": "2026-08-24T00:00:00Z", "allowed_prefixes": ["src"],
        "commit_date": "2026-08-24T00:00:00+00:00"}})
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("wall clock")
        .as_millis()
        .try_into()
        .expect("millisecond range")
}

pub fn other_id(id: u32) -> String {
    if id == u32::MAX { id - 1 } else { id + 1 }.to_string()
}
