use super::super::transport::TransportConfig;
use super::super::wire::{call, PROTO};
use super::super::KernelPermitCheck;
use crate::authority_gateway::{
    FinalAuthorityCheck, FinalCheckInput, FinalSettlementInput, GatewayError,
    GatewayError::ContractUnavailable,
};
use crate::mutation_ledger::{MutationOperation, MutationOutcome, MutationSubject};
use bullet_git_types::Digest;
use serde::Deserialize;
use serde_json::{json, Value};
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::net::UnixListener;
use std::time::Duration;

#[derive(Debug, Deserialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
struct TestReply {
    ok: bool,
}

fn invoke(response: Vec<u8>, delay: Duration) -> Result<TestReply, GatewayError> {
    invoke_with_termination(response, delay, true)
}

fn invoke_with_termination(
    response: Vec<u8>,
    delay: Duration,
    append_newline: bool,
) -> Result<TestReply, GatewayError> {
    let (_root, config, server) = serve(response, delay, append_newline);
    let result = call(&config, "test", &json!({"bounded": true}));
    let request = server.join().expect("server");
    assert_eq!(request["proto"], PROTO);
    assert_eq!(request["id"], 1);
    assert_eq!(request["method"], "test");
    result
}

fn serve(
    response: Vec<u8>,
    delay: Duration,
    append_newline: bool,
) -> (
    tempfile::TempDir,
    TransportConfig,
    std::thread::JoinHandle<Value>,
) {
    let root = tempfile::tempdir().expect("tempdir");
    let socket = root.path().join("authority.sock");
    let listener = UnixListener::bind(&socket).expect("bind");
    std::fs::set_permissions(&socket, std::fs::Permissions::from_mode(0o660)).expect("mode");
    let meta = std::fs::metadata(&socket).expect("metadata");
    let config = TransportConfig::from_values(
        Some(socket),
        Some(OsString::from(meta.uid().to_string())),
        Some(OsString::from(meta.gid().to_string())),
        Duration::from_millis(250),
    )
    .expect("config");
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().expect("accept");
        let mut request = Vec::new();
        let mut byte = [0_u8; 1];
        loop {
            let count = stream.read(&mut byte).expect("read request");
            if count == 0 || byte[0] == b'\n' {
                break;
            }
            request.push(byte[0]);
        }
        let request: Value = serde_json::from_slice(&request).expect("request json");
        std::thread::sleep(delay);
        let _ = stream.write_all(&response);
        if append_newline {
            let _ = stream.write_all(b"\n");
        }
        request
    });
    (root, config, server)
}

fn encoded(value: Value) -> Vec<u8> {
    serde_json::to_vec(&value).expect("json")
}

fn subject(request_digest: String) -> MutationSubject {
    MutationSubject {
        authority_envelope_digest: "a".repeat(64),
        authority_token_nonce: "b".repeat(64),
        mutation_id: format!("mut_{}", "c".repeat(64)),
        reservation_id: format!("rsv_{}", "d".repeat(64)),
        operation: MutationOperation::ApplyPatch,
        request_digest,
        repository_id: format!("rep_{}", "e".repeat(64)),
        workspace_id: format!("wsp_{}", "f".repeat(64)),
        workspace_generation: 1,
        workspace_nonce: "1".repeat(64),
        attempt_id: format!("atm_{}", "2".repeat(64)),
        attempt_fence: 3,
        authority_epoch: 4,
        freeze_generation: 0,
        permit_nonce: "3".repeat(64),
        permit_digest: "4".repeat(64),
    }
}

#[test]
fn exact_closed_success_and_error_envelopes_are_distinct() {
    let success = invoke(
        encoded(json!({"proto": PROTO, "id": 1, "result": {"ok": true}})),
        Duration::ZERO,
    )
    .expect("success");
    assert_eq!(success, TestReply { ok: true });

    let error = invoke(
        encoded(json!({
            "proto": PROTO,
            "id": 1,
            "error": {"code": "AUTHORITY_CONTRACT_UNAVAILABLE", "message": "blocked"}
        })),
        Duration::ZERO,
    )
    .expect_err("typed refusal");
    assert!(matches!(error, ContractUnavailable(message) if message == "blocked"));
}

#[test]
fn kernel_checker_maps_exact_check_and_settlement_requests() {
    let transport_fingerprint = Digest::of(b"exact checked request");
    let subject = subject(transport_fingerprint.to_hex());
    let authority = json!({
        "paseto": "signed-envelope",
        "kernel_permit": {"token": "one-use"},
        "nested": {"kernel_permit": "domain-data"}
    });
    let params = json!({"path": "src/lib.rs"});
    let check_response = encoded(json!({
        "proto": PROTO,
        "id": 1,
        "result": {
            "subject": subject,
            "operation": "apply-patch",
            "transport_fingerprint": transport_fingerprint.to_hex(),
            "expires_at_unix_ms": 500
        }
    }));
    let (_check_root, check_transport, check_server) = serve(check_response, Duration::ZERO, true);
    let mut checker = KernelPermitCheck {
        transport: Ok(check_transport),
    };
    let decision = checker
        .check(&FinalCheckInput {
            operation: MutationOperation::ApplyPatch,
            authority: &authority,
            params: &params,
            transport_fingerprint,
        })
        .expect("mapped check reply");
    assert_eq!(decision.subject, subject);
    assert_eq!(decision.operation, MutationOperation::ApplyPatch);
    assert_eq!(decision.transport_fingerprint, transport_fingerprint);
    assert_eq!(decision.expires_at_unix_ms, 500);
    let check_request = check_server.join().expect("check server");
    assert_eq!(check_request["proto"], PROTO);
    assert_eq!(check_request["id"], 1);
    assert_eq!(check_request["method"], "check");
    assert_eq!(check_request["params"]["operation"], "apply-patch");
    assert_eq!(check_request["params"]["params"], params);
    assert_eq!(
        check_request["params"]["authority"],
        json!({
            "paseto": "signed-envelope",
            "nested": {"kernel_permit": "domain-data"}
        })
    );
    assert_eq!(
        check_request["params"]["kernel_permit"],
        json!({"token": "one-use"})
    );
    assert_eq!(
        check_request["params"]["transport_fingerprint"],
        transport_fingerprint.to_hex()
    );

    let result_digest = "5".repeat(64);
    let settlement_fingerprint = Digest::of(b"exact settlement");
    let settle_response = encoded(json!({
        "proto": PROTO,
        "id": 1,
        "result": {
            "mutation_id": subject.mutation_id,
            "reservation_id": subject.reservation_id,
            "result_digest": result_digest,
            "settlement_fingerprint": settlement_fingerprint.to_hex()
        }
    }));
    let (_settle_root, settle_transport, settle_server) =
        serve(settle_response, Duration::ZERO, true);
    let mut checker = KernelPermitCheck {
        transport: Ok(settle_transport),
    };
    let acknowledgment = checker
        .settle(&FinalSettlementInput {
            subject: &subject,
            outcome: MutationOutcome::Committed,
            result_digest: &result_digest,
            completed_at_unix_ms: 600,
            settlement_fingerprint,
        })
        .expect("mapped settlement reply");
    assert_eq!(acknowledgment.mutation_id, subject.mutation_id);
    assert_eq!(acknowledgment.reservation_id, subject.reservation_id);
    assert_eq!(acknowledgment.result_digest, result_digest);
    assert_eq!(
        acknowledgment.settlement_fingerprint,
        settlement_fingerprint
    );
    let settle_request = settle_server.join().expect("settle server");
    assert_eq!(settle_request["proto"], PROTO);
    assert_eq!(settle_request["id"], 1);
    assert_eq!(settle_request["method"], "settle");
    assert_eq!(
        settle_request["params"]["subject"],
        serde_json::to_value(&subject).expect("subject JSON")
    );
    assert_eq!(settle_request["params"]["outcome"], "committed");
    assert_eq!(settle_request["params"]["result_digest"], result_digest);
    assert_eq!(settle_request["params"]["completed_at_unix_ms"], 600);
    assert_eq!(
        settle_request["params"]["settlement_fingerprint"],
        settlement_fingerprint.to_hex()
    );
}

#[test]
fn protocol_id_unknown_ambiguous_and_malformed_replies_refuse() {
    let hostiles = [
        encoded(json!({"proto": "wrong", "id": 1, "result": {"ok": true}})),
        encoded(json!({"proto": PROTO, "id": 2, "result": {"ok": true}})),
        encoded(json!({"proto": PROTO, "id": 1, "result": {"ok": true}, "extra": 1})),
        encoded(json!({"proto": PROTO, "id": 1, "result": {"ok": true, "extra": 1}})),
        encoded(json!({
            "proto": PROTO,
            "id": 1,
            "result": {"ok": true},
            "error": {"code": "AUTHORITY_REFUSED", "message": "ambiguous"}
        })),
        encoded(json!({
            "proto": PROTO,
            "id": 1,
            "result": null,
            "error": {"code": "AUTHORITY_REFUSED", "message": "ambiguous"}
        })),
        encoded(json!({
            "proto": PROTO,
            "id": 1,
            "result": {"ok": true},
            "error": null
        })),
        encoded(json!({"proto": PROTO, "id": 1, "result": {"ok": null}})),
        encoded(json!({"proto": PROTO, "id": 1, "result": null})),
        encoded(json!({"proto": PROTO, "id": 1, "error": null})),
        encoded(json!({"proto": PROTO, "id": 1})),
        encoded(json!({
            "proto": PROTO,
            "id": 1,
            "error": {"code": "AUTHORITY_REFUSED", "message": "no", "extra": 1}
        })),
        br#"{"proto":"bullet-farm.kernel-authority.rpc.v1","id":1,"result":{"ok":true}"#.to_vec(),
        br#"{"proto":"bullet-farm.kernel-authority.rpc.v1","proto":"bullet-farm.kernel-authority.rpc.v1","id":1,"result":{"ok":true}}"#.to_vec(),
    ];
    for response in hostiles {
        let error = invoke(response, Duration::ZERO).expect_err("hostile reply");
        assert_eq!(error.reason_code(), "AUTHORITY_REFUSED");
    }

    let oversized = invoke(vec![b'x'; 65_537], Duration::ZERO).expect_err("oversized reply");
    assert_eq!(oversized.reason_code(), "AUTHORITY_REFUSED");

    let eof = invoke_with_termination(
        encoded(json!({"proto": PROTO, "id": 1, "result": {"ok": true}})),
        Duration::ZERO,
        false,
    )
    .expect_err("EOF before newline");
    assert_eq!(eof.reason_code(), "AUTHORITY_REFUSED");
}

#[test]
fn stalled_reply_hits_the_read_deadline() {
    let error = invoke(
        encoded(json!({"proto": PROTO, "id": 1, "result": {"ok": true}})),
        Duration::from_millis(750),
    )
    .expect_err("timeout");
    assert_eq!(error.reason_code(), "AUTHORITY_REFUSED");
    assert!(error.to_string().contains("deadline exceeded"));
}
