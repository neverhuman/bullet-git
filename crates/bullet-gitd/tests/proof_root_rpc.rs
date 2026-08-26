//! `bind_proof` / `verify_proof_root` are reachable on the JSONL RPC.

use bullet_git_types::{
    Candidate, CandidateManifest, Digest, GitOid, RepoPath, CANDIDATE_MANIFEST_SCHEMA_VERSION,
};
use bullet_gitd::daemon::Daemon;
use serde_json::{json, Value};
use std::str::FromStr;

fn repeated_id<T>(prefix: &str, hex: char) -> T
where
    T: TryFrom<String>,
    T::Error: std::fmt::Debug,
{
    T::try_from(format!("{prefix}_{}", hex.to_string().repeat(64))).expect("typed id")
}

fn candidate() -> Candidate {
    let manifest = CandidateManifest {
        schema_version: CANDIDATE_MANIFEST_SCHEMA_VERSION,
        repository_id: repeated_id("rep", '1'),
        change_id: repeated_id("chg", '2'),
        producing_attempt_id: repeated_id("atm", '3'),
        attempt_fence: 17,
        work_package_id: repeated_id("wpk", '4'),
        variant_id: repeated_id("var", '5'),
        plan_revision_id: repeated_id("pln", '6'),
        graph_revision_id: repeated_id("grf", '7'),
        base_checkpoint_id: repeated_id("ckp", '8'),
        base_commit: GitOid::new(format!("sha1:{}", "9".repeat(40))).expect("oid"),
        head_commit: GitOid::new(format!("sha1:{}", "a".repeat(40))).expect("oid"),
        tree_oid: GitOid::new(format!("sha1:{}", "b".repeat(40))).expect("oid"),
        patch_digest: Digest::from_bytes([12; 32]),
        parent_candidate_ids: vec![repeated_id("can", 'd')],
        granted_scope: vec![RepoPath::from_str("src").expect("path")],
        actual_scope: vec![RepoPath::from_str("src/lib.rs").expect("path")],
        context_capsule_id: repeated_id("cnt", 'e'),
        configuration_snapshot_id: repeated_id("cnt", '1'),
        policy_snapshot_id: repeated_id("cnt", '2'),
        routing_snapshot_id: repeated_id("cnt", '3'),
        environment_digest: Digest::from_bytes([14; 32]),
        toolchain_digest: Digest::from_bytes([15; 32]),
    };
    Candidate::from_manifest(manifest, "2026-08-25T00:00:00Z".into()).expect("candidate")
}

fn eight_inputs() -> Value {
    json!({
        "scope_and_write_set": "scope-grant+write-set",
        "runner_and_sandbox": "runner-sandbox",
        "toolchain_and_deps": "toolchain-deps",
        "evidence": "deterministic-evidence",
        "verifier_evidence": "verifier-evidence",
        "reviews": "reviews",
        "policy": "policy-decision",
        "approvals_and_effect_receipts": "approvals+effects"
    })
}

fn rpc(daemon: &mut Daemon, method: &str, params: Value) -> Value {
    let line = json!({"id": 1, "method": method, "params": params}).to_string();
    serde_json::from_str(&daemon.handle_line(&line)).expect("response json")
}

#[test]
fn bind_proof_and_verify_are_reachable_without_a_session() {
    let mut daemon = Daemon::new();
    let candidate = candidate();
    let inputs = eight_inputs();
    let bound = rpc(
        &mut daemon,
        "bind_proof",
        json!({"candidate": candidate, "inputs": inputs}),
    );
    assert!(bound.get("err").is_none(), "{bound}");
    let root = bound["ok"].clone();
    assert_eq!(root["candidate"], candidate.id.as_str());

    let verified = rpc(
        &mut daemon,
        "verify_proof_root",
        json!({"root": root.clone(), "candidate": candidate.clone(), "inputs": inputs.clone()}),
    );
    assert!(verified.get("err").is_none(), "{verified}");
    assert_eq!(verified["ok"]["verified"], true);

    let mut wrong_candidate_id = candidate.clone();
    wrong_candidate_id.id = repeated_id("can", 'f');
    let bind_refused = rpc(
        &mut daemon,
        "bind_proof",
        json!({"candidate": wrong_candidate_id, "inputs": inputs.clone()}),
    );
    assert_eq!(
        bind_refused["err"]["code"], "CANDIDATE_ID_MISMATCH",
        "{bind_refused}"
    );

    let mut wrong_content_id = candidate;
    wrong_content_id.content_id = repeated_id("cnt", 'f');
    let verify_refused = rpc(
        &mut daemon,
        "verify_proof_root",
        json!({"root": root, "candidate": wrong_content_id, "inputs": inputs}),
    );
    assert_eq!(
        verify_refused["err"]["code"], "CONTENT_ID_MISMATCH",
        "{verify_refused}"
    );
}

#[test]
fn verify_proof_root_refuses_a_tampered_leaf() {
    let mut daemon = Daemon::new();
    let candidate = candidate();
    let inputs = eight_inputs();
    let bound = rpc(
        &mut daemon,
        "bind_proof",
        json!({"candidate": candidate, "inputs": inputs}),
    );
    let root = bound["ok"].clone();
    let mut tampered = inputs;
    tampered["evidence"] = json!("tampered");
    let refused = rpc(
        &mut daemon,
        "verify_proof_root",
        json!({"root": root, "candidate": candidate, "inputs": tampered}),
    );
    assert_eq!(refused["err"]["code"], "PROOF_ROOT_MISMATCH", "{refused}");
}

#[test]
fn proof_rpc_requires_every_nonempty_leaf_and_rejects_unknown_fields() {
    let mut daemon = Daemon::new();
    let candidate = candidate();
    let complete = eight_inputs();
    let fields = [
        "scope_and_write_set",
        "runner_and_sandbox",
        "toolchain_and_deps",
        "evidence",
        "verifier_evidence",
        "reviews",
        "policy",
        "approvals_and_effect_receipts",
    ];

    let omitted_object = rpc(
        &mut daemon,
        "bind_proof",
        json!({"candidate": candidate.clone()}),
    );
    assert_eq!(omitted_object["err"]["code"], "BAD_REQUEST");

    for field in fields {
        let mut missing = complete.clone();
        missing
            .as_object_mut()
            .expect("proof inputs object")
            .remove(field);
        let missing_response = rpc(
            &mut daemon,
            "bind_proof",
            json!({"candidate": candidate.clone(), "inputs": missing}),
        );
        assert_eq!(missing_response["err"]["code"], "BAD_REQUEST", "{field}");

        let mut empty = complete.clone();
        empty[field] = json!("");
        let empty_response = rpc(
            &mut daemon,
            "verify_proof_root",
            json!({"root": {"candidate": candidate.id, "root": "00".repeat(32)}, "candidate": candidate.clone(), "inputs": empty}),
        );
        assert_eq!(empty_response["err"]["code"], "BAD_REQUEST", "{field}");
    }

    let mut unknown = complete;
    unknown["caller_selected_outcome"] = json!("pass");
    let unknown_response = rpc(
        &mut daemon,
        "bind_proof",
        json!({"candidate": candidate, "inputs": unknown}),
    );
    assert_eq!(unknown_response["err"]["code"], "BAD_REQUEST");
}
