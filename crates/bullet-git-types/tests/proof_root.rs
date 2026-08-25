//! Eight-leaf ProofRoot bind, verify-on-read, and one tamper per input.

use bullet_git_types::{
    verify_proof_root, Candidate, CandidateManifest, Digest, GitOid, ProofInputs, ProofRoot,
    RepoPath, CANDIDATE_MANIFEST_SCHEMA_VERSION,
};
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

fn populated_inputs() -> ProofInputs<'static> {
    ProofInputs {
        scope_and_write_set: b"scope-grant+write-set",
        runner_and_sandbox: b"runner-sandbox",
        toolchain_and_deps: b"toolchain-deps",
        evidence: b"deterministic-evidence",
        verifier_evidence: b"verifier-evidence",
        reviews: b"reviews",
        policy: b"policy-decision",
        approvals_and_effect_receipts: b"approvals+effects",
    }
}

#[test]
fn proof_root_bind_is_stable_and_verify_accepts_the_same_inputs() {
    let candidate = candidate();
    let inputs = populated_inputs();
    let root = ProofRoot::bind(&candidate, &inputs);
    assert_eq!(root.candidate, candidate.id);
    verify_proof_root(&root, &candidate, &inputs).expect("verify");
    assert_eq!(root, ProofRoot::bind(&candidate, &inputs));
}

#[test]
fn proof_root_each_of_the_eight_leaves_is_tamper_evident() {
    let candidate = candidate();
    let inputs = populated_inputs();
    let root = ProofRoot::bind(&candidate, &inputs);
    let flipped = b"tampered";
    for (name, _) in inputs.named_leaves() {
        let mut tampered = inputs;
        match name {
            "scope_and_write_set" => tampered.scope_and_write_set = flipped,
            "runner_and_sandbox" => tampered.runner_and_sandbox = flipped,
            "toolchain_and_deps" => tampered.toolchain_and_deps = flipped,
            "evidence" => tampered.evidence = flipped,
            "verifier_evidence" => tampered.verifier_evidence = flipped,
            "reviews" => tampered.reviews = flipped,
            "policy" => tampered.policy = flipped,
            "approvals_and_effect_receipts" => tampered.approvals_and_effect_receipts = flipped,
            other => panic!("unexpected leaf {other}"),
        }
        let error = verify_proof_root(&root, &candidate, &tampered).expect_err(name);
        assert_eq!(error.reason_code(), "PROOF_ROOT_MISMATCH", "{name}");
        assert_ne!(root, ProofRoot::bind(&candidate, &tampered), "{name}");
    }
}

#[test]
fn proof_root_eight_leaf_field_shift_does_not_collide() {
    let candidate = candidate();
    let split = ProofInputs {
        scope_and_write_set: b"ab",
        runner_and_sandbox: b"c",
        ..ProofInputs::empty()
    };
    let merged = ProofInputs {
        scope_and_write_set: b"a",
        runner_and_sandbox: b"bc",
        ..ProofInputs::empty()
    };
    assert_ne!(
        ProofRoot::bind(&candidate, &split).root,
        ProofRoot::bind(&candidate, &merged).root
    );
}

#[test]
fn proof_root_compute_maps_historical_blobs_onto_the_eight_leaf_bind() {
    let candidate = candidate();
    let via_compute = ProofRoot::compute(&candidate, b"scope", b"evidence", b"reviews", b"policy");
    let via_bind = ProofRoot::bind(
        &candidate,
        &ProofInputs {
            scope_and_write_set: b"scope",
            evidence: b"evidence",
            reviews: b"reviews",
            policy: b"policy",
            ..ProofInputs::empty()
        },
    );
    assert_eq!(via_compute, via_bind);
    verify_proof_root(&via_compute, &candidate, &via_bind_inputs()).expect("historical mapping");
}

fn via_bind_inputs() -> ProofInputs<'static> {
    ProofInputs {
        scope_and_write_set: b"scope",
        evidence: b"evidence",
        reviews: b"reviews",
        policy: b"policy",
        ..ProofInputs::empty()
    }
}

#[test]
fn proof_root_candidate_identity_change_fails_verify() {
    let original = candidate();
    let mut changed = original.manifest.clone();
    changed.tree_oid = GitOid::new(format!("sha1:{}", "c".repeat(40))).expect("tree");
    let other = Candidate::from_manifest(changed, "2026-08-25T00:00:00Z".into()).expect("other");
    let inputs = ProofInputs::empty();
    let root = ProofRoot::bind(&original, &inputs);
    assert_eq!(
        verify_proof_root(&root, &other, &inputs)
            .expect_err("other candidate")
            .reason_code(),
        "PROOF_ROOT_MISMATCH"
    );
}
