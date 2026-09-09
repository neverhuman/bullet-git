//! Candidate and ProofRoot unit proofs.

use super::*;
use crate::GitOidAlgorithm;
use std::str::FromStr;

fn repeated_id<T>(prefix: &str, hex: char) -> T
where
    T: TryFrom<String>,
    T::Error: std::fmt::Debug,
{
    T::try_from(format!("{prefix}_{}", hex.to_string().repeat(64))).expect("typed id")
}

fn manifest() -> CandidateManifest {
    CandidateManifest {
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
    }
}

#[test]
fn hub_candidate_golden_is_exact() {
    let manifest = manifest();
    const HUB_CANONICAL: &str = r#"{"actual_scope":["src/lib.rs"],"attempt_fence":17,"base_checkpoint_id":"ckp_8888888888888888888888888888888888888888888888888888888888888888","base_commit":"sha1:9999999999999999999999999999999999999999","change_id":"chg_2222222222222222222222222222222222222222222222222222222222222222","configuration_snapshot_id":"cnt_1111111111111111111111111111111111111111111111111111111111111111","context_capsule_id":"cnt_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","environment_digest":"0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e0e","granted_scope":["src"],"graph_revision_id":"grf_7777777777777777777777777777777777777777777777777777777777777777","head_commit":"sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","parent_candidate_ids":["can_dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"],"patch_digest":"0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c","plan_revision_id":"pln_6666666666666666666666666666666666666666666666666666666666666666","policy_snapshot_id":"cnt_2222222222222222222222222222222222222222222222222222222222222222","producing_attempt_id":"atm_3333333333333333333333333333333333333333333333333333333333333333","repository_id":"rep_1111111111111111111111111111111111111111111111111111111111111111","routing_snapshot_id":"cnt_3333333333333333333333333333333333333333333333333333333333333333","schema_version":1,"toolchain_digest":"0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f0f","tree_oid":"sha1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","variant_id":"var_5555555555555555555555555555555555555555555555555555555555555555","work_package_id":"wpk_4444444444444444444444444444444444444444444444444444444444444444"}"#;
    assert_eq!(
        String::from_utf8(serde_jcs::to_vec(&manifest).expect("canonical")).expect("utf8"),
        HUB_CANONICAL
    );
    assert_eq!(
        manifest.candidate_id().expect("candidate").as_str(),
        "can_66da272ac2783b2e7c67ff8c3e88dc941b4853838ea24a0d133de6c619e5cdf1"
    );
    assert_eq!(
        manifest.content_id().expect("content").as_str(),
        "cnt_a37542cdff7a381b42a24e83fa1c2875506c6e8fbf492c4317c9a81f44e7c19b"
    );
}

#[test]
fn provenance_changes_leave_content_identity_reusable() {
    let original = manifest();
    let mut successor = original.clone();
    successor.attempt_fence += 1;
    successor.producing_attempt_id = repeated_id("atm", 'f');
    assert_eq!(
        original.content_id().expect("content"),
        successor.content_id().expect("content")
    );
    assert_ne!(
        original.candidate_id().expect("candidate"),
        successor.candidate_id().expect("candidate")
    );
}

#[test]
fn every_content_manifest_field_changes_content_identity() {
    let original = manifest();
    let content_id = original.content_id().expect("content");

    let mut repository = original.clone();
    repository.repository_id = repeated_id("rep", 'f');
    let mut base = original.clone();
    base.base_commit = GitOid::new(format!("sha1:{}", "0".repeat(40))).expect("oid");
    let mut head = original.clone();
    head.head_commit = GitOid::new(format!("sha1:{}", "1".repeat(40))).expect("oid");
    let mut tree = original.clone();
    tree.tree_oid = GitOid::new(format!("sha1:{}", "2".repeat(40))).expect("oid");
    let mut patch = original;
    patch.patch_digest = Digest::from_bytes([3; 32]);

    for (field, changed) in [
        ("repository_id", repository),
        ("base_commit", base),
        ("head_commit", head),
        ("tree_oid", tree),
        ("patch_digest", patch),
    ] {
        assert_ne!(
            changed.content_id().expect("content"),
            content_id,
            "{field}"
        );
    }
}

#[test]
fn observation_metadata_is_not_candidate_authority() {
    let manifest = manifest();
    let earlier = Candidate::from_manifest(manifest.clone(), "2026-08-24T00:00:00Z".into())
        .expect("candidate");
    let later =
        Candidate::from_manifest(manifest, "2026-08-25T00:00:00Z".into()).expect("candidate");
    assert_eq!(earlier.id, later.id);
    assert_eq!(earlier.content_id, later.content_id);
    assert_ne!(earlier.prepared_at, later.prepared_at);
}

#[test]
fn every_manifest_field_is_candidate_sensitive() {
    let manifest = manifest();
    let original = manifest.candidate_id().expect("candidate");
    let value = serde_json::to_value(&manifest).expect("value");
    for key in value.as_object().expect("object").keys() {
        let mut changed = value.clone();
        changed.as_object_mut().expect("object").remove(key);
        let digest = hash_canonical("candidate.provenance", &changed).expect("hash");
        assert_ne!(CandidateId::from_digest(digest), original, "field {key}");
    }
}

#[test]
fn validation_refuses_zero_fence_and_scope_escape() {
    let mut zero = manifest();
    zero.attempt_fence = 0;
    assert_eq!(
        zero.candidate_id().expect_err("zero fence").reason_code(),
        "INVALID_FENCE"
    );
    let mut escaped = manifest();
    escaped.actual_scope = vec![RepoPath::from_str("src2/lib.rs").expect("path")];
    assert_eq!(
        escaped
            .candidate_id()
            .expect_err("scope escape")
            .reason_code(),
        "ACTUAL_SCOPE_EXCEEDS_GRANT"
    );
}

#[test]
fn proof_root_changes_when_candidate_changes() {
    let a = Candidate::from_manifest(manifest(), "2026-08-24T00:00:00Z".into()).expect("candidate");
    let mut changed = manifest();
    changed.tree_oid = GitOid::from_hex(GitOidAlgorithm::Sha1, "c".repeat(40)).expect("tree");
    let b = Candidate::from_manifest(changed, "2026-08-24T00:00:00Z".into()).expect("candidate");
    let ra = ProofRoot::compute(&a, b"", b"", b"", b"");
    let rb = ProofRoot::compute(&b, b"", b"", b"", b"");
    assert_ne!(ra.root, rb.root);
    assert_eq!(ra, ProofRoot::compute(&a, b"", b"", b"", b""));
}

#[test]
fn proof_root_field_shift_does_not_collide() {
    let candidate = Candidate::from_manifest(manifest(), "observed".into()).expect("candidate");
    let one = ProofRoot::compute(&candidate, b"xy", b"", b"", b"");
    let two = ProofRoot::compute(&candidate, b"x", b"y", b"", b"");
    assert_ne!(one.root, two.root);
}

#[test]
fn evolution_kind_has_generated_refresh() {
    let kind = EvolutionKind::GeneratedRefresh;
    let json = serde_json::to_string(&kind).expect("serialize");
    assert_eq!(json, "\"generated_refresh\"");
    let back: EvolutionKind = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, kind);
}
