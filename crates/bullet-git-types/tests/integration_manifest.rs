//! IntegrationManifest canonical identity, IntegrationRoot bind/verify, and
//! hostile candidate-set / target inputs.

use bullet_git_types::{
    combined_proof_root, CandidateId, ContentId, Digest, GitOid, IntegrationId, IntegrationInputs,
    IntegrationManifest, IntegrationRoot, ProofRoot, INTEGRATION_MANIFEST_SCHEMA_VERSION,
    MAX_INTEGRATION_CANDIDATES,
};

fn repeated_id<T>(prefix: &str, hex: char) -> T
where
    T: TryFrom<String>,
    T::Error: std::fmt::Debug,
{
    T::try_from(format!("{prefix}_{}", hex.to_string().repeat(64))).expect("typed id")
}

fn sha1(hex: char) -> GitOid {
    GitOid::new(format!("sha1:{}", hex.to_string().repeat(40))).expect("oid")
}

fn candidate_roots() -> Vec<ProofRoot> {
    vec![
        ProofRoot {
            candidate: repeated_id("can", 'a'),
            root: Digest::from_bytes([1; 32]),
        },
        ProofRoot {
            candidate: repeated_id("can", 'b'),
            root: Digest::from_bytes([2; 32]),
        },
    ]
}

fn manifest() -> IntegrationManifest {
    IntegrationManifest {
        schema_version: INTEGRATION_MANIFEST_SCHEMA_VERSION,
        target_ref: "refs/heads/main".into(),
        target_sha: sha1('1'),
        candidate_ids: vec![repeated_id("can", 'a'), repeated_id("can", 'b')],
        merge_group_sha: Some(sha1('2')),
        proof_root: combined_proof_root(&candidate_roots()),
        policy_snapshot_id: repeated_id("cnt", '4'),
    }
}

fn populated_inputs() -> IntegrationInputs<'static> {
    IntegrationInputs {
        merge_method: b"merge-method",
        conflict_resolutions: b"conflict-resolutions",
        integration_evidence: b"integration-evidence",
        approvals_and_effect_receipts: b"approvals+effects",
    }
}

#[test]
fn integration_golden_canonical_encoding_id_and_root_are_stable() {
    const CANONICAL: &str = r#"{"candidate_ids":["can_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","can_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"merge_group_sha":"sha1:2222222222222222222222222222222222222222","policy_snapshot_id":"cnt_4444444444444444444444444444444444444444444444444444444444444444","proof_root":"551dabb68756698cc35b140175dffd4b9c26b748a9903bb39a5becadfc0dc52f","schema_version":1,"target_ref":"refs/heads/main","target_sha":"sha1:1111111111111111111111111111111111111111"}"#;
    let manifest = manifest();
    assert_eq!(
        String::from_utf8(serde_jcs::to_vec(&manifest).expect("canonical")).expect("utf8"),
        CANONICAL
    );
    assert_eq!(
        manifest.integration_id().expect("id").as_str(),
        "int_78779dfab17a494508cda1a9b5eeab009c5e0801db4d92c98c97283404af0937"
    );
    let root =
        IntegrationRoot::bind(&manifest, &candidate_roots(), &populated_inputs()).expect("root");
    assert_eq!(
        root.root.to_hex(),
        "798dc9a72a194601c853543e373c80662a033c411b7a863610d82ae124edbd33"
    );
    let json = serde_json::to_string(&manifest).expect("json");
    let back: IntegrationManifest = serde_json::from_str(&json).expect("round trip");
    assert_eq!(back, manifest);
}

#[test]
fn every_integration_manifest_field_is_identity_sensitive() {
    let original = manifest();
    let id = original.integration_id().expect("id");
    let mut target_ref = original.clone();
    target_ref.target_ref = "refs/heads/release".into();
    let mut target_sha = original.clone();
    target_sha.target_sha = sha1('9');
    let mut candidates = original.clone();
    candidates.candidate_ids = vec![repeated_id("can", 'a'), repeated_id("can", 'c')];
    let mut reordered = original.clone();
    reordered.candidate_ids.reverse();
    let mut merge_group_none = original.clone();
    merge_group_none.merge_group_sha = None;
    let mut merge_group_other = original.clone();
    merge_group_other.merge_group_sha = Some(sha1('8'));
    let mut proof_root = original.clone();
    proof_root.proof_root = Digest::from_bytes([7; 32]);
    let mut policy = original.clone();
    policy.policy_snapshot_id = repeated_id("cnt", '6');
    let cases = [
        ("target_ref", target_ref),
        ("target_sha", target_sha),
        ("candidate_ids", candidates),
        ("candidate_ids order", reordered),
        ("merge_group_sha none", merge_group_none),
        ("merge_group_sha other", merge_group_other),
        ("proof_root", proof_root),
        ("policy_snapshot_id", policy),
    ];
    let mut seen = std::collections::BTreeSet::new();
    for (field, changed) in &cases {
        let changed_id = changed.integration_id().expect(field);
        assert_ne!(changed_id, id, "{field}");
        assert!(
            seen.insert(changed_id),
            "{field} collided with another case"
        );
    }
    let value = serde_json::to_value(&original).expect("value");
    let fields = value.as_object().expect("object").len();
    let distinct_fields = cases
        .iter()
        .map(|(name, _)| name.split(' ').next().expect("field"))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(distinct_fields.len() + 1, fields, "unswept manifest field");
    let mut schema = original;
    schema.schema_version = 2;
    assert_eq!(
        schema.integration_id().expect_err("schema").reason_code(),
        "UNSUPPORTED_SCHEMA"
    );
}

#[test]
fn hostile_duplicate_candidate_ids_are_refused() {
    let mut duplicate = manifest();
    duplicate.candidate_ids = vec![
        repeated_id("can", 'a'),
        repeated_id("can", 'b'),
        repeated_id("can", 'a'),
    ];
    let error = duplicate.integration_id().expect_err("duplicate");
    assert_eq!(error.reason_code(), "DUPLICATE_CANDIDATE_ID");
    assert!(IntegrationRoot::bind(
        &duplicate,
        &candidate_roots(),
        &IntegrationInputs::default()
    )
    .is_err());
}

#[test]
fn hostile_empty_candidate_set_is_refused() {
    let mut empty = manifest();
    empty.candidate_ids.clear();
    assert_eq!(
        empty.integration_id().expect_err("empty").reason_code(),
        "EMPTY_CANDIDATE_SET"
    );
    let mut oversized = manifest();
    oversized.candidate_ids = (0..=MAX_INTEGRATION_CANDIDATES)
        .map(|index| CandidateId::from_seed(&index.to_string()))
        .collect();
    assert_eq!(
        oversized
            .integration_id()
            .expect_err("oversized")
            .reason_code(),
        "CANDIDATE_SET_TOO_LARGE"
    );
}

#[test]
fn hostile_malformed_target_sha_is_refused_at_the_type_boundary() {
    GitOid::new("sha1:1111111111111111111111111111111111111111").expect("well-formed sha1");
    for raw in [
        "1111111111111111111111111111111111111111",
        "sha1:111111111111111111111111111111111111111",
        "sha1:1111111111111111111111111111111111111111x",
        "sha1:111111111111111111111111111111111111111G",
        "SHA1:1111111111111111111111111111111111111111",
        "sha1:1111111111111111111111111111111111111111\n",
        "md5:11111111111111111111111111111111",
        "",
    ] {
        assert_eq!(
            GitOid::new(raw).expect_err(raw).reason_code(),
            "INVALID_OID",
            "{raw:?}"
        );
        let json = serde_json::to_string(&manifest())
            .expect("json")
            .replace("sha1:1111111111111111111111111111111111111111", raw);
        assert!(
            serde_json::from_str::<IntegrationManifest>(&json).is_err(),
            "{raw:?} deserialized"
        );
    }
}

#[test]
fn hostile_target_ref_shapes_are_refused() {
    let accepted = ["refs/heads/main", "refs/heads/release/v1.2", "refs/tags/v1"];
    for target_ref in accepted {
        let mut manifest = manifest();
        manifest.target_ref = target_ref.into();
        manifest.integration_id().expect(target_ref);
    }
    let refused = [
        "",
        "main",
        "refs/",
        "refs/heads/",
        "refs/heads/main.lock",
        "refs/heads/ma in",
        "refs/heads/../main",
        "refs//heads/main",
        "refs/heads/.hidden",
        "refs/heads/main@{1}",
        "refs/heads/main~1",
        "refs/heads/main^",
        "refs/heads/ma:in",
        "refs/heads/ma?in",
        "refs/heads/ma*in",
        "refs/heads/ma[in",
        "refs/heads/ma\\in",
        "refs/heads/main.",
        "refs/heads/m\u{e9}n",
    ];
    for target_ref in refused {
        let mut manifest = manifest();
        manifest.target_ref = target_ref.into();
        assert_eq!(
            manifest
                .integration_id()
                .expect_err(target_ref)
                .reason_code(),
            "INVALID_TARGET_REF",
            "{target_ref:?}"
        );
    }
    let mut oversized = manifest();
    oversized.target_ref = format!("refs/heads/{}", "a".repeat(300));
    assert_eq!(
        oversized.integration_id().expect_err("long").reason_code(),
        "INVALID_TARGET_REF"
    );
}

#[test]
fn hostile_merge_group_equal_to_target_is_refused() {
    let mut same = manifest();
    same.merge_group_sha = Some(same.target_sha.clone());
    assert_eq!(
        same.integration_id().expect_err("same").reason_code(),
        "MERGE_GROUP_EQUALS_TARGET"
    );
}

#[test]
fn integration_root_each_of_the_four_leaves_is_tamper_evident() {
    let manifest = manifest();
    let inputs = populated_inputs();
    let root = IntegrationRoot::bind(&manifest, &candidate_roots(), &inputs).expect("root");
    assert_eq!(root.subject, manifest.integration_id().expect("id"));
    root.verify(&manifest, &candidate_roots(), &inputs)
        .expect("verify");
    for (name, _) in inputs.named_leaves() {
        let mut tampered = inputs;
        match name {
            "merge_method" => tampered.merge_method = b"tampered",
            "conflict_resolutions" => tampered.conflict_resolutions = b"tampered",
            "integration_evidence" => tampered.integration_evidence = b"tampered",
            "approvals_and_effect_receipts" => tampered.approvals_and_effect_receipts = b"tampered",
            other => panic!("unexpected leaf {other}"),
        }
        assert_eq!(
            root.verify(&manifest, &candidate_roots(), &tampered)
                .expect_err(name)
                .reason_code(),
            "INTEGRATION_ROOT_MISMATCH",
            "{name}"
        );
    }
    let mut other = manifest.clone();
    other.target_sha = sha1('f');
    assert_eq!(
        root.verify(&other, &candidate_roots(), &inputs)
            .expect_err("other subject")
            .reason_code(),
        "INTEGRATION_ROOT_MISMATCH"
    );
    let mut forged_subject = root.clone();
    forged_subject.subject = IntegrationId::from_digest(Digest::from_bytes([0; 32]));
    assert_eq!(
        forged_subject
            .verify(&manifest, &candidate_roots(), &inputs)
            .expect_err("forged subject")
            .reason_code(),
        "INTEGRATION_ROOT_MISMATCH"
    );
}

#[test]
fn integration_root_field_shift_does_not_collide() {
    let manifest = manifest();
    let split = IntegrationInputs {
        merge_method: b"ab",
        conflict_resolutions: b"c",
        ..IntegrationInputs::default()
    };
    let merged = IntegrationInputs {
        merge_method: b"a",
        conflict_resolutions: b"bc",
        ..IntegrationInputs::default()
    };
    assert_ne!(
        IntegrationRoot::bind(&manifest, &candidate_roots(), &split)
            .expect("split")
            .root,
        IntegrationRoot::bind(&manifest, &candidate_roots(), &merged)
            .expect("merged")
            .root
    );
    let mut ref_shift = manifest.clone();
    ref_shift.target_ref = "refs/heads/mai".into();
    let mut sha_shift = ref_shift.clone();
    sha_shift.target_ref = "refs/heads/main".into();
    assert_ne!(
        IntegrationRoot::bind(
            &ref_shift,
            &candidate_roots(),
            &IntegrationInputs::default()
        )
        .expect("ref shift")
        .root,
        IntegrationRoot::bind(
            &sha_shift,
            &candidate_roots(),
            &IntegrationInputs::default()
        )
        .expect("sha shift")
        .root
    );
}

#[test]
fn combined_proof_root_binds_candidate_and_order() {
    let a = ProofRoot {
        candidate: repeated_id("can", 'a'),
        root: Digest::from_bytes([1; 32]),
    };
    let b = ProofRoot {
        candidate: repeated_id("can", 'b'),
        root: Digest::from_bytes([2; 32]),
    };
    let ab = combined_proof_root(&[a.clone(), b.clone()]);
    assert_eq!(ab, combined_proof_root(&[a.clone(), b.clone()]));
    assert_ne!(ab, combined_proof_root(&[b.clone(), a.clone()]));
    assert_ne!(ab, combined_proof_root(std::slice::from_ref(&a)));
    let mut swapped = a.clone();
    swapped.root = b.root;
    assert_ne!(ab, combined_proof_root(&[swapped, b]));
    assert_ne!(
        combined_proof_root(std::slice::from_ref(&a)),
        combined_proof_root(&[ProofRoot {
            candidate: repeated_id("can", 'c'),
            root: a.root
        }])
    );
}

#[test]
fn integration_and_binding_ids_are_prefix_distinct() {
    let digest = Digest::from_bytes([5; 32]);
    let integration = IntegrationId::from_digest(digest);
    assert!(integration.as_str().starts_with("int_"));
    assert!(IntegrationId::parse(integration.as_str()).is_ok());
    let as_candidate = format!("can_{}", digest.to_hex());
    assert_eq!(
        IntegrationId::parse(&as_candidate)
            .expect_err("candidate prefix")
            .reason_code(),
        "INVALID_ID"
    );
    assert!(CandidateId::parse(integration.as_str()).is_err());
    assert!(ContentId::parse(integration.as_str()).is_err());
    assert!(IntegrationId::parse(format!("int_{}", "G".repeat(64))).is_err());
    assert!(serde_json::from_str::<IntegrationId>(&format!("\"{as_candidate}\"")).is_err());
}

#[test]
fn integration_root_binds_only_the_derived_proof_root() {
    let manifest = manifest();
    let roots = candidate_roots();
    manifest.verify_proof_root(&roots).expect("derived");
    let bound = IntegrationRoot::bind(&manifest, &roots, &populated_inputs()).expect("bind");
    bound
        .verify(&manifest, &roots, &populated_inputs())
        .expect("verify");
    let mut hand_supplied = manifest.clone();
    hand_supplied.proof_root = Digest::from_bytes([3; 32]);
    hand_supplied.integration_id().expect("id still canonical");
    assert_eq!(
        hand_supplied
            .verify_proof_root(&roots)
            .expect_err("hand-supplied digest")
            .reason_code(),
        "PROOF_ROOT_NOT_DERIVED"
    );
    assert_eq!(
        IntegrationRoot::bind(&hand_supplied, &roots, &populated_inputs())
            .expect_err("no root from a hand-supplied digest")
            .reason_code(),
        "PROOF_ROOT_NOT_DERIVED"
    );
    assert_eq!(
        bound
            .verify(&hand_supplied, &roots, &populated_inputs())
            .expect_err("verify refuses before comparing")
            .reason_code(),
        "PROOF_ROOT_NOT_DERIVED"
    );
}

#[test]
fn candidate_root_set_must_match_the_ordered_candidate_set() {
    let manifest = manifest();
    let roots = candidate_roots();
    let extra = ProofRoot {
        candidate: repeated_id("can", 'c'),
        root: Digest::from_bytes([4; 32]),
    };
    let missing = roots[..1].to_vec();
    let with_extra = [roots.clone(), vec![extra.clone()]].concat();
    let reordered = vec![roots[1].clone(), roots[0].clone()];
    let substituted = vec![roots[0].clone(), extra];
    let mut swapped_digest = roots.clone();
    swapped_digest[0].root = Digest::from_bytes([9; 32]);
    for (name, supplied) in [
        ("missing", missing),
        ("extra", with_extra),
        ("reordered", reordered),
        ("substituted", substituted),
        ("swapped digest", swapped_digest),
        ("none", Vec::new()),
    ] {
        assert_eq!(
            manifest
                .verify_proof_root(&supplied)
                .expect_err(name)
                .reason_code(),
            "PROOF_ROOT_NOT_DERIVED",
            "{name}"
        );
        assert_eq!(
            IntegrationRoot::bind(&manifest, &supplied, &IntegrationInputs::default())
                .expect_err(name)
                .reason_code(),
            "PROOF_ROOT_NOT_DERIVED",
            "{name}"
        );
    }
    manifest
        .verify_proof_root(&roots)
        .expect("exact set and order");
}

#[test]
fn changing_one_candidate_root_changes_the_integration_root() {
    let original = manifest();
    let roots = candidate_roots();
    let mut changed_roots = roots.clone();
    changed_roots[1].root = Digest::from_bytes([9; 32]);
    let mut changed = original.clone();
    changed.proof_root = combined_proof_root(&changed_roots);
    let inputs = IntegrationInputs::default();
    let before = IntegrationRoot::bind(&original, &roots, &inputs).expect("before");
    let after = IntegrationRoot::bind(&changed, &changed_roots, &inputs).expect("after");
    assert_ne!(before.subject, after.subject);
    assert_ne!(before.root, after.root);
    assert_eq!(
        IntegrationRoot::bind(&original, &changed_roots, &inputs)
            .expect_err("old manifest, new roots")
            .reason_code(),
        "PROOF_ROOT_NOT_DERIVED"
    );
    assert_eq!(
        before
            .verify(&changed, &changed_roots, &inputs)
            .expect_err("old root, new subject")
            .reason_code(),
        "INTEGRATION_ROOT_MISMATCH"
    );
}
