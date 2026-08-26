//! IntegrationManifest canonical identity, IntegrationRoot bind/verify, and
//! hostile candidate-set / target inputs.

use bullet_git_types::{
    combined_proof_root, BindingId, CandidateBindingCheck, CandidateId, ContentId, Digest, GateId,
    GitOid, IntegrationId, IntegrationInputs, IntegrationManifest, IntegrationRoot, ProofRoot,
    INTEGRATION_MANIFEST_SCHEMA_VERSION, MAX_INTEGRATION_CANDIDATES,
};

mod support;
use support::{
    bind, bind_with_set, binding_ids, candidate_roots, candidate_set, repeated_id, sha1, verify,
};

macro_rules! assert_refusal {
    ($result:expr, $code:literal) => {
        assert_eq!($result.expect_err($code).reason_code(), $code)
    };
    ($result:expr, $code:literal, $context:expr) => {
        assert_eq!(
            $result.expect_err($context).reason_code(),
            $code,
            "{}",
            $context
        )
    };
}

fn manifest() -> IntegrationManifest {
    let set = candidate_set(0);
    IntegrationManifest {
        schema_version: INTEGRATION_MANIFEST_SCHEMA_VERSION,
        target_ref: "refs/heads/main".into(),
        target_sha: sha1('1'),
        candidate_ids: set
            .roots
            .iter()
            .map(|root| root.candidate.clone())
            .collect(),
        binding_ids: binding_ids(&set),
        merge_group_sha: Some(sha1('2')),
        proof_root: combined_proof_root(&set.roots),
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
    const CANONICAL: &str = r#"{"binding_ids":["bnd_562427ad42681210eb266696ca0df867c051a468c0fa8846e2ed05524995e12c","bnd_ae736a6caf76a09532a5840a28e9841c4bbadf17dfd9f8a319f54b2cf66b3ef8"],"candidate_ids":["can_06278e4db9383fd6fa9919ed403a3f1e82b181dc0b680b5fdfb0878c5a4ce620","can_63012825e6eab17d6cfe0233f928fbb44090eb5e31d6a4738a70c939b02e81a1"],"merge_group_sha":"sha1:2222222222222222222222222222222222222222","policy_snapshot_id":"cnt_4444444444444444444444444444444444444444444444444444444444444444","proof_root":"d31b2c297c064604d2d837c69084fccec6ee2359ecb23f3ef8b318bcecf91a9a","schema_version":1,"target_ref":"refs/heads/main","target_sha":"sha1:1111111111111111111111111111111111111111"}"#;
    let manifest = manifest();
    let observed_canonical =
        String::from_utf8(serde_jcs::to_vec(&manifest).expect("canonical")).expect("utf8");
    let observed_id = manifest.integration_id().expect("id");
    let observed_root = bind(&manifest, &candidate_roots(), &populated_inputs()).expect("root");
    assert_eq!(observed_canonical, CANONICAL);
    assert_eq!(
        observed_id.as_str(),
        "int_9299b256e1f07a0ee257c8d9b42544697fbf24262ed3f06615aa7707c81968b5"
    );
    let root = observed_root;
    assert_eq!(
        root.root.to_hex(),
        "72e9ab11ec9416ef0a592d48b7b11b30222fec284599283b7a3d3957a43f6b52"
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
    let mut bindings = original.clone();
    bindings.binding_ids[1] = repeated_id("bnd", '9');
    let mut bindings_reordered = original.clone();
    bindings_reordered.binding_ids.reverse();
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
        ("binding_ids", bindings),
        ("binding_ids order", bindings_reordered),
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
    assert_refusal!(schema.integration_id(), "UNSUPPORTED_SCHEMA");
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
    assert!(bind(
        &duplicate,
        &candidate_roots(),
        &IntegrationInputs::default()
    )
    .is_err());
    let mut duplicate_binding = manifest();
    duplicate_binding.binding_ids[1] = duplicate_binding.binding_ids[0].clone();
    assert_refusal!(duplicate_binding.integration_id(), "DUPLICATE_BINDING_ID");
    let mut missing_binding = manifest();
    missing_binding.binding_ids.pop();
    assert_refusal!(missing_binding.integration_id(), "BINDING_SET_MISMATCH");
}

#[test]
fn hostile_empty_candidate_set_is_refused() {
    let mut empty = manifest();
    empty.candidate_ids.clear();
    assert_refusal!(empty.integration_id(), "EMPTY_CANDIDATE_SET");
    let mut oversized = manifest();
    oversized.candidate_ids = (0..=MAX_INTEGRATION_CANDIDATES)
        .map(|index| CandidateId::from_seed(&index.to_string()))
        .collect();
    assert_refusal!(oversized.integration_id(), "CANDIDATE_SET_TOO_LARGE");
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
        assert_refusal!(GitOid::new(raw), "INVALID_OID", raw);
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
        assert_refusal!(manifest.integration_id(), "INVALID_TARGET_REF", target_ref);
    }
    let mut oversized = manifest();
    oversized.target_ref = format!("refs/heads/{}", "a".repeat(300));
    assert_refusal!(oversized.integration_id(), "INVALID_TARGET_REF");
}

#[test]
fn hostile_merge_group_equal_to_target_is_refused() {
    let mut same = manifest();
    same.merge_group_sha = Some(same.target_sha.clone());
    assert_refusal!(same.integration_id(), "MERGE_GROUP_EQUALS_TARGET");
}

#[test]
fn integration_root_each_of_the_four_leaves_is_tamper_evident() {
    let manifest = manifest();
    let inputs = populated_inputs();
    let root = bind(&manifest, &candidate_roots(), &inputs).expect("root");
    assert_eq!(root.subject, manifest.integration_id().expect("id"));
    verify(&root, &manifest, &candidate_roots(), &inputs).expect("verify");
    for (name, _) in inputs.named_leaves() {
        let mut tampered = inputs;
        match name {
            "merge_method" => tampered.merge_method = b"tampered",
            "conflict_resolutions" => tampered.conflict_resolutions = b"tampered",
            "integration_evidence" => tampered.integration_evidence = b"tampered",
            "approvals_and_effect_receipts" => tampered.approvals_and_effect_receipts = b"tampered",
            other => panic!("unexpected leaf {other}"),
        }
        assert_refusal!(
            verify(&root, &manifest, &candidate_roots(), &tampered),
            "INTEGRATION_ROOT_MISMATCH",
            name
        );
    }
    let mut other = manifest.clone();
    other.target_sha = sha1('f');
    assert_refusal!(
        verify(&root, &other, &candidate_roots(), &inputs),
        "INTEGRATION_ROOT_MISMATCH"
    );
    let mut forged_subject = root.clone();
    forged_subject.subject = IntegrationId::from_digest(Digest::from_bytes([0; 32]));
    assert_refusal!(
        verify(&forged_subject, &manifest, &candidate_roots(), &inputs),
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
        bind(&manifest, &candidate_roots(), &split)
            .expect("split")
            .root,
        bind(&manifest, &candidate_roots(), &merged)
            .expect("merged")
            .root
    );
    let mut ref_shift = manifest.clone();
    ref_shift.target_ref = "refs/heads/mai".into();
    let mut sha_shift = ref_shift.clone();
    sha_shift.target_ref = "refs/heads/main".into();
    assert_ne!(
        bind(
            &ref_shift,
            &candidate_roots(),
            &IntegrationInputs::default()
        )
        .expect("ref shift")
        .root,
        bind(
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
    assert_refusal!(IntegrationId::parse(&as_candidate), "INVALID_ID");
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
    let bound = bind(&manifest, &roots, &populated_inputs()).expect("bind");
    verify(&bound, &manifest, &roots, &populated_inputs()).expect("verify");
    let mut hand_supplied = manifest.clone();
    hand_supplied.proof_root = Digest::from_bytes([3; 32]);
    hand_supplied.integration_id().expect("id still canonical");
    assert_refusal!(
        hand_supplied.verify_proof_root(&roots),
        "PROOF_ROOT_NOT_DERIVED"
    );
    assert_refusal!(
        bind(&hand_supplied, &roots, &populated_inputs()),
        "PROOF_ROOT_NOT_DERIVED"
    );
    assert_refusal!(
        verify(&bound, &hand_supplied, &roots, &populated_inputs()),
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
    for (_, supplied) in [
        ("missing", missing),
        ("extra", with_extra),
        ("reordered", reordered),
        ("substituted", substituted),
        ("swapped digest", swapped_digest),
        ("none", Vec::new()),
    ] {
        assert_refusal!(
            manifest.verify_proof_root(&supplied),
            "PROOF_ROOT_NOT_DERIVED"
        );
        assert_refusal!(
            bind(&manifest, &supplied, &IntegrationInputs::default()),
            "PROOF_ROOT_NOT_DERIVED"
        );
    }
    manifest
        .verify_proof_root(&roots)
        .expect("exact set and order");
    let set = candidate_set(0);
    let exact = set.checks();
    manifest
        .verify_bindings(&roots, &exact)
        .expect("exact bindings");
    for (_, supplied) in [
        ("missing", exact[..1].to_vec()),
        ("extra", [exact.clone(), vec![exact[1]]].concat()),
        ("reordered", vec![exact[1], exact[0]]),
    ] {
        assert_refusal!(
            manifest.verify_bindings(&roots, &supplied),
            "BINDING_SET_MISMATCH"
        );
    }
    let mut reordered_ids = manifest.clone();
    reordered_ids.binding_ids.reverse();
    let mut substituted_id = manifest.clone();
    substituted_id.binding_ids[0] = BindingId::from_digest(Digest::from_bytes([9; 32]));
    for changed in [reordered_ids, substituted_id] {
        assert_refusal!(
            changed.verify_bindings(&roots, &exact),
            "BINDING_SET_MISMATCH"
        );
    }
    let mut gate_substitution = set.bindings[0].clone();
    gate_substitution.gate_ids = vec![GateId::from_seed("substituted")];
    let mut envelope_substitution = set.bindings[0].clone();
    envelope_substitution.envelope.provider_version = "fixture/substituted".into();
    for raw_substitution in [gate_substitution, envelope_substitution] {
        let mut matching_manifest = manifest.clone();
        matching_manifest.binding_ids[0] = raw_substitution.binding_id().expect("substituted id");
        let substituted_check = CandidateBindingCheck {
            binding: &raw_substitution,
            candidate: &set.candidates[0],
            proof_root: &set.roots[0],
            expected_gate_ids: &set.gates[0],
            expected_envelope: &set.envelopes[0],
        };
        let checks = vec![substituted_check, exact[1]];
        assert_refusal!(
            IntegrationRoot::bind(
                &matching_manifest,
                &roots,
                &checks,
                &IntegrationInputs::default()
            ),
            "BINDING_MISMATCH"
        );
    }
}

#[test]
fn changing_one_candidate_root_changes_the_integration_root() {
    let original = manifest();
    let roots = candidate_roots();
    let changed_set = candidate_set(1);
    let changed_roots = changed_set.roots.clone();
    let mut changed = original.clone();
    changed.proof_root = combined_proof_root(&changed_roots);
    changed.binding_ids = binding_ids(&changed_set);
    let inputs = IntegrationInputs::default();
    let before = bind(&original, &roots, &inputs).expect("before");
    let after = bind_with_set(&changed, &changed_set, &inputs).expect("after");
    assert_ne!(before.subject, after.subject);
    assert_ne!(before.root, after.root);
    assert_refusal!(
        IntegrationRoot::bind(&original, &changed_roots, &changed_set.checks(), &inputs),
        "PROOF_ROOT_NOT_DERIVED"
    );
    assert_refusal!(
        before.verify(&changed, &changed_roots, &changed_set.checks(), &inputs),
        "INTEGRATION_ROOT_MISMATCH"
    );
}
