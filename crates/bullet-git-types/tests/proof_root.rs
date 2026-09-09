//! Eight-leaf ProofRoot bind, verify-on-read, one tamper per input, the
//! proof-carrying CandidateBinding, and candidate-vs-integration root separation.

use bullet_git_types::{
    combined_proof_root, verify_proof_root, Candidate, CandidateBinding, CandidateBindingCheck,
    CandidateManifest, CandidateManifestError, Digest, ExecutionEnvelope, GateId, GitOid,
    IntegrationId, IntegrationInputs, IntegrationManifest, IntegrationRoot, ProofInputs, ProofRoot,
    RepoPath, CANDIDATE_MANIFEST_SCHEMA_VERSION, INTEGRATION_MANIFEST_SCHEMA_VERSION,
    MAX_BOUND_GATE_IDS,
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
    candidate.validate_identity().expect("valid identity");

    let mut wrong_candidate_id = candidate.clone();
    wrong_candidate_id.id = repeated_id("can", 'f');
    assert_eq!(
        wrong_candidate_id
            .validate_identity()
            .expect_err("stored Candidate id mismatch"),
        CandidateManifestError::CandidateIdMismatch
    );

    let mut wrong_content_id = candidate.clone();
    wrong_content_id.content_id = repeated_id("cnt", 'f');
    assert_eq!(
        wrong_content_id
            .validate_identity()
            .expect_err("stored content id mismatch"),
        CandidateManifestError::ContentIdMismatch
    );

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

fn envelope() -> ExecutionEnvelope {
    ExecutionEnvelope {
        runner_image_digest: Digest::from_bytes([21; 32]),
        provider_version: "provider/model@harness-2026.08".into(),
        lock_digest: Digest::from_bytes([22; 32]),
        toolchain_digest: Digest::from_bytes([15; 32]),
        environment_digest: Digest::from_bytes([14; 32]),
    }
}

fn gates() -> Vec<GateId> {
    vec![repeated_id("gat", '1'), repeated_id("gat", '2')]
}

fn bound() -> (Candidate, ProofRoot, CandidateBinding) {
    let candidate = candidate();
    let root = ProofRoot::bind(&candidate, &populated_inputs());
    let binding = CandidateBinding::bind(&candidate, &root, gates(), envelope()).expect("binding");
    (candidate, root, binding)
}

#[test]
fn candidate_binding_golden_is_stable() {
    let (candidate, root, binding) = bound();
    assert_eq!(binding.candidate_id, candidate.id);
    assert_eq!(binding.content_id, candidate.content_id);
    assert_eq!(binding.proof_root, root.root);
    let canonical =
        String::from_utf8(serde_jcs::to_vec(&binding).expect("canonical")).expect("utf8");
    assert!(canonical.starts_with(r#"{"candidate_id":"can_66da272ac2783b2e"#));
    assert!(canonical.contains(r#""envelope":{"environment_digest":"0e0e"#));
    assert!(canonical.contains(r#""gate_ids":["gat_1111"#));
    assert_eq!(
        binding.binding_id().expect("id").as_str(),
        "bnd_e8e4742c127722b59536d789606b0e7e3599d21f13bd64915631a44e7ca8b6b4"
    );
    let back: CandidateBinding =
        serde_json::from_str(&serde_json::to_string(&binding).expect("json")).expect("round trip");
    assert_eq!(back, binding);
    binding
        .verify(&candidate, &root, &gates(), &envelope())
        .expect("verify");
}

#[test]
fn every_candidate_binding_field_is_identity_sensitive() {
    let (_, _, original) = bound();
    let id = original.binding_id().expect("id");
    let mut candidate_id = original.clone();
    candidate_id.candidate_id = repeated_id("can", 'f');
    let mut content_id = original.clone();
    content_id.content_id = repeated_id("cnt", 'f');
    let mut gate_set = original.clone();
    gate_set.gate_ids = vec![repeated_id("gat", '1'), repeated_id("gat", '3')];
    let mut gate_extra = original.clone();
    gate_extra.gate_ids.push(repeated_id("gat", '3'));
    let mut proof_root = original.clone();
    proof_root.proof_root = Digest::from_bytes([99; 32]);
    let mut runner = original.clone();
    runner.envelope.runner_image_digest = Digest::from_bytes([98; 32]);
    let mut provider = original.clone();
    provider.envelope.provider_version = "provider/model@harness-2026.09".into();
    let mut lock = original.clone();
    lock.envelope.lock_digest = Digest::from_bytes([97; 32]);
    let mut toolchain = original.clone();
    toolchain.envelope.toolchain_digest = Digest::from_bytes([96; 32]);
    let mut environment = original.clone();
    environment.envelope.environment_digest = Digest::from_bytes([95; 32]);
    let cases = [
        ("candidate_id", candidate_id),
        ("content_id", content_id),
        ("gate_ids", gate_set),
        ("gate_ids extra", gate_extra),
        ("proof_root", proof_root),
        ("envelope.runner_image_digest", runner),
        ("envelope.provider_version", provider),
        ("envelope.lock_digest", lock),
        ("envelope.toolchain_digest", toolchain),
        ("envelope.environment_digest", environment),
    ];
    let mut seen = std::collections::BTreeSet::new();
    for (field, changed) in &cases {
        let changed_id = changed.binding_id().expect(field);
        assert_ne!(changed_id, id, "{field}");
        assert!(seen.insert(changed_id), "{field} collided");
    }
    let value = serde_json::to_value(&original).expect("value");
    let top = value.as_object().expect("object");
    let envelope_fields = top["envelope"].as_object().expect("envelope").len();
    let swept_top = cases
        .iter()
        .map(|(name, _)| name.split([' ', '.']).next().expect("field"))
        .collect::<std::collections::BTreeSet<_>>();
    let swept_envelope = cases
        .iter()
        .filter(|(name, _)| name.starts_with("envelope."))
        .count();
    assert_eq!(swept_top.len() + 1, top.len(), "unswept binding field");
    assert_eq!(swept_envelope, envelope_fields, "unswept envelope field");
    let mut schema = original;
    schema.schema_version = INTEGRATION_MANIFEST_SCHEMA_VERSION + 1;
    assert_eq!(
        schema.binding_id().expect_err("schema").reason_code(),
        "UNSUPPORTED_SCHEMA"
    );
}

#[test]
fn candidate_binding_refuses_every_hostile_input() {
    let candidate = candidate();
    let root = ProofRoot::bind(&candidate, &populated_inputs());
    let refuse = |root: &ProofRoot, gates: Vec<GateId>, envelope: ExecutionEnvelope| {
        CandidateBinding::bind(&candidate, root, gates, envelope)
            .expect_err("refused")
            .reason_code()
    };
    let mut other_subject = root.clone();
    other_subject.candidate = repeated_id("can", 'f');
    assert_eq!(
        refuse(&other_subject, gates(), envelope()),
        "PROOF_ROOT_SUBJECT_MISMATCH"
    );
    let mut toolchain = envelope();
    toolchain.toolchain_digest = Digest::from_bytes([0; 32]);
    assert_eq!(refuse(&root, gates(), toolchain), "ENVELOPE_MISMATCH");
    let mut environment = envelope();
    environment.environment_digest = Digest::from_bytes([0; 32]);
    assert_eq!(refuse(&root, gates(), environment), "ENVELOPE_MISMATCH");
    assert_eq!(refuse(&root, vec![], envelope()), "EMPTY_GATE_SET");
    let duplicate = vec![repeated_id("gat", '1'), repeated_id("gat", '1')];
    assert_eq!(
        refuse(&root, duplicate, envelope()),
        "GATE_IDS_NOT_ASCENDING"
    );
    let unsorted = vec![repeated_id("gat", '2'), repeated_id("gat", '1')];
    assert_eq!(
        refuse(&root, unsorted, envelope()),
        "GATE_IDS_NOT_ASCENDING"
    );
    let oversized = (0..=MAX_BOUND_GATE_IDS)
        .map(|index| GateId::from_seed(&index.to_string()))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    assert_eq!(oversized.len(), MAX_BOUND_GATE_IDS + 1);
    assert_eq!(refuse(&root, oversized, envelope()), "GATE_SET_TOO_LARGE");
    for version in ["", " ", "provider model", "\u{e9}", &"v".repeat(129)] {
        let mut bad = envelope();
        bad.provider_version = version.to_string();
        assert_eq!(
            refuse(&root, gates(), bad),
            "INVALID_PROVIDER_VERSION",
            "{version:?}"
        );
    }
    let mut forged = candidate.clone();
    forged.id = repeated_id("can", 'e');
    let forged_root = ProofRoot::bind(&forged, &ProofInputs::empty());
    assert_eq!(
        CandidateBinding::bind(&forged, &forged_root, gates(), envelope())
            .expect_err("forged candidate")
            .reason_code(),
        "CANDIDATE_ID_MISMATCH"
    );
}

#[test]
fn candidate_binding_verify_on_read_detects_tamper() {
    let (candidate, root, binding) = bound();
    let expected_gates = gates();
    let expected_envelope = envelope();
    let mut proof_root = binding.clone();
    proof_root.proof_root = Digest::from_bytes([0; 32]);
    assert_eq!(
        proof_root
            .verify(&candidate, &root, &expected_gates, &expected_envelope)
            .expect_err("proof root")
            .reason_code(),
        "BINDING_MISMATCH"
    );
    let mut content = binding.clone();
    content.content_id = repeated_id("cnt", 'f');
    assert_eq!(
        content
            .verify(&candidate, &root, &expected_gates, &expected_envelope)
            .expect_err("content id")
            .reason_code(),
        "BINDING_MISMATCH"
    );
    let mut other_root = root.clone();
    other_root.root = Digest::from_bytes([1; 32]);
    assert_eq!(
        binding
            .verify(&candidate, &other_root, &expected_gates, &expected_envelope,)
            .expect_err("other root")
            .reason_code(),
        "BINDING_MISMATCH"
    );
    let mut gates_swapped = binding.clone();
    gates_swapped.gate_ids = vec![repeated_id("gat", '9')];
    let mut runner = binding.clone();
    runner.envelope.runner_image_digest = Digest::from_bytes([31; 32]);
    let mut provider = binding.clone();
    provider.envelope.provider_version = "provider/model@other".into();
    let mut lock = binding.clone();
    lock.envelope.lock_digest = Digest::from_bytes([32; 32]);
    let mut toolchain = binding.clone();
    toolchain.envelope.toolchain_digest = Digest::from_bytes([33; 32]);
    let mut environment = binding.clone();
    environment.envelope.environment_digest = Digest::from_bytes([34; 32]);
    for (name, changed) in [
        ("gates", gates_swapped),
        ("runner", runner),
        ("provider", provider),
        ("lock", lock),
        ("toolchain", toolchain),
        ("environment", environment),
    ] {
        assert_eq!(
            changed
                .verify(&candidate, &root, &expected_gates, &expected_envelope)
                .expect_err(name)
                .reason_code(),
            "BINDING_MISMATCH",
            "{name}"
        );
    }
}

#[test]
fn candidate_root_never_validates_as_integration_root() {
    let candidate = candidate();
    let inputs = ProofInputs::empty();
    let proof = ProofRoot::bind(&candidate, &inputs);
    let expected_gates = gates();
    let expected_envelope = envelope();
    let binding = CandidateBinding::bind(
        &candidate,
        &proof,
        expected_gates.clone(),
        expected_envelope.clone(),
    )
    .expect("binding");
    let check = CandidateBindingCheck {
        binding: &binding,
        candidate: &candidate,
        proof_root: &proof,
        expected_gate_ids: &expected_gates,
        expected_envelope: &expected_envelope,
    };
    let manifest = IntegrationManifest {
        schema_version: INTEGRATION_MANIFEST_SCHEMA_VERSION,
        target_ref: "refs/heads/main".into(),
        target_sha: GitOid::new(format!("sha1:{}", "1".repeat(40))).expect("oid"),
        candidate_ids: vec![candidate.id.clone()],
        binding_ids: vec![binding.binding_id().expect("binding id")],
        merge_group_sha: None,
        proof_root: combined_proof_root(std::slice::from_ref(&proof)),
        policy_snapshot_id: repeated_id("cnt", '2'),
    };
    let integration_inputs = IntegrationInputs::default();
    let integration = IntegrationRoot::bind(
        &manifest,
        std::slice::from_ref(&proof),
        std::slice::from_ref(&check),
        &integration_inputs,
    )
    .expect("root");
    assert_ne!(integration.root, proof.root);
    assert_ne!(integration.root, manifest.proof_root);
    let forged_integration = IntegrationRoot {
        subject: integration.subject.clone(),
        root: proof.root,
    };
    assert_eq!(
        forged_integration
            .verify(
                &manifest,
                std::slice::from_ref(&proof),
                std::slice::from_ref(&check),
                &integration_inputs,
            )
            .expect_err("candidate digest as integration root")
            .reason_code(),
        "INTEGRATION_ROOT_MISMATCH"
    );
    let forged_proof = ProofRoot {
        candidate: candidate.id.clone(),
        root: integration.root,
    };
    assert_eq!(
        verify_proof_root(&forged_proof, &candidate, &inputs)
            .expect_err("integration digest as candidate root")
            .reason_code(),
        "PROOF_ROOT_MISMATCH"
    );
    let proof_json = serde_json::to_string(&proof).expect("json");
    assert!(serde_json::from_str::<IntegrationRoot>(&proof_json).is_err());
    let integration_json = serde_json::to_string(&integration).expect("json");
    assert!(serde_json::from_str::<ProofRoot>(&integration_json).is_err());
    assert!(IntegrationId::parse(candidate.id.as_str()).is_err());
    assert_ne!(integration.subject.as_str(), candidate.id.as_str());
}
