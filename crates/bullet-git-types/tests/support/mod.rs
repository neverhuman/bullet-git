use bullet_git_types::{
    Candidate, CandidateBinding, CandidateBindingCheck, CandidateManifest, Digest,
    ExecutionEnvelope, GateId, GitOid, IntegrationError, IntegrationInputs, IntegrationManifest,
    IntegrationRoot, ProofInputs, ProofRoot, RepoPath, CANDIDATE_MANIFEST_SCHEMA_VERSION,
};
use std::str::FromStr;

pub struct CandidateSet {
    pub candidates: Vec<Candidate>,
    pub roots: Vec<ProofRoot>,
    pub bindings: Vec<CandidateBinding>,
    pub gates: Vec<Vec<GateId>>,
    pub envelopes: Vec<ExecutionEnvelope>,
}

impl CandidateSet {
    pub fn checks(&self) -> Vec<CandidateBindingCheck<'_>> {
        (0..self.bindings.len())
            .map(|index| CandidateBindingCheck {
                binding: &self.bindings[index],
                candidate: &self.candidates[index],
                proof_root: &self.roots[index],
                expected_gate_ids: &self.gates[index],
                expected_envelope: &self.envelopes[index],
            })
            .collect()
    }
}

pub fn repeated_id<T>(prefix: &str, hex: char) -> T
where
    T: TryFrom<String>,
    T::Error: std::fmt::Debug,
{
    T::try_from(format!("{prefix}_{}", hex.to_string().repeat(64))).expect("typed id")
}

pub fn sha1(hex: char) -> GitOid {
    GitOid::new(format!("sha1:{}", hex.to_string().repeat(40))).expect("oid")
}

fn candidate(index: u8) -> Candidate {
    let manifest = CandidateManifest {
        schema_version: CANDIDATE_MANIFEST_SCHEMA_VERSION,
        repository_id: repeated_id("rep", '1'),
        change_id: repeated_id("chg", if index == 0 { '2' } else { 'c' }),
        producing_attempt_id: repeated_id("atm", if index == 0 { '3' } else { 'd' }),
        attempt_fence: u64::from(index) + 17,
        work_package_id: repeated_id("wpk", '4'),
        variant_id: repeated_id("var", if index == 0 { '5' } else { 'e' }),
        plan_revision_id: repeated_id("pln", '6'),
        graph_revision_id: repeated_id("grf", '7'),
        base_checkpoint_id: repeated_id("ckp", '8'),
        base_commit: sha1('9'),
        head_commit: sha1(if index == 0 { 'a' } else { 'c' }),
        tree_oid: sha1(if index == 0 { 'b' } else { 'd' }),
        patch_digest: Digest::from_bytes([12 + index; 32]),
        parent_candidate_ids: Vec::new(),
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

pub fn candidate_set(second_root_salt: u8) -> CandidateSet {
    let candidates = vec![candidate(0), candidate(1)];
    let roots = candidates
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            let salt = [second_root_salt];
            let inputs = ProofInputs {
                evidence: if index == 1 && second_root_salt != 0 {
                    &salt
                } else {
                    b""
                },
                ..ProofInputs::empty()
            };
            ProofRoot::bind(candidate, &inputs)
        })
        .collect::<Vec<_>>();
    let gates = (0..2)
        .map(|index| vec![GateId::from_seed(&format!("gate-{index}"))])
        .collect::<Vec<_>>();
    let envelopes = (0..2)
        .map(|index| ExecutionEnvelope {
            runner_image_digest: Digest::from_bytes([3; 32]),
            provider_version: format!("fixture/{index}"),
            lock_digest: Digest::from_bytes([4; 32]),
            toolchain_digest: Digest::from_bytes([15; 32]),
            environment_digest: Digest::from_bytes([14; 32]),
        })
        .collect::<Vec<_>>();
    let bindings = (0..2)
        .map(|index| {
            CandidateBinding::bind(
                &candidates[index],
                &roots[index],
                gates[index].clone(),
                envelopes[index].clone(),
            )
            .expect("binding")
        })
        .collect();
    CandidateSet {
        candidates,
        roots,
        bindings,
        gates,
        envelopes,
    }
}

pub fn candidate_roots() -> Vec<ProofRoot> {
    candidate_set(0).roots
}

pub fn binding_ids(set: &CandidateSet) -> Vec<bullet_git_types::BindingId> {
    set.bindings
        .iter()
        .map(|binding| binding.binding_id().expect("binding id"))
        .collect()
}

pub fn bind(
    manifest: &IntegrationManifest,
    roots: &[ProofRoot],
    inputs: &IntegrationInputs<'_>,
) -> Result<IntegrationRoot, IntegrationError> {
    let set = candidate_set(0);
    IntegrationRoot::bind(manifest, roots, &set.checks(), inputs)
}

pub fn verify(
    root: &IntegrationRoot,
    manifest: &IntegrationManifest,
    roots: &[ProofRoot],
    inputs: &IntegrationInputs<'_>,
) -> Result<(), IntegrationError> {
    let set = candidate_set(0);
    root.verify(manifest, roots, &set.checks(), inputs)
}

pub fn bind_with_set(
    manifest: &IntegrationManifest,
    set: &CandidateSet,
    inputs: &IntegrationInputs<'_>,
) -> Result<IntegrationRoot, IntegrationError> {
    IntegrationRoot::bind(manifest, &set.roots, &set.checks(), inputs)
}
