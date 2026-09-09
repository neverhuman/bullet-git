use super::*;
use bullet_git_types::{
    AttemptId, ChangeId, ContentId, GraphRevisionId, PlanRevisionId, RepositoryId, VariantId,
    WorkPackageId, CANDIDATE_MANIFEST_SCHEMA_VERSION,
};

fn attempt(seed: &str) -> String {
    AttemptId::from_seed(seed).to_string()
}

fn variant() -> VariantId {
    VariantId::from_seed("memory-variant")
}

fn expected() -> ExpectedAuthority {
    ExpectedAuthority {
        attempt_id: attempt("atm_1"),
        attempt_fence: 3,
        workspace_nonce: [7u8; 32],
    }
}

fn token(attempt: &str, fence: u64) -> AuthorityEnvelope {
    let nonce: Vec<u8> = vec![7u8; 32];
    AuthorityEnvelope {
        token: serde_json::to_vec(&serde_json::json!({
            "variant_id": variant(),
            "attempt_id": AttemptId::from_seed(attempt),
            "attempt_fence": fence,
            "workspace_nonce": nonce,
        }))
        .expect("token json"),
    }
}

fn grant() -> ScopeGrant {
    ScopeGrant::new(&["src".into()]).expect("grant")
}

fn change() -> Change {
    Change {
        id: ChangeId::from_seed("feat"),
        mission: "demo".into(),
        acceptance_root: Digest::of(b"acc"),
    }
}

fn provenance(repo: &MemoryRepository, attempt_seed: &str) -> CandidateProvenance {
    CandidateProvenance {
        schema_version: CANDIDATE_MANIFEST_SCHEMA_VERSION,
        repository_id: RepositoryId::from_seed("memory-repository"),
        producing_attempt_id: AttemptId::from_seed(attempt_seed),
        attempt_fence: repo.expected.attempt_fence,
        work_package_id: WorkPackageId::from_seed("memory-package"),
        variant_id: variant(),
        plan_revision_id: PlanRevisionId::from_seed("memory-plan"),
        graph_revision_id: GraphRevisionId::from_seed("memory-graph"),
        base_checkpoint_id: repo.journal.checkpoint().id,
        base_commit: repo.base.clone(),
        parent_candidate_ids: Vec::new(),
        granted_scope: repo
            .grant
            .allowed_prefixes
            .iter()
            .map(|path| path.parse::<RepoPath>().expect("grant"))
            .collect(),
        context_capsule_id: ContentId::from_seed("memory-context"),
        configuration_snapshot_id: ContentId::from_seed("memory-config"),
        policy_snapshot_id: ContentId::from_seed("memory-policy"),
        routing_snapshot_id: ContentId::from_seed("memory-route"),
        environment_digest: Digest::of(b"memory-environment"),
        toolchain_digest: Digest::of(b"memory-toolchain"),
    }
}

fn prepare(repo: &mut MemoryRepository, auth: &AuthorityEnvelope, attempt_seed: &str) -> Candidate {
    let provenance = provenance(repo, attempt_seed);
    repo.prepare_candidate(auth, &change(), &provenance)
        .expect("prepare")
}

#[test]
fn empty_and_garbage_tokens_are_rejected() {
    let repo = MemoryRepository::new(expected(), grant());
    for bytes in [Vec::new(), b"x".to_vec()] {
        let auth = AuthorityEnvelope { token: bytes };
        let err = repo.read_tree(&auth).expect_err("rejected");
        assert_eq!(err.reason_code(), "UNAUTHORIZED");
    }
}

#[test]
fn wrong_fence_token_is_stale() {
    let repo = MemoryRepository::new(expected(), grant());
    let err = repo.read_tree(&token("atm_1", 4)).expect_err("stale");
    assert_eq!(err.reason_code(), "STALE_AUTHORITY");
}

#[test]
fn worktree_writes_are_blocked() {
    let mut repo = MemoryRepository::worktree(expected(), grant());
    let err = repo
        .apply_change(
            &token("atm_1", 3),
            &[PatchHunk::write("src/lib.rs", b"x".to_vec())],
        )
        .expect_err("blocked");
    assert_eq!(err.reason_code(), "WORKTREE_FORBIDDEN");
}

#[test]
fn out_of_scope_patch_leaves_tree_untouched() {
    let mut repo = MemoryRepository::new(expected(), grant());
    let auth = token("atm_1", 3);
    let err = repo
        .apply_change(
            &auth,
            &[
                PatchHunk::write("src/ok.rs", b"fine".to_vec()),
                PatchHunk::write("../escape", b"evil".to_vec()),
            ],
        )
        .expect_err("refused");
    assert_eq!(err.reason_code(), "OUT_OF_SCOPE");
    assert!(err.to_string().contains("../escape"));
    assert!(repo.read_tree(&auth).expect("read").is_empty());
}

#[test]
fn content_id_ignores_application_order_while_candidate_binds_checkpoint() {
    let auth = token("atm_1", 3);
    let a = PatchHunk::write("src/a.rs", b"alpha".to_vec());
    let b = PatchHunk::write("src/b.rs", b"beta".to_vec());
    let mut one = MemoryRepository::new(expected(), grant());
    one.apply_change(&auth, &[a.clone(), b.clone()])
        .expect("apply");
    let mut two = MemoryRepository::new(expected(), grant());
    two.apply_change(&auth, &[b, a]).expect("apply");
    let c1 = prepare(&mut one, &auth, "atm_1");
    let c2 = prepare(&mut two, &auth, "atm_1");
    assert_eq!(c1.content_id, c2.content_id);
    assert_ne!(c1.id, c2.id, "journal checkpoint is provenance");
    assert_eq!(c1.manifest.tree_oid, c2.manifest.tree_oid);
    assert_eq!(c1.manifest.patch_digest, c2.manifest.patch_digest);
    let mut three = MemoryRepository::new(expected(), grant());
    three
        .apply_change(
            &auth,
            &[PatchHunk::write("src/a.rs", b"different".to_vec())],
        )
        .expect("apply");
    let c3 = prepare(&mut three, &auth, "atm_1");
    assert_ne!(c1.id, c3.id);
    assert_ne!(c1.content_id, c3.content_id);
}

#[test]
fn delete_removes_the_file_and_absent_target_is_typed() {
    let auth = token("atm_1", 3);
    let mut repo = MemoryRepository::new(expected(), grant());
    repo.apply_change(&auth, &[PatchHunk::write("src/lib.rs", b"x".to_vec())])
        .expect("apply");
    let err = repo
        .apply_change(
            &auth,
            &[
                PatchHunk::write("src/other.rs", b"y".to_vec()),
                PatchHunk::delete("src/ghost.rs"),
            ],
        )
        .expect_err("refused");
    assert_eq!(err.reason_code(), "PATH_ABSENT");
    assert_eq!(
        repo.read_tree(&auth).expect("read"),
        vec!["src/lib.rs".to_string()],
        "failed batch must not mutate"
    );
    repo.apply_change(&auth, &[PatchHunk::delete("src/lib.rs")])
        .expect("delete");
    assert!(repo.read_tree(&auth).expect("read").is_empty());
    let candidate = prepare(&mut repo, &auth, "atm_1");
    assert!(candidate.manifest.actual_scope.is_empty());
}

#[test]
fn evolution_produces_new_candidate_and_proof_binds() {
    let auth = token("atm_1", 3);
    let mut repo = MemoryRepository::new(expected(), grant());
    repo.apply_change(
        &auth,
        &[PatchHunk::write("src/lib.rs", b"fn main() {}".to_vec())],
    )
    .expect("apply");
    let checkpoint = repo.checkpoint(&auth).expect("checkpoint");
    assert_eq!(checkpoint.through_seq, 1);
    let candidate = prepare(&mut repo, &auth, "atm_1");
    let proof = bind_proof(&candidate);
    assert_eq!(proof.candidate, candidate.id);
    let (repaired, edge) = MemoryRepository::evolve(&candidate, EvolutionKind::Repair, "r1");
    assert_eq!(edge.kind, EvolutionKind::Repair);
    assert_ne!(repaired.id, candidate.id);
    assert_eq!(repaired.manifest.change_id, candidate.manifest.change_id);
    assert_eq!(repaired.manifest.parent_candidate_ids, vec![candidate.id]);
    repo.record_evolution(&auth, &change(), edge)
        .expect("lineage");
    let evo = repo.query_lineage(&auth, &change().id).expect("query");
    assert_eq!(evo.edges.len(), 1);
    assert!(!evo.edges[0].invalidates_evidence());
}
