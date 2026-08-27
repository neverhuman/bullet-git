//! RealRepository over real Git: lifecycle, determinism, and fail-closed paths.

mod support;

use bullet_git_journal::Checkpoint;
use bullet_git_types::{
    AttemptId, AuthorityEnvelope, Candidate, CandidateProvenance, Change, ChangeId, CheckpointId,
    ContentId, Digest, GateId, GraphRevisionId, PatchMutation, PatchOperation, PatchProposal,
    PlanRevisionId, Preimage, RepoPath, RepositoryId, VariantId, WorkPackageId,
    CANDIDATE_MANIFEST_SCHEMA_VERSION, PATCH_PROPOSAL_SCHEMA_VERSION,
};
use bullet_git_workspace::{
    cas_digest, AgentRepository, CommitIdentity, ExpectedAuthority, FileProtocol, ImmutableCas,
    PatchHunk, RealRepository, ScopeGrant, MAX_CAS_OBJECT_BYTES,
};
use support::{
    clone_workspace, envelope, good_auth, init_source, real_repo, ATTEMPT, FENCE, NONCE, VARIANT,
};

const ATTEMPT_2: &str = "atm_3333333333333333333333333333333333333333333333333333333333333333";

fn change() -> Change {
    Change {
        id: ChangeId::from_seed("feat"),
        mission: "demo".into(),
        acceptance_root: Digest::of(b"acc"),
    }
}

fn patch(path: &str, contents: &str) -> PatchHunk {
    PatchHunk::write(path, contents.as_bytes().to_vec())
}

fn proposal(
    attempt: &AttemptId,
    checkpoint: &Checkpoint,
    operations: Vec<PatchOperation>,
) -> PatchProposal {
    PatchProposal {
        schema_version: PATCH_PROPOSAL_SCHEMA_VERSION,
        proposal_id: ContentId::from_seed("real-repository-proposal"),
        producing_attempt_id: attempt.clone(),
        base_checkpoint_id: checkpoint.id.clone(),
        base_checkpoint_digest: checkpoint.digest,
        operations,
        gate_ids: vec![GateId::from_seed("cargo-test")],
    }
}

fn proposal_write(path: &str, preimage: Preimage, contents: &str) -> PatchOperation {
    PatchOperation {
        path: path.parse::<RepoPath>().expect("canonical path"),
        preimage,
        mutation: PatchMutation::Write {
            content_utf8: contents.into(),
        },
    }
}

fn candidate_provenance(repo: &RealRepository, attempt: &str) -> CandidateProvenance {
    CandidateProvenance {
        schema_version: CANDIDATE_MANIFEST_SCHEMA_VERSION,
        repository_id: RepositoryId::from_seed("fixture-repository"),
        producing_attempt_id: AttemptId::parse(attempt).expect("fixture attempt id"),
        attempt_fence: FENCE,
        work_package_id: WorkPackageId::from_seed("fixture-package"),
        variant_id: VariantId::parse(VARIANT).expect("fixture variant id"),
        plan_revision_id: PlanRevisionId::from_seed("fixture-plan"),
        graph_revision_id: GraphRevisionId::from_seed("fixture-graph"),
        base_checkpoint_id: repo.active_checkpoint().id.clone(),
        base_commit: bullet_git_types::GitOid::new(repo.workspace().base_sha())
            .expect("fixture base"),
        parent_candidate_ids: Vec::new(),
        granted_scope: ["src", "docs"]
            .into_iter()
            .map(|path| path.parse::<RepoPath>().expect("fixture grant"))
            .collect(),
        context_capsule_id: ContentId::from_seed("fixture-context"),
        configuration_snapshot_id: ContentId::from_seed("fixture-config"),
        policy_snapshot_id: ContentId::from_seed("fixture-policy"),
        routing_snapshot_id: ContentId::from_seed("fixture-route"),
        environment_digest: Digest::of(b"fixture-environment"),
        toolchain_digest: Digest::of(b"fixture-toolchain"),
    }
}

fn prepare(
    repo: &mut RealRepository,
    auth: &AuthorityEnvelope,
    attempt: &str,
) -> Result<Candidate, bullet_git_workspace::CapabilityError> {
    let provenance = candidate_provenance(repo, attempt);
    repo.prepare_candidate(auth, &change(), &provenance)
}

fn cas_entries(repo: &RealRepository) -> Vec<String> {
    let mut entries = std::fs::read_dir(repo.workspace().runtime_dir().join("cas"))
        .expect("read CAS")
        .map(|entry| {
            entry
                .expect("CAS entry")
                .file_name()
                .to_string_lossy()
                .into_owned()
        })
        .collect::<Vec<_>>();
    entries.sort();
    entries
}

fn candidate_for(patches: &[PatchHunk], attempt: &str) -> Candidate {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, attempt);
    let mut repo = real_repo(workspace, attempt);
    let auth = envelope(attempt, FENCE, NONCE);
    repo.apply_change(&auth, patches).expect("apply");
    prepare(&mut repo, &auth, attempt).expect("prepare")
}

#[path = "real_repository/lifecycle.rs"]
mod lifecycle;
#[path = "real_repository/safety.rs"]
mod safety;
