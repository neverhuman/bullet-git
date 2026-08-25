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

#[test]
fn full_lifecycle_produces_exact_candidate() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let mut repo = real_repo(workspace, ATTEMPT);
    let auth = good_auth();
    let files = repo.read_tree(&auth).expect("read tree");
    assert!(files.contains(&"README.md".to_string()));
    repo.apply_change(&auth, &[patch("src/lib.rs", "pub fn hello() {}\n")])
        .expect("apply");
    let checkpoint = repo.checkpoint(&auth).expect("checkpoint");
    assert!(checkpoint.identity_is_valid());
    let git_tree = checkpoint.git_tree.expect("git tree");
    assert!(git_tree.as_str().starts_with("sha1:"));
    assert_eq!(git_tree.hex().len(), 40);
    // R7: the checkpoint must not stage anything in the live index.
    let clean_index = repo
        .workspace()
        .git()
        .probe(
            Some(repo.workspace().repo_dir()),
            &["diff", "--cached", "--quiet"],
        )
        .expect("probe");
    assert!(clean_index, "checkpoint staged files in the live index");
    let candidate = prepare(&mut repo, &auth, ATTEMPT).expect("prepare");
    assert_eq!(candidate.manifest.base_commit.as_str(), base);
    assert_ne!(
        candidate.manifest.head_commit,
        candidate.manifest.base_commit
    );
    assert!(candidate.manifest.tree_oid.as_str().starts_with("sha1:"));
    assert_eq!(candidate.manifest.tree_oid.hex().len(), 40);
    assert!(candidate
        .manifest
        .actual_scope
        .iter()
        .any(|path| path.as_str() == "src/lib.rs"));
    assert_eq!(candidate.manifest.producing_attempt_id.as_str(), ATTEMPT);
    println!(
        "prepared candidate:\n{}",
        serde_json::to_string_pretty(&candidate).expect("json")
    );
}

#[test]
fn candidate_subject_mismatches_refuse_before_generation_or_commit() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let mut repo = real_repo(workspace, ATTEMPT);
    let auth = good_auth();
    let valid = candidate_provenance(&repo, ATTEMPT);
    let before_generation = repo.workspace().generation();
    let before_checkpoint = repo.active_checkpoint().clone();
    let before_head = repo
        .workspace()
        .git()
        .run(
            Some(repo.workspace().repo_dir()),
            FileProtocol::Never,
            &["rev-parse", "HEAD"],
            &[],
        )
        .expect("head")
        .text();

    let mut cases = Vec::new();
    let mut schema = valid.clone();
    schema.schema_version += 1;
    cases.push(("schema_version", schema, "UNSUPPORTED_SCHEMA"));
    let mut attempt = valid.clone();
    attempt.producing_attempt_id = AttemptId::from_seed("other-attempt");
    cases.push((
        "producing_attempt_id",
        attempt,
        "CANDIDATE_SUBJECT_MISMATCH",
    ));
    let mut fence = valid.clone();
    fence.attempt_fence += 1;
    cases.push(("attempt_fence", fence, "CANDIDATE_SUBJECT_MISMATCH"));
    let mut variant = valid.clone();
    variant.variant_id = VariantId::from_seed("other-variant");
    cases.push(("variant_id", variant, "CANDIDATE_SUBJECT_MISMATCH"));
    let mut checkpoint = valid.clone();
    checkpoint.base_checkpoint_id = CheckpointId::from_seed("stale-checkpoint");
    cases.push((
        "base_checkpoint_id",
        checkpoint,
        "CANDIDATE_SUBJECT_MISMATCH",
    ));
    let mut base_commit = valid.clone();
    base_commit.base_commit =
        bullet_git_types::GitOid::new(format!("sha1:{}", "0".repeat(40))).expect("oid");
    cases.push(("base_commit", base_commit, "CANDIDATE_SUBJECT_MISMATCH"));
    let mut grant = valid.clone();
    grant.granted_scope = vec!["src/narrow".parse::<RepoPath>().expect("grant")];
    cases.push(("granted_scope", grant, "CANDIDATE_SUBJECT_MISMATCH"));

    for (field, provenance, reason) in cases {
        let error = repo
            .prepare_candidate(&auth, &change(), &provenance)
            .expect_err("subject mismatch refused");
        assert_eq!(error.reason_code(), reason, "field {field}");
        assert_eq!(
            repo.workspace().generation(),
            before_generation,
            "field {field}"
        );
        assert_eq!(
            repo.active_checkpoint(),
            &before_checkpoint,
            "field {field}"
        );
        let after_head = repo
            .workspace()
            .git()
            .run(
                Some(repo.workspace().repo_dir()),
                FileProtocol::Never,
                &["rev-parse", "HEAD"],
                &[],
            )
            .expect("head")
            .text();
        assert_eq!(after_head, before_head, "field {field} created a commit");
    }

    let hostile_variant = VariantId::from_seed("authority-variant");
    let authority = AuthorityEnvelope {
        token: serde_json::to_vec(&serde_json::json!({
            "variant_id": hostile_variant,
            "attempt_id": ATTEMPT,
            "attempt_fence": FENCE,
            "workspace_nonce": NONCE,
        }))
        .expect("authority"),
    };
    let error = repo
        .prepare_candidate(&authority, &change(), &valid)
        .expect_err("authority variant refused");
    assert_eq!(error.reason_code(), "CANDIDATE_SUBJECT_MISMATCH");
    assert_eq!(repo.workspace().generation(), before_generation);
    assert_eq!(repo.active_checkpoint(), &before_checkpoint);
}

#[test]
fn journal_reopens_from_the_workspace_runtime_directory() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let mut repo = real_repo(workspace, ATTEMPT);
    let auth = good_auth();
    repo.apply_change(
        &auth,
        &[
            patch("src/a.rs", "pub fn a() {}\n"),
            patch("src/b.rs", "pub fn b() {}\n"),
        ],
    )
    .expect("apply durable batch");
    let expected_ops = repo.journal_ops().to_vec();
    let expected_checkpoint = repo.checkpoint(&auth).expect("checkpoint");
    let workspace = repo.into_workspace();

    let mut reopened = real_repo(workspace, ATTEMPT);
    assert_eq!(reopened.journal_ops(), expected_ops);
    assert_eq!(
        reopened
            .checkpoint(&auth)
            .expect("reopened checkpoint")
            .digest,
        expected_checkpoint.digest
    );
}

#[test]
fn active_checkpoint_accessor_is_read_only_clone_metadata() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let repo = real_repo(workspace, ATTEMPT);
    let before_generation = repo.workspace().generation();
    let before_journal = repo.journal_ops().to_vec();
    let before_tree =
        std::fs::read(repo.workspace().repo_dir().join("src/lib.rs")).expect("tree bytes");
    let before_cas = cas_entries(&repo);

    let first = repo.active_checkpoint().clone();
    let second = repo.active_checkpoint().clone();

    assert_eq!(first, second);
    assert!(first.identity_is_valid());
    assert_eq!(repo.workspace().generation(), before_generation);
    assert_eq!(repo.journal_ops(), before_journal);
    assert_eq!(cas_entries(&repo), before_cas);
    assert_eq!(
        std::fs::read(repo.workspace().repo_dir().join("src/lib.rs")).expect("tree unchanged"),
        before_tree
    );
}

#[test]
fn apply_publishes_one_complete_generation_and_preserves_the_prior_bytes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let prior_repo = workspace.repo_dir().to_path_buf();
    let prior = std::fs::read(prior_repo.join("src/lib.rs")).expect("prior bytes");
    assert_eq!(workspace.generation(), 0);
    let mut repo = real_repo(workspace, ATTEMPT);
    let auth = good_auth();

    repo.apply_change(
        &auth,
        &[patch("src/lib.rs", "pub fn generation_one() {}\n")],
    )
    .expect("publish generation");
    assert_eq!(repo.workspace().generation(), 1);
    assert_ne!(repo.workspace().repo_dir(), prior_repo);
    assert_eq!(
        std::fs::read(prior_repo.join("src/lib.rs")).expect("immutable prior"),
        prior
    );
    let expected = repo.checkpoint(&auth).expect("exact checkpoint");
    let expected_ops = repo.journal_ops().to_vec();
    let workspace = repo.into_workspace();

    let mut reopened = real_repo(workspace, ATTEMPT);
    assert_eq!(reopened.workspace().generation(), 1);
    assert_eq!(reopened.journal_ops(), expected_ops);
    assert_eq!(reopened.checkpoint(&auth).expect("reopened"), expected);
    assert_eq!(
        std::fs::read(reopened.workspace().repo_dir().join("src/lib.rs")).expect("complete next"),
        b"pub fn generation_one() {}\n"
    );
}

#[test]
fn apply_proposal_publishes_only_after_exact_checkpoint_and_preimages_match() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let attempt = AttemptId::from_seed("real-proposal-success");
    let workspace = clone_workspace(tmp.path(), &src, &base, attempt.as_str());
    let mut repo = real_repo(workspace, attempt.as_str());
    let auth = envelope(attempt.as_str(), FENCE, NONCE);
    let before = repo.checkpoint(&auth).expect("base checkpoint");
    let current =
        std::fs::read(repo.workspace().repo_dir().join("src/lib.rs")).expect("current preimage");
    let proposal = proposal(
        &attempt,
        &before,
        vec![
            proposal_write(
                "src/lib.rs",
                Preimage::Digest {
                    digest: Digest::of(&current),
                },
                "pub fn proposal() {}\n",
            ),
            proposal_write("src/new.rs", Preimage::Absent, "pub fn added() {}\n"),
        ],
    );

    let after = repo
        .apply_proposal(&auth, &proposal)
        .expect("exact proposal applies");
    assert_eq!(repo.workspace().generation(), 1);
    assert_eq!(repo.journal_ops().len(), 2);
    assert_ne!(after.id, before.id);
    assert_ne!(after.digest, before.digest);
    assert_eq!(repo.checkpoint(&auth).expect("active checkpoint"), after);
    assert_eq!(
        std::fs::read(repo.workspace().repo_dir().join("src/lib.rs")).expect("next bytes"),
        b"pub fn proposal() {}\n"
    );
}

#[test]
fn stale_proposal_subjects_leave_generation_journal_tree_and_cas_unchanged() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let attempt = AttemptId::from_seed("real-proposal-refusal");
    let workspace = clone_workspace(tmp.path(), &src, &base, attempt.as_str());
    let mut repo = real_repo(workspace, attempt.as_str());
    let auth = envelope(attempt.as_str(), FENCE, NONCE);
    let checkpoint = repo.checkpoint(&auth).expect("base checkpoint");
    let target = repo.workspace().repo_dir().join("src/lib.rs");
    let before_bytes = std::fs::read(&target).expect("before bytes");
    let before_generation = repo.workspace().generation();
    let before_journal = repo.journal_ops().to_vec();
    let before_cas = cas_entries(&repo);

    let assert_unchanged = |repo: &mut RealRepository| {
        assert_eq!(repo.workspace().generation(), before_generation);
        assert_eq!(repo.journal_ops(), before_journal);
        assert_eq!(std::fs::read(&target).expect("tree bytes"), before_bytes);
        assert_eq!(cas_entries(repo), before_cas, "validation wrote CAS state");
        assert_eq!(
            repo.checkpoint(&auth).expect("active checkpoint"),
            checkpoint
        );
    };

    let mut stale_checkpoint = proposal(
        &attempt,
        &checkpoint,
        vec![proposal_write(
            "src/lib.rs",
            Preimage::Digest {
                digest: Digest::of(&before_bytes),
            },
            "stale checkpoint must not land\n",
        )],
    );
    stale_checkpoint.base_checkpoint_id = CheckpointId::from_seed("wrong-checkpoint");
    let error = repo
        .apply_proposal(&auth, &stale_checkpoint)
        .expect_err("stale checkpoint refused");
    assert_eq!(error.reason_code(), "STALE_CHECKPOINT");
    assert_unchanged(&mut repo);

    let stale_preimage = proposal(
        &attempt,
        &checkpoint,
        vec![
            proposal_write("src/new.rs", Preimage::Absent, "must remain absent\n"),
            proposal_write(
                "src/lib.rs",
                Preimage::Digest {
                    digest: Digest::of(b"wrong preimage"),
                },
                "stale preimage must not land\n",
            ),
        ],
    );
    let error = repo
        .apply_proposal(&auth, &stale_preimage)
        .expect_err("stale preimage refused");
    assert_eq!(error.reason_code(), "STALE_PREIMAGE");
    assert!(!repo.workspace().repo_dir().join("src/new.rs").exists());
    assert_unchanged(&mut repo);

    let mut wrong_attempt = proposal(
        &attempt,
        &checkpoint,
        vec![proposal_write(
            "src/new.rs",
            Preimage::Absent,
            "not written\n",
        )],
    );
    wrong_attempt.producing_attempt_id = AttemptId::from_seed("different-attempt");
    let error = repo
        .apply_proposal(&auth, &wrong_attempt)
        .expect_err("wrong producing attempt refused");
    assert_eq!(error.reason_code(), "PROPOSAL_ATTEMPT_MISMATCH");
    assert_unchanged(&mut repo);
}

#[test]
fn cas_publication_before_tree_mutation_recovers_the_prior_checkpoint() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let mut repo = real_repo(workspace, ATTEMPT);
    let auth = good_auth();
    let before = repo.checkpoint(&auth).expect("prior checkpoint");
    let workspace = repo.into_workspace();

    let cas = ImmutableCas::open(workspace.runtime_dir().join("cas")).expect("open CAS");
    let orphan = cas
        .put(b"published without journal batch")
        .expect("put orphan");
    drop(cas);

    let mut reopened = real_repo(workspace, ATTEMPT);
    assert!(reopened.journal_ops().is_empty());
    assert_eq!(
        reopened.checkpoint(&auth).expect("prior").digest,
        before.digest
    );
    let cas =
        ImmutableCas::open(reopened.workspace().runtime_dir().join("cas")).expect("reopen CAS");
    assert_eq!(
        cas.get(&orphan.digest).expect("read orphan"),
        Some(b"published without journal batch".to_vec())
    );
}

#[test]
fn reopen_fails_closed_when_a_journal_content_object_is_missing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let mut repo = real_repo(workspace, ATTEMPT);
    repo.apply_change(&good_auth(), &[patch("src/lib.rs", "changed\n")])
        .expect("apply");
    let missing = repo.journal_ops()[0].after.expect("after object");
    let workspace = repo.into_workspace();
    std::fs::remove_file(workspace.runtime_dir().join("cas").join(missing.to_hex()))
        .expect("remove object");

    let error = match RealRepository::new(
        workspace,
        ScopeGrant::new(&["src".into(), "docs".into()]).expect("grant"),
        ExpectedAuthority {
            attempt_id: ATTEMPT.into(),
            attempt_fence: FENCE,
            workspace_nonce: NONCE,
        },
        CommitIdentity::farm(support::COMMIT_DATE),
    ) {
        Ok(_) => panic!("missing object accepted"),
        Err(error) => error,
    };
    assert_eq!(error.reason_code(), "CAS_CORRUPT");
}

#[test]
fn journal_append_failure_restores_the_applied_file_batch() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let mut repo = real_repo(workspace, ATTEMPT);
    let auth = good_auth();
    let target = repo.workspace().repo_dir().join("src/lib.rs");
    let before = std::fs::read(&target).expect("read before-state");
    let occupied = repo
        .workspace()
        .journal_dir()
        .join("00000000000000000001-00000000000000000001.json");
    std::fs::write(&occupied, b"occupied").expect("occupy next batch name");

    let error = repo
        .apply_change(&auth, &[patch("src/lib.rs", "pub fn changed() {}\n")])
        .expect_err("journal publication refused");
    assert_eq!(error.reason_code(), "JOURNAL_FAILED");
    assert_eq!(std::fs::read(&target).expect("read restored file"), before);
    assert!(repo.journal_ops().is_empty(), "failed batch became visible");
}

#[test]
fn oversized_preimage_is_refused_before_tree_or_journal_mutation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let mut repo = real_repo(workspace, ATTEMPT);
    let target = repo.workspace().repo_dir().join("src/lib.rs");
    let oversized = vec![b'x'; MAX_CAS_OBJECT_BYTES + 1];
    std::fs::write(&target, &oversized).expect("oversized preimage fixture");

    let error = repo
        .apply_change(&good_auth(), &[patch("src/lib.rs", "replacement\n")])
        .expect_err("oversized preimage refused");
    assert_eq!(error.reason_code(), "CAS_OBJECT_TOO_LARGE");
    assert_eq!(std::fs::read(&target).expect("unchanged tree"), oversized);
    assert!(repo.journal_ops().is_empty(), "journal must remain prior");
}

#[test]
fn same_content_is_reusable_across_distinct_attempt_candidates() {
    let a = patch("src/a.rs", "pub fn a() {}\n");
    let b = patch("src/b.rs", "pub fn b() {}\n");
    let one = candidate_for(&[a.clone(), b.clone()], ATTEMPT);
    let two = candidate_for(&[b, a], ATTEMPT_2);
    assert_eq!(
        one.manifest.tree_oid, two.manifest.tree_oid,
        "same tree, same tree OID"
    );
    assert_eq!(
        one.manifest.patch_digest, two.manifest.patch_digest,
        "order must not change digests"
    );
    assert_eq!(one.content_id, two.content_id, "content remains reusable");
    assert_ne!(one.id, two.id, "producing Attempt is Candidate provenance");
}

#[test]
fn different_contents_under_one_change_have_different_candidate_ids() {
    let one = candidate_for(&[patch("src/a.rs", "pub fn a() {}\n")], ATTEMPT);
    let two = candidate_for(&[patch("src/a.rs", "pub fn b() {}\n")], ATTEMPT);
    assert_eq!(one.manifest.change_id, two.manifest.change_id);
    assert_ne!(one.manifest.tree_oid, two.manifest.tree_oid);
    assert_ne!(one.content_id, two.content_id);
    assert_ne!(one.id, two.id, "two different trees must never share an id");
}

#[test]
fn out_of_scope_patch_is_refused_naming_the_path_and_tree_untouched() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let mut repo = real_repo(workspace, ATTEMPT);
    let auth = good_auth();
    let err = repo
        .apply_change(
            &auth,
            &[
                patch("src/new.rs", "pub fn ok() {}\n"),
                patch("README.md", "hijacked\n"),
            ],
        )
        .expect_err("refused");
    assert_eq!(err.reason_code(), "OUT_OF_SCOPE");
    assert!(err.to_string().contains("README.md"));
    assert!(!repo.workspace().repo_dir().join("src/new.rs").exists());
    let status = repo
        .workspace()
        .git()
        .run(
            Some(repo.workspace().repo_dir()),
            FileProtocol::Never,
            &["status", "--porcelain=v2"],
            &[],
        )
        .expect("status");
    assert!(status.text().is_empty(), "tree must be untouched");
}

#[test]
fn duplicate_patch_paths_are_refused_before_any_file_is_written() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let mut repo = real_repo(workspace, ATTEMPT);
    let auth = good_auth();
    let target = repo.workspace().repo_dir().join("src/duplicate.rs");
    let err = repo
        .apply_change(
            &auth,
            &[
                patch("src/duplicate.rs", "first\n"),
                patch("src/duplicate.rs", "second\n"),
            ],
        )
        .expect_err("duplicate refused");
    assert_eq!(err.reason_code(), "DUPLICATE_PATH");
    assert!(!target.exists(), "validation failure must precede mutation");

    let upper = repo.workspace().repo_dir().join("src/Portable.rs");
    let lower = repo.workspace().repo_dir().join("src/portable.rs");
    let err = repo
        .apply_change(
            &auth,
            &[
                patch("src/Portable.rs", "first\n"),
                patch("src/portable.rs", "second\n"),
            ],
        )
        .expect_err("portable collision refused");
    assert_eq!(err.reason_code(), "PATH_COLLISION");
    assert!(!upper.exists() && !lower.exists(), "batch must be atomic");
}

#[test]
fn hostile_hooks_and_home_config_never_execute() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let canary = tmp.path().join("canary");
    let canary_script = format!("#!/bin/sh\ntouch {}\nexit 0\n", canary.display());
    // Hostile hook planted inside the private clone's own .git.
    let hooks = workspace.repo_dir().join(".git").join("hooks");
    std::fs::create_dir_all(&hooks).expect("hooks dir");
    write_executable(&hooks.join("pre-commit"), &canary_script);
    // Hostile config planted in the isolated HOME the SafeGit uses.
    let hostile_hooks = tmp.path().join("hostile-hooks");
    std::fs::create_dir_all(&hostile_hooks).expect("hostile hooks dir");
    write_executable(&hostile_hooks.join("pre-commit"), &canary_script);
    let home_config = workspace.runtime_dir().join("home").join(".gitconfig");
    std::fs::write(
        &home_config,
        format!(
            "[core]\n\thooksPath = {}\n[includeIf \"gitdir:/\"]\n\tpath = {}\n",
            hostile_hooks.display(),
            home_config.display()
        ),
    )
    .expect("hostile gitconfig");
    let mut repo = real_repo(workspace, ATTEMPT);
    let auth = good_auth();
    repo.apply_change(&auth, &[patch("src/lib.rs", "pub fn h() {}\n")])
        .expect("apply");
    let candidate = prepare(&mut repo, &auth, ATTEMPT).expect("prepare");
    assert_eq!(candidate.manifest.base_commit.as_str(), base);
    assert!(!canary.exists(), "a hostile hook executed");
}

#[test]
fn repository_local_clean_filter_is_refused_before_execution() {
    use std::io::Write;

    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let canary = tmp.path().join("filter-canary");
    let filter = tmp.path().join("clean-filter.sh");
    write_executable(
        &filter,
        &format!("#!/bin/sh\ntouch {}\ncat\n", canary.display()),
    );
    let mut repo = real_repo(workspace, ATTEMPT);
    let auth = good_auth();
    repo.apply_change(&auth, &[patch("src/lib.rs", "pub fn filtered() {}\n")])
        .expect("apply before hostile config");
    std::fs::write(
        repo.workspace().repo_dir().join(".gitattributes"),
        "*.rs filter=bullet-canary\n",
    )
    .expect("hostile attributes");
    let mut config = std::fs::OpenOptions::new()
        .append(true)
        .open(repo.workspace().repo_dir().join(".git/config"))
        .expect("open local config");
    writeln!(
        config,
        "[filter \"bullet-canary\"]\n\tclean = {}\n\trequired = true",
        filter.display()
    )
    .expect("plant local filter");
    drop(config);

    let error = repo.checkpoint(&auth).expect_err("hostile filter refused");
    assert_eq!(error.reason_code(), "HOSTILE_GIT_CONFIG");
    assert!(error.to_string().contains("filter.bullet-canary.clean"));
    assert!(!canary.exists(), "repository-local clean filter executed");
}

#[test]
fn delete_of_tracked_file_lands_in_candidate_and_journal() {
    use bullet_git_journal::JournalOpKind;
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let mut repo = real_repo(workspace, ATTEMPT);
    let auth = good_auth();
    let target = repo.workspace().repo_dir().join("src/lib.rs");
    let before = std::fs::read(&target).expect("before bytes");
    repo.apply_change(&auth, &[PatchHunk::delete("src/lib.rs")])
        .expect("delete");
    assert!(target.exists(), "prior generation remains immutable");
    assert!(
        !repo.workspace().repo_dir().join("src/lib.rs").exists(),
        "file removed from the active generation"
    );
    let op = repo.journal_ops().last().expect("journal op");
    assert_eq!(op.kind, JournalOpKind::Delete);
    assert_eq!(op.before, Some(cas_digest(&before)), "before-state object");
    assert_eq!(op.after, None);
    let candidate = prepare(&mut repo, &auth, ATTEMPT).expect("prepare");
    assert!(candidate
        .manifest
        .actual_scope
        .iter()
        .any(|path| path.as_str() == "src/lib.rs"));
    let listed = repo
        .workspace()
        .git()
        .run(
            Some(repo.workspace().repo_dir()),
            FileProtocol::Never,
            &["ls-tree", "-r", "--name-only", "HEAD"],
            &[],
        )
        .expect("ls-tree")
        .text();
    assert!(
        !listed.contains("src/lib.rs"),
        "deleted file must not linger in the candidate tree: {listed}"
    );
    assert!(listed.contains("README.md"));
}

#[test]
fn delete_of_absent_path_refuses_before_any_mutation() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let mut repo = real_repo(workspace, ATTEMPT);
    let auth = good_auth();
    let err = repo
        .apply_change(
            &auth,
            &[
                patch("src/new.rs", "pub fn ok() {}\n"),
                PatchHunk::delete("src/ghost.rs"),
            ],
        )
        .expect_err("refused");
    assert_eq!(err.reason_code(), "PATH_ABSENT");
    assert!(err.to_string().contains("src/ghost.rs"));
    assert!(
        !repo.workspace().repo_dir().join("src/new.rs").exists(),
        "failed batch must not write"
    );
    let err = repo
        .apply_change(&auth, &[PatchHunk::delete("README.md")])
        .expect_err("out of scope");
    assert_eq!(err.reason_code(), "OUT_OF_SCOPE");
    assert!(repo.workspace().repo_dir().join("README.md").exists());
}

#[test]
fn worktree_shaped_directory_is_refused() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let mut repo = real_repo(workspace, ATTEMPT);
    // A worktree is a directory whose .git is a FILE containing `gitdir: ...`.
    let dot_git = repo.workspace().repo_dir().join(".git");
    let hidden = repo.workspace().repo_dir().join(".git-moved");
    std::fs::rename(&dot_git, &hidden).expect("move .git aside");
    std::fs::write(&dot_git, format!("gitdir: {}\n", hidden.display())).expect("gitdir file");
    let auth = good_auth();
    let err = repo
        .apply_change(&auth, &[patch("src/lib.rs", "x")])
        .expect_err("refused");
    assert_eq!(err.reason_code(), "WORKTREE_FORBIDDEN");
    let err = repo.checkpoint(&auth).expect_err("refused");
    assert_eq!(err.reason_code(), "WORKTREE_FORBIDDEN");
}

#[test]
fn sequencer_state_blocks_checkpoint_and_prepare() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    std::fs::write(workspace.repo_dir().join(".git").join("MERGE_HEAD"), base).expect("merge head");
    let mut repo = real_repo(workspace, ATTEMPT);
    let auth = good_auth();
    let err = repo.checkpoint(&auth).expect_err("refused");
    assert_eq!(err.reason_code(), "SEQUENCER_ACTIVE");
    let err = prepare(&mut repo, &auth, ATTEMPT).expect_err("refused");
    assert_eq!(err.reason_code(), "SEQUENCER_ACTIVE");
}

#[test]
fn unclassified_untracked_file_outside_scope_blocks_prepare() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let mut repo = real_repo(workspace, ATTEMPT);
    std::fs::write(repo.workspace().repo_dir().join("stray.bin"), b"noise").expect("stray");
    let auth = good_auth();
    let err = prepare(&mut repo, &auth, ATTEMPT).expect_err("refused");
    assert_eq!(err.reason_code(), "UNCLASSIFIED_UNTRACKED");
    assert!(err.to_string().contains("stray.bin"));
}

#[test]
fn stale_empty_and_garbage_tokens_are_refused() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let repo = real_repo(workspace, ATTEMPT);
    let err = repo
        .read_tree(&envelope(ATTEMPT, FENCE + 1, NONCE))
        .expect_err("stale fence");
    assert_eq!(err.reason_code(), "STALE_AUTHORITY");
    let err = repo
        .read_tree(&AuthorityEnvelope { token: Vec::new() })
        .expect_err("empty");
    assert_eq!(err.reason_code(), "UNAUTHORIZED");
    let err = repo
        .read_tree(&AuthorityEnvelope {
            token: b"x".to_vec(),
        })
        .expect_err("garbage");
    assert_eq!(err.reason_code(), "UNAUTHORIZED");
}

#[test]
fn symlink_write_is_refused() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let mut repo = real_repo(workspace, ATTEMPT);
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&outside).expect("outside");
    std::os::unix::fs::symlink(
        &outside,
        repo.workspace().repo_dir().join("src").join("link"),
    )
    .expect("symlink");
    let auth = good_auth();
    let err = repo
        .apply_change(&auth, &[patch("src/link", "overwrite")])
        .expect_err("refused");
    assert_eq!(err.reason_code(), "SYMLINK_FORBIDDEN");
    let err = repo
        .apply_change(&auth, &[patch("src/link/inner.rs", "escape")])
        .expect_err("refused");
    assert_eq!(err.reason_code(), "SYMLINK_FORBIDDEN");
}

fn write_executable(path: &std::path::Path, contents: &str) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, contents).expect("write script");
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755)).expect("chmod");
}
