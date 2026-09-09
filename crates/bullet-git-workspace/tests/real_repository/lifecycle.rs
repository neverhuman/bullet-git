use super::*;

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
    let initial_binding = workspace.active_generation_binding();
    assert_eq!(initial_binding.generation, 0);
    assert!(initial_binding.parent.is_none());
    let mut repo = real_repo(workspace, ATTEMPT);
    let auth = good_auth();

    repo.apply_change(
        &auth,
        &[patch("src/lib.rs", "pub fn generation_one() {}\n")],
    )
    .expect("publish generation");
    assert_eq!(repo.workspace().generation(), 1);
    let next_binding = repo.workspace().active_generation_binding();
    assert_eq!(next_binding.generation, 1);
    assert_eq!(next_binding.checkpoint, *repo.active_checkpoint());
    let parent = next_binding.parent.expect("generation-one parent");
    assert_eq!(parent.generation, 0);
    assert_eq!(parent.manifest_digest, initial_binding.manifest_digest);
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
