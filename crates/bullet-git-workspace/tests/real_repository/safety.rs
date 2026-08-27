use super::*;

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
