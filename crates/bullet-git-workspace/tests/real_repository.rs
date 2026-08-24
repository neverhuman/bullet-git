//! RealRepository over real Git: lifecycle, determinism, and fail-closed paths.

mod support;

use bullet_git_types::{AuthorityEnvelope, Candidate, Change, ChangeId, Digest};
use bullet_git_workspace::{AgentRepository, FileProtocol, PatchHunk};
use support::{
    clone_workspace, envelope, good_auth, init_source, real_repo, ATTEMPT, FENCE, NONCE,
};

fn change() -> Change {
    Change {
        id: ChangeId::from_seed("feat"),
        mission: "demo".into(),
        acceptance_root: Digest::of(b"acc"),
    }
}

fn patch(path: &str, contents: &str) -> PatchHunk {
    PatchHunk {
        path: path.into(),
        contents: contents.as_bytes().to_vec(),
    }
}

fn candidate_for(patches: &[PatchHunk], attempt: &str) -> Candidate {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, attempt);
    let mut repo = real_repo(workspace, attempt);
    let auth = envelope(attempt, FENCE, NONCE);
    repo.apply_change(&auth, patches).expect("apply");
    repo.prepare_candidate(&auth, &change()).expect("prepare")
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
    let git_tree = checkpoint.git_tree.expect("git tree");
    assert_eq!(git_tree.as_str().len(), 40);
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
    let candidate = repo.prepare_candidate(&auth, &change()).expect("prepare");
    assert_eq!(candidate.base_commit.as_str(), base);
    assert_ne!(candidate.head_commit, candidate.base_commit);
    assert_eq!(candidate.tree_hash.as_str().len(), 40);
    assert!(candidate.actual_scope.contains(&"src/lib.rs".to_string()));
    assert_eq!(candidate.attempt_id, ATTEMPT);
    println!(
        "prepared candidate:\n{}",
        serde_json::to_string_pretty(&candidate).expect("json")
    );
}

#[test]
fn same_tree_means_same_tree_sha_and_order_does_not_matter() {
    let a = patch("src/a.rs", "pub fn a() {}\n");
    let b = patch("src/b.rs", "pub fn b() {}\n");
    let one = candidate_for(&[a.clone(), b.clone()], ATTEMPT);
    let two = candidate_for(&[b, a], "atm_fixture02");
    assert_eq!(one.tree_hash, two.tree_hash, "same tree, same tree_sha");
    assert_eq!(
        one.patch_hash, two.patch_hash,
        "order must not change digests"
    );
    assert_eq!(one.id, two.id, "content-derived id is order independent");
}

#[test]
fn different_contents_under_one_change_have_different_candidate_ids() {
    let one = candidate_for(&[patch("src/a.rs", "pub fn a() {}\n")], ATTEMPT);
    let two = candidate_for(&[patch("src/a.rs", "pub fn b() {}\n")], "atm_fixture02");
    assert_eq!(one.change, two.change);
    assert_ne!(one.tree_hash, two.tree_hash);
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
    let candidate = repo.prepare_candidate(&auth, &change()).expect("prepare");
    assert_eq!(candidate.base_commit.as_str(), base);
    assert!(!canary.exists(), "a hostile hook executed");
}

#[test]
fn worktree_shaped_directory_is_refused() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    // A worktree is a directory whose .git is a FILE containing `gitdir: ...`.
    let dot_git = workspace.repo_dir().join(".git");
    let hidden = workspace.repo_dir().join(".git-moved");
    std::fs::rename(&dot_git, &hidden).expect("move .git aside");
    std::fs::write(&dot_git, format!("gitdir: {}\n", hidden.display())).expect("gitdir file");
    let mut repo = real_repo(workspace, ATTEMPT);
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
    let err = repo
        .prepare_candidate(&auth, &change())
        .expect_err("refused");
    assert_eq!(err.reason_code(), "SEQUENCER_ACTIVE");
}

#[test]
fn unclassified_untracked_file_outside_scope_blocks_prepare() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    std::fs::write(workspace.repo_dir().join("stray.bin"), b"noise").expect("stray");
    let mut repo = real_repo(workspace, ATTEMPT);
    let auth = good_auth();
    let err = repo
        .prepare_candidate(&auth, &change())
        .expect_err("refused");
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
    let outside = tmp.path().join("outside");
    std::fs::create_dir_all(&outside).expect("outside");
    std::os::unix::fs::symlink(&outside, workspace.repo_dir().join("src").join("link"))
        .expect("symlink");
    let mut repo = real_repo(workspace, ATTEMPT);
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
