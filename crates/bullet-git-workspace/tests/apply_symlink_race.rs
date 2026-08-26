//! Descriptor-relative apply: symlinks swapped in after validation are
//! refused at the open, failed batches roll back, and nothing outside the
//! staged generation root ever changes.
//!
//! The `dirfd` module is compiled from its exact source here (it depends only
//! on `std` and `rustix`) so the swap can be staged between the validation
//! read and the write; the `RealRepository` tests prove the wired path.
#![cfg(target_os = "linux")]

mod support;

#[allow(dead_code)]
#[path = "../src/apply/dirfd.rs"]
mod dirfd;

use bullet_git_workspace::{AgentRepository, CapabilityError, GenerationError, PatchHunk};
use dirfd::{DirfdError, StagedRoot};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use support::{clone_workspace, good_auth, init_source, real_repo, ATTEMPT};

/// Every regular file and symlink under `dir` (recursively) with its bytes or
/// link target, so "nothing changed" is an exact comparison.
fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut entries = BTreeMap::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(&current).expect("read snapshot dir") {
            let path = entry.expect("snapshot entry").path();
            if path.file_name().is_some_and(|name| name == ".git") {
                continue;
            }
            let metadata = fs::symlink_metadata(&path).expect("snapshot metadata");
            if metadata.file_type().is_symlink() {
                let target = fs::read_link(&path).expect("snapshot link");
                entries.insert(path, target.to_string_lossy().into_owned().into_bytes());
            } else if metadata.is_dir() {
                entries.insert(path.clone(), b"<dir>".to_vec());
                pending.push(path);
            } else {
                entries.insert(path.clone(), fs::read(&path).expect("snapshot bytes"));
            }
        }
    }
    entries
}

/// A staged root with a real `src/` directory and an outside directory
/// holding `secret` and `existing`.
fn hostile_fixture() -> (tempfile::TempDir, PathBuf, PathBuf) {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = temp.path().join("repo");
    let outside = temp.path().join("outside");
    fs::create_dir_all(root.join("src")).expect("root src");
    fs::create_dir_all(&outside).expect("outside");
    fs::write(outside.join("secret"), b"outside secret").expect("outside secret");
    fs::write(outside.join("existing"), b"outside existing").expect("outside existing");
    (temp, root, outside)
}

fn swap_to_symlink(path: &Path, target: &Path) {
    let aside = path.with_extension("aside");
    fs::rename(path, &aside).expect("move real directory aside");
    symlink(target, path).expect("swap in symlink");
}

#[test]
fn directory_component_swapped_to_symlink_after_validation_is_refused() {
    let (_temp, root, outside) = hostile_fixture();
    let before = snapshot(&outside);
    let staged = StagedRoot::open(&root).expect("open staged root");
    assert_eq!(staged.read("src/secret").expect("clean preimage"), None);

    swap_to_symlink(&root.join("src"), &outside);

    let error = staged
        .write("src/secret", b"escaped")
        .expect_err("write through swapped symlink");
    assert_eq!(
        error,
        DirfdError::Symlink {
            path: "src/secret".into()
        }
    );
    assert_eq!(error.reason_code(), "SYMLINK_FORBIDDEN");
    let error = staged
        .unlink("src/existing")
        .expect_err("unlink through swapped symlink");
    assert_eq!(error.reason_code(), "SYMLINK_FORBIDDEN");
    let error = staged
        .read("src/secret")
        .expect_err("preimage read through swapped symlink");
    assert_eq!(error.reason_code(), "SYMLINK_FORBIDDEN");
    assert_eq!(snapshot(&outside), before, "outside directory changed");

    // A deeper swap: `src` is real again but `src/vendor` points outside.
    fs::remove_file(root.join("src")).expect("drop symlink");
    fs::rename(root.join("src.aside"), root.join("src")).expect("restore src");
    symlink(&outside, root.join("src/vendor")).expect("nested symlink");
    let error = staged
        .write("src/vendor/deep/escape.rs", b"escaped")
        .expect_err("mkdir walk through nested symlink");
    assert_eq!(error.reason_code(), "SYMLINK_FORBIDDEN");
    assert!(error.to_string().contains("src/vendor/deep/escape.rs"));
    assert_eq!(snapshot(&outside), before, "outside directory changed");
}

#[test]
fn symlinked_file_target_is_refused_for_write_and_delete() {
    let (_temp, root, outside) = hostile_fixture();
    let before = snapshot(&outside);
    let staged = StagedRoot::open(&root).expect("open staged root");
    symlink(outside.join("secret"), root.join("src/link.rs")).expect("file symlink");

    let error = staged
        .write("src/link.rs", b"overwrite")
        .expect_err("write onto file symlink");
    assert_eq!(error.reason_code(), "SYMLINK_FORBIDDEN");
    let error = staged
        .unlink("src/link.rs")
        .expect_err("delete of file symlink");
    assert_eq!(
        error,
        DirfdError::Symlink {
            path: "src/link.rs".into()
        }
    );
    assert!(
        fs::symlink_metadata(root.join("src/link.rs"))
            .expect("link survives")
            .file_type()
            .is_symlink(),
        "the symlink itself must not be unlinked"
    );
    assert_eq!(snapshot(&outside), before, "outside directory changed");
}

#[test]
fn rollback_reports_every_unrestorable_path() {
    let (_temp, root, outside) = hostile_fixture();
    fs::write(root.join("src/a.rs"), b"staged a").expect("staged a");
    fs::write(outside.join("a.rs"), b"outside a").expect("outside a");
    fs::write(outside.join("b.rs"), b"outside b").expect("outside b");
    let before = snapshot(&outside);
    let staged = StagedRoot::open(&root).expect("open staged root");

    swap_to_symlink(&root.join("src"), &outside);

    let undo: Vec<(&str, Option<&[u8]>)> = vec![
        ("src/b.rs", None),
        ("src/a.rs", Some(b"prior a".as_slice())),
    ];
    let error = staged
        .restore(undo.into_iter())
        .expect_err("rollback through swapped symlink");
    assert_eq!(error.reason_code(), "GENERATION_IO_FAILED");
    let DirfdError::Restore { failures } = &error else {
        panic!("expected aggregated restore refusal, got {error:?}");
    };
    assert_eq!(
        failures
            .iter()
            .map(|failure| (failure.path.as_str(), failure.reason_code))
            .collect::<Vec<_>>(),
        vec![
            ("src/b.rs", "SYMLINK_FORBIDDEN"),
            ("src/a.rs", "SYMLINK_FORBIDDEN"),
        ]
    );
    let message = error.to_string();
    assert!(message.contains("2 path(s)") && message.contains("src/a.rs"));
    assert!(message.contains("src/b.rs"));
    assert_eq!(snapshot(&outside), before, "outside directory changed");
}

#[test]
fn git_and_traversal_components_are_refused_before_any_open() {
    let (_temp, root, _outside) = hostile_fixture();
    let before = snapshot(&root);
    let staged = StagedRoot::open(&root).expect("open staged root");
    for bad in [
        "",
        "/etc/passwd",
        "../escape",
        "src/../escape",
        "..",
        ".",
        "src/./x.rs",
        "src//x.rs",
        ".git/hooks/pre-commit",
        "src/.GIT/config",
        "src\\x.rs",
        "src/a\0b",
    ] {
        for (label, error) in [
            ("write", staged.write(bad, b"x").expect_err("write refused")),
            ("unlink", staged.unlink(bad).expect_err("unlink refused")),
            ("read", staged.read(bad).expect_err("read refused")),
        ] {
            assert!(
                matches!(&error, DirfdError::InvalidPath { path, .. } if path == bad),
                "{label} {bad:?} gave {error:?}"
            );
            assert_eq!(error.reason_code(), "OUT_OF_SCOPE", "{label} {bad:?}");
        }
    }
    assert_eq!(snapshot(&root), before, "refused paths touched the tree");
}

#[test]
fn descriptor_relative_write_creates_directories_and_round_trips() {
    let (_temp, root, _outside) = hostile_fixture();
    let staged = StagedRoot::open(&root).expect("open staged root");
    staged
        .write("src/nested/deep/file.rs", b"first")
        .expect("nested write");
    assert_eq!(
        staged.read("src/nested/deep/file.rs").expect("read back"),
        Some(b"first".to_vec())
    );
    staged
        .write("src/nested/deep/file.rs", b"second, shorter")
        .expect("truncating rewrite");
    assert_eq!(
        fs::read(root.join("src/nested/deep/file.rs")).expect("bytes"),
        b"second, shorter"
    );
    staged.unlink("src/nested/deep/file.rs").expect("unlink");
    assert_eq!(staged.read("src/nested/deep/file.rs").expect("gone"), None);
    assert_eq!(
        staged
            .unlink("src/nested/deep/file.rs")
            .expect_err("absent"),
        DirfdError::Absent {
            path: "src/nested/deep/file.rs".into()
        }
    );
    let error = staged
        .unlink("src/nested")
        .expect_err("directory is not a regular file");
    assert_eq!(error.reason_code(), "PATH_ABSENT");
    assert!(root.join("src/nested/deep").is_dir());
}

fn staging_repo(active_repo: &Path) -> PathBuf {
    let generations = active_repo
        .parent()
        .and_then(Path::parent)
        .expect("generations directory");
    let mut stages = fs::read_dir(generations)
        .expect("read generations")
        .map(|entry| entry.expect("generation entry").path())
        .filter(|path| {
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".stage-"))
        })
        .collect::<Vec<_>>();
    assert_eq!(stages.len(), 1, "exactly one abandoned staging generation");
    stages.pop().expect("staging generation").join("repo")
}

#[test]
fn mid_batch_failure_rolls_back_staging_and_names_the_exact_path() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let active_repo = workspace.repo_dir().to_path_buf();
    let prior_lib = fs::read(active_repo.join("src/lib.rs")).expect("prior lib");
    let mut repo = real_repo(workspace, ATTEMPT);
    // A directory where the second hunk expects a regular file: validation and
    // journal preparation both admit it, so the batch fails inside `apply_all`.
    fs::create_dir(active_repo.join("src/blocker")).expect("blocker dir");
    fs::write(active_repo.join("src/blocker/keep"), b"keep").expect("blocker child");
    let before = snapshot(&active_repo);

    let error = repo
        .apply_change(
            &good_auth(),
            &[
                PatchHunk::write("src/lib.rs", b"pub fn changed() {}\n".to_vec()),
                PatchHunk::write("src/blocker", b"never".to_vec()),
            ],
        )
        .expect_err("second hunk cannot be applied");
    assert_eq!(error.reason_code(), "IO_FAILED");
    assert!(
        error.to_string().contains("src/blocker"),
        "error must name the exact failed path: {error}"
    );
    assert_eq!(repo.workspace().generation(), 0, "no generation published");
    assert!(
        repo.journal_ops().is_empty(),
        "failed batch reached the journal"
    );
    assert_eq!(
        snapshot(&active_repo),
        before,
        "active generation changed on a failed batch"
    );

    let staging = staging_repo(&active_repo);
    assert_eq!(
        fs::read(staging.join("src/lib.rs")).expect("staged lib"),
        prior_lib,
        "first hunk was not rolled back inside the staging generation"
    );
    assert!(
        staging.join("src/blocker").is_dir(),
        "directory target survived"
    );
    assert_eq!(
        fs::read(staging.join("src/blocker/keep")).expect("kept"),
        b"keep"
    );
}

#[test]
fn git_and_traversal_patch_paths_are_refused_through_apply_change() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let active_repo = workspace.repo_dir().to_path_buf();
    let before = snapshot(&active_repo);
    let mut repo = real_repo(workspace, ATTEMPT);
    for bad in [
        "src/../README.md",
        "src/.git/config",
        ".git/hooks/pre-commit",
        "/src/lib.rs",
        "src\\lib.rs",
    ] {
        let error = repo
            .apply_change(&good_auth(), &[PatchHunk::write(bad, b"x".to_vec())])
            .expect_err("refused");
        assert_eq!(error.reason_code(), "OUT_OF_SCOPE", "{bad:?}");
        assert!(error.to_string().contains(bad), "{bad:?}: {error}");
    }
    assert_eq!(repo.workspace().generation(), 0);
    assert_eq!(snapshot(&active_repo), before);
}

/// The wired call site (`publish_prepared_patches`) composes the apply
/// refusal with a refused rollback. From the public API every apply mutation
/// and its inverse need the same same-uid permission (create/unlink both need
/// directory write+search; overwrite/rewrite both need file write), so a
/// rollback that must fail cannot be forced there without a concurrent swap
/// of the staged tree; the composition is therefore covered directly with a
/// real refused `dirfd` rollback.
#[test]
fn failed_rollback_is_composed_with_the_apply_refusal() {
    let (_temp, root, outside) = hostile_fixture();
    fs::write(root.join("src/a.rs"), b"staged a").expect("staged a");
    let staged = StagedRoot::open(&root).expect("open staged root");
    swap_to_symlink(&root.join("src"), &outside);
    let undo: Vec<(&str, Option<&[u8]>)> = vec![
        ("src/b.rs", None),
        ("src/a.rs", Some(b"prior a".as_slice())),
    ];
    let rollback = staged
        .restore(undo.into_iter())
        .expect_err("rollback refused through swapped symlink");
    let rollback = CapabilityError::Generation(GenerationError::Io(rollback.to_string()));

    let composed =
        CapabilityError::SymlinkForbidden("src/escape.rs".into()).with_failed_rollback(&rollback);
    assert_eq!(composed.reason_code(), "GENERATION_IO_FAILED");
    let message = composed.to_string();
    for needle in [
        "apply refused with SYMLINK_FORBIDDEN",
        "src/escape.rs",
        "rollback refused for 2 path(s)",
        "src/b.rs [SYMLINK_FORBIDDEN",
        "src/a.rs [SYMLINK_FORBIDDEN",
    ] {
        assert!(
            message.contains(needle),
            "{needle:?} missing from {message}"
        );
    }
    assert_ne!(
        composed,
        CapabilityError::SymlinkForbidden("src/escape.rs".into()),
        "a failed rollback must not masquerade as a clean refusal"
    );
}
