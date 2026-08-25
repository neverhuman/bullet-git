//! Mirror-under-lock guarantees: layout, freshness, dissociation, concurrency.

mod support;

use bullet_git_workspace::{mirror_dir, CopyMode, MirrorLock};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use support::{clone_workspace, fixture_git, init_source, sha1_oid, try_clone_workspace};

fn lock_file_for(mirror: &Path) -> PathBuf {
    let name = mirror.file_name().expect("mirror name").to_string_lossy();
    mirror.with_file_name(format!("{name}.lock"))
}

#[test]
fn clone_goes_through_a_dissociated_mirror() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, "atm_mirror01");
    let mirror = mirror_dir(tmp.path(), &src).expect("mirror dir");
    assert!(mirror.join("HEAD").is_file(), "bare mirror created");
    assert!(!lock_file_for(&mirror).exists(), "lock released");
    assert!(
        !workspace
            .repo_dir()
            .join(".git/objects/info/alternates")
            .exists(),
        "no alternates file may survive materialization"
    );
    assert!(matches!(
        workspace.manifest().object_materialization,
        CopyMode::Reflink | CopyMode::Fallback
    ));
    let remotes = workspace
        .git()
        .run(
            Some(workspace.repo_dir()),
            bullet_git_workspace::FileProtocol::Never,
            &["remote"],
            &[],
        )
        .expect("list remotes")
        .text();
    assert!(remotes.is_empty(), "materialization creates no remote");
    assert_eq!(workspace.base_sha(), base);
    assert_eq!(
        workspace.manifest().mirror_dir,
        mirror.to_string_lossy(),
        "manifest records the mirror"
    );

    let source_objects = src.join(".git").join("objects");
    std::fs::write(
        mirror.join("objects").join("info").join("alternates"),
        format!("{}\n", source_objects.display()),
    )
    .expect("plant valid mirror alternates dependency");
    let error = try_clone_workspace(tmp.path(), &src, &base, "atm_mirror_alternates")
        .expect_err("alternate-backed mirror must be refused");
    assert_eq!(error.reason_code(), "GIT_FAILED");
}

#[test]
fn second_clone_fetches_new_commits_under_the_lock() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base_one) = init_source(tmp.path());
    let first = clone_workspace(tmp.path(), &src, &base_one, "atm_mirror02");
    assert_eq!(first.base_sha(), base_one);
    let home = tmp.path().join("fixture-home");
    std::fs::write(src.join("src").join("two.rs"), "pub fn two() {}\n").expect("second file");
    let src_str = src.to_string_lossy().into_owned();
    fixture_git(&home, &["-C", &src_str, "add", "-A"]);
    fixture_git(
        &home,
        &[
            "-C",
            &src_str,
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@test.local",
            "commit",
            "-q",
            "-m",
            "two",
        ],
    );
    let base_two = sha1_oid(&fixture_git(&home, &["-C", &src_str, "rev-parse", "HEAD"]));
    assert_ne!(base_one, base_two);
    let second = clone_workspace(tmp.path(), &src, &base_two, "atm_mirror03");
    assert_eq!(second.base_sha(), base_two);
    assert!(
        second.repo_dir().join("src/two.rs").exists(),
        "fetched commit checked out"
    );
}

#[test]
fn stale_lock_from_a_dead_holder_is_broken() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let mirror = mirror_dir(tmp.path(), &src).expect("mirror dir");
    std::fs::create_dir_all(mirror.parent().expect("mirrors dir")).expect("mkdir");
    std::fs::write(lock_file_for(&mirror), "4294000000").expect("dead-holder lock");
    let workspace = clone_workspace(tmp.path(), &src, &base, "atm_mirror04");
    assert_eq!(workspace.base_sha(), base);
    assert!(!lock_file_for(&mirror).exists(), "lock released");
}

#[test]
fn held_lock_blocks_a_clone_until_released() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let mirror = mirror_dir(tmp.path(), &src).expect("mirror dir");
    let lock = MirrorLock::acquire(&mirror, Duration::from_secs(5)).expect("hold");
    let done = Arc::new(AtomicBool::new(false));
    let done_flag = done.clone();
    let (root, source, sha) = (tmp.path().to_path_buf(), src.clone(), base.clone());
    let worker = std::thread::spawn(move || {
        let workspace = clone_workspace(&root, &source, &sha, "atm_mirror05");
        done_flag.store(true, Ordering::SeqCst);
        workspace.base_sha().to_string()
    });
    std::thread::sleep(Duration::from_millis(400));
    assert!(!done.load(Ordering::SeqCst), "clone must wait for the lock");
    drop(lock);
    let sha_seen = worker.join().expect("worker");
    assert!(done.load(Ordering::SeqCst));
    assert_eq!(sha_seen, base);
}

#[test]
fn concurrent_clones_of_one_source_both_succeed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let mut workers = Vec::new();
    for attempt in ["atm_mirror06", "atm_mirror07"] {
        let (root, source, sha) = (tmp.path().to_path_buf(), src.clone(), base.clone());
        workers.push(std::thread::spawn(move || {
            let workspace = clone_workspace(&root, &source, &sha, attempt);
            assert!(
                !workspace
                    .repo_dir()
                    .join(".git/objects/info/alternates")
                    .exists(),
                "no alternates under concurrency"
            );
            workspace.base_sha().to_string()
        }));
    }
    for worker in workers {
        assert_eq!(worker.join().expect("clone thread"), base);
    }
    let mirror = mirror_dir(tmp.path(), &src).expect("mirror dir");
    assert!(mirror.join("HEAD").is_file(), "one shared mirror");
    assert!(!lock_file_for(&mirror).exists(), "lock released");
}
