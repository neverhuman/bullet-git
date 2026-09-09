//! GC-under-load fault tests (spec §20.2, WI-30): a hostile mirror
//! `git gc --prune=now` — after clone creation, concurrent with clone
//! creation, or concurrent with workspace commits — and even deletion of the
//! mirror never corrupt a private clone, because the Rust reflink-or-bounded-
//! copy path independently materializes every object before creation returns.

mod support;

use bullet_git_types::{GitOid, GitOidAlgorithm};
use bullet_git_workspace::{
    mirror_dir, pin_retained_object, retention_ref_exists, CapabilityError, FileProtocol,
    PrivateClone, RetentionClass, RetentionPin,
};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use support::{clone_workspace, fixture_git, init_source, sha1_oid, try_clone_workspace};

/// Hostile git on the mirror: an operator or cron job that knows nothing
/// about the workspace lock and runs with an ordinary scrubbed environment.
fn hostile_git(home: &Path, repo: &Path, args: &[&str]) -> Result<String, String> {
    let out = Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("PATH"))
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .arg("-C")
        .arg(repo)
        .args(args)
        .output()
        .expect("spawn hostile git");
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&out.stderr).trim().to_string())
    }
}

fn gc_prune_now(home: &Path, mirror: &Path) -> Result<(), String> {
    hostile_git(
        home,
        mirror,
        &["gc", "--prune=now", "--aggressive", "--quiet"],
    )
    .map(|_| ())
}

fn pack_files(mirror: &Path) -> BTreeSet<PathBuf> {
    std::fs::read_dir(mirror.join("objects").join("pack"))
        .expect("mirror pack dir")
        .map(|entry| entry.expect("pack entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "pack"))
        .collect()
}

/// Every reachable object is readable from the clone's own object store,
/// `fsck --strict` is clean, and no alternates file exists.
fn assert_clone_intact(workspace: &PrivateClone, base: &str) {
    let repo = workspace.repo_dir();
    let git = workspace.git();
    assert!(
        !repo.join(".git/objects/info/alternates").exists(),
        "no alternates may survive dissociation"
    );
    git.run(
        Some(repo),
        FileProtocol::Never,
        &["fsck", "--full", "--strict", "--no-dangling"],
        &[],
    )
    .expect("fsck clean");
    let commitish = format!("{}^{{commit}}", &base[5..]);
    git.run(
        Some(repo),
        FileProtocol::Never,
        &["cat-file", "-e", &commitish],
        &[],
    )
    .expect("base commit readable");
    let listing = git
        .run(
            Some(repo),
            FileProtocol::Never,
            &["rev-list", "--objects", "--all"],
            &[],
        )
        .expect("object listing")
        .text();
    let oids: Vec<&str> = listing
        .lines()
        .filter_map(|line| line.split_whitespace().next())
        .collect();
    assert!(oids.len() >= 4, "commit, tree, subtree, blobs: {listing}");
    for oid in &oids {
        git.run(
            Some(repo),
            FileProtocol::Never,
            &["cat-file", "-e", oid],
            &[],
        )
        .unwrap_or_else(|err| panic!("object {oid} readable: {err}"));
    }
    let counts = git
        .run(
            Some(repo),
            FileProtocol::Never,
            &["count-objects", "-v"],
            &[],
        )
        .expect("count-objects")
        .text();
    let local: usize = counts
        .lines()
        .filter(|line| line.starts_with("count: ") || line.starts_with("in-pack: "))
        .map(|line| line.rsplit(' ').next().unwrap().parse::<usize>().unwrap())
        .sum();
    assert!(
        local >= oids.len(),
        "objects live in the clone's own store: {counts}"
    );
}

/// A checkout round-trip to the base and back, then a new commit on the
/// private branch; returns the new head.
fn checkout_and_commit(workspace: &PrivateClone, name: &str) -> String {
    let repo = workspace.repo_dir();
    let git = workspace.git();
    let base = workspace.base_sha()[5..].to_string();
    git.run(
        Some(repo),
        FileProtocol::Never,
        &["checkout", "-q", "--detach", &base],
        &[],
    )
    .expect("checkout base");
    git.run(
        Some(repo),
        FileProtocol::Never,
        &["checkout", "-q", workspace.branch()],
        &[],
    )
    .expect("checkout private branch");
    std::fs::write(
        repo.join("src").join(format!("{name}.rs")),
        format!("pub fn {name}() {{}}\n"),
    )
    .expect("write source");
    git.run(Some(repo), FileProtocol::Never, &["add", "-A"], &[])
        .expect("add");
    let identity: [(&str, OsString); 4] = [
        ("GIT_AUTHOR_NAME", "Fixture".into()),
        ("GIT_AUTHOR_EMAIL", "fixture@test.local".into()),
        ("GIT_COMMITTER_NAME", "Fixture".into()),
        ("GIT_COMMITTER_EMAIL", "fixture@test.local".into()),
    ];
    git.run(
        Some(repo),
        FileProtocol::Never,
        &["commit", "-q", "-m", name],
        &identity,
    )
    .expect("commit");
    git.run(Some(repo), FileProtocol::Never, &["rev-parse", "HEAD"], &[])
        .expect("head")
        .text()
}

fn advance_source(home: &Path, src: &Path, name: &str) -> String {
    std::fs::write(
        src.join("src").join(format!("{name}.rs")),
        format!("pub fn {name}() {{}}\n"),
    )
    .expect("source file");
    let src_str = src.to_string_lossy().into_owned();
    fixture_git(home, &["-C", &src_str, "add", "-A"]);
    fixture_git(
        home,
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
            name,
        ],
    );
    sha1_oid(&fixture_git(home, &["-C", &src_str, "rev-parse", "HEAD"]))
}

/// Clone creation attempts made while the hostile GC loop runs.
const CLONE_ATTEMPTS_UNDER_LOAD: usize = 6;

#[test]
fn mirror_gc_prune_and_deletion_after_clone_never_corrupt_private_clones() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("fixture-home");
    let (src, base_one) = init_source(tmp.path());
    let first = clone_workspace(tmp.path(), &src, &base_one, "atm_gc_after_01");
    let base_two = advance_source(&home, &src, "two");
    let second = clone_workspace(tmp.path(), &src, &base_two, "atm_gc_after_02");
    let mirror = mirror_dir(tmp.path(), &src).expect("mirror dir");

    let packs_before = pack_files(&mirror);
    gc_prune_now(&home, &mirror).expect("hostile gc on the mirror");
    hostile_git(&home, &mirror, &["prune", "--expire=now"]).expect("hostile prune");
    let packs_after = pack_files(&mirror);
    assert_ne!(
        packs_before, packs_after,
        "the GC must rewrite the packs the clones were created from"
    );
    assert_clone_intact(&first, &base_one);
    assert_clone_intact(&second, &base_two);

    std::fs::remove_dir_all(&mirror).expect("delete the mirror outright");
    assert_clone_intact(&first, &base_one);
    assert_clone_intact(&second, &base_two);
    let head_one = checkout_and_commit(&first, "after_gc_one");
    let head_two = checkout_and_commit(&second, "after_gc_two");
    assert_ne!(head_one, head_two);
    assert_clone_intact(&first, &base_one);
    assert_clone_intact(&second, &base_two);
}

#[test]
fn gc_loop_concurrent_with_clone_creation_and_workspace_commits_corrupts_nothing() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("fixture-home");
    let (src, base) = init_source(tmp.path());
    let seed = clone_workspace(tmp.path(), &src, &base, "atm_gc_load_00");
    let mirror = mirror_dir(tmp.path(), &src).expect("mirror dir");

    let stop = Arc::new(AtomicBool::new(false));
    let gc_runs = Arc::new(AtomicUsize::new(0));
    let gc_thread = {
        let (stop, gc_runs, home, mirror) =
            (stop.clone(), gc_runs.clone(), home.clone(), mirror.clone());
        std::thread::spawn(move || {
            let mut failures = Vec::new();
            while !stop.load(Ordering::SeqCst) {
                match gc_prune_now(&home, &mirror) {
                    Ok(()) => {
                        gc_runs.fetch_add(1, Ordering::SeqCst);
                    }
                    Err(err) => failures.push(err),
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            failures
        })
    };

    // Clone creation may legitimately refuse while the mirror is being repacked: a
    // refused clone is fail-closed and harmless. The invariant under test is that
    // nothing is *corrupted*, so attempt several clones, require at least one to be
    // created under load, and assert intactness for every clone that was created.
    let mut clones = vec![seed];
    let mut refused: Vec<CapabilityError> = Vec::new();
    for index in 1..=CLONE_ATTEMPTS_UNDER_LOAD {
        let attempt = format!("atm_gc_load_{index:02}");
        match try_clone_workspace(tmp.path(), &src, &base, &attempt) {
            Ok(workspace) => {
                let previous = clones.last().expect("seed clone");
                checkout_and_commit(previous, &format!("under_load_{index}"));
                clones.push(workspace);
            }
            Err(err) => refused.push(err),
        }
    }
    assert!(
        clones.len() > 1,
        "no clone could be created under hostile GC in {CLONE_ATTEMPTS_UNDER_LOAD} attempts: {refused:?}"
    );
    stop.store(true, Ordering::SeqCst);
    let gc_failures = gc_thread.join().expect("gc thread");
    assert!(
        gc_runs.load(Ordering::SeqCst) >= 1,
        "the hostile GC must have run: failures={gc_failures:?}"
    );
    for workspace in &clones {
        assert_clone_intact(workspace, &base);
        checkout_and_commit(workspace, "after_load");
        assert_clone_intact(workspace, &base);
    }
}

#[test]
fn tombstoned_objects_survive_gc_prune_now() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("fixture-home");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, "atm_gc_tombstone");
    let repo = workspace.repo_dir();
    let git = workspace.git();

    let keep = write_dangling_blob(git, repo, "tombstone-keep.bin", b"tombstone-payload");
    let drop = write_dangling_blob(git, repo, "eligible-drop.bin", b"eligible-payload");
    let pin = RetentionPin {
        oid: GitOid::from_hex(GitOidAlgorithm::Sha1, keep.clone()).expect("oid"),
        class: RetentionClass::Tombstoned,
    };
    assert!(!RetentionClass::Tombstoned.may_prune());
    assert!(RetentionClass::Eligible.may_prune());
    pin_retained_object(git, repo, &pin).expect("pin tombstone");
    assert!(retention_ref_exists(git, repo, &pin).expect("retain ref"));
    assert_eq!(
        pin_retained_object(
            git,
            repo,
            &RetentionPin {
                oid: GitOid::from_hex(GitOidAlgorithm::Sha1, drop.clone()).expect("oid"),
                class: RetentionClass::Eligible,
            },
        )
        .expect_err("eligible")
        .reason_code(),
        "IO_FAILED"
    );

    gc_prune_now(&home, repo).expect("hostile gc on the private clone");

    git.run(
        Some(repo),
        FileProtocol::Never,
        &["cat-file", "-e", &keep],
        &[],
    )
    .expect("tombstoned object must survive prune");
    assert!(
        !git.probe(Some(repo), &["cat-file", "-e", &drop])
            .expect("probe eligible"),
        "unpinned dangling object should be pruned"
    );
}

#[test]
fn live_workspace_objects_survive_gc_prune_now() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let home = tmp.path().join("fixture-home");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, "atm_gc_live");
    let repo = workspace.repo_dir();
    let git = workspace.git();

    let keep = write_dangling_blob(git, repo, "live-keep.bin", b"live-workspace-payload");
    let drop = write_dangling_blob(git, repo, "eligible-drop.bin", b"eligible-payload");
    let pin = RetentionPin {
        oid: GitOid::from_hex(GitOidAlgorithm::Sha1, keep.clone()).expect("oid"),
        class: RetentionClass::LiveWorkspace,
    };
    assert!(!RetentionClass::LiveWorkspace.may_prune());
    assert_eq!(
        RetentionClass::LiveWorkspace.retain_namespace(),
        Some("refs/bullet/retain/live")
    );
    pin_retained_object(git, repo, &pin).expect("pin live workspace");
    assert!(retention_ref_exists(git, repo, &pin).expect("retain ref"));

    gc_prune_now(&home, repo).expect("hostile gc on the private clone");

    git.run(
        Some(repo),
        FileProtocol::Never,
        &["cat-file", "-e", &keep],
        &[],
    )
    .expect("live-workspace object must survive prune");
    assert!(
        !git.probe(Some(repo), &["cat-file", "-e", &drop])
            .expect("probe eligible"),
        "unpinned dangling object should be pruned"
    );
}

fn write_dangling_blob(
    git: &bullet_git_workspace::SafeGit,
    repo: &Path,
    name: &str,
    bytes: &[u8],
) -> String {
    let path = repo.join(name);
    std::fs::write(&path, bytes).expect("blob file");
    let hex = git
        .run(
            Some(repo),
            FileProtocol::Never,
            &["hash-object", "-w", name],
            &[],
        )
        .expect("hash-object")
        .text();
    std::fs::remove_file(&path).expect("unlink working-tree copy");
    hex
}
