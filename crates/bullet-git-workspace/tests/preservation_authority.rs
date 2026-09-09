//! Sealed preservation receipts are the sole authority for exact cleanup.

mod support;

use bullet_git_workspace::{AgentRepository, PatchHunk, PreservationAuthority, RealRepository};
use std::fs;
use std::path::{Path, PathBuf};
use support::{
    clone_workspace, envelope, good_auth, init_source, real_repo, ATTEMPT, CREATED_AT, FENCE, NONCE,
};

struct Fixture {
    _tmp: tempfile::TempDir,
    repo: RealRepository,
    authority: PreservationAuthority,
    destination: PathBuf,
    work_dir: PathBuf,
    runtime_dir: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().expect("tempdir");
        let (source, base) = init_source(tmp.path());
        let workspace = clone_workspace(tmp.path(), &source, &base, ATTEMPT);
        let mut repo = real_repo(workspace, ATTEMPT);
        repo.apply_change(
            &good_auth(),
            &[
                PatchHunk::write("src/lib.rs", b"pub fn preserved() {}\n".to_vec()),
                PatchHunk::write("src/untracked.rs", b"pub fn untracked() {}\n".to_vec()),
            ],
        )
        .expect("uncommitted changes");
        let runtime_dir = repo.workspace().runtime_dir().to_path_buf();
        let work_dir = attempt_work_dir(repo.workspace().repo_dir());
        let authority = PreservationAuthority::open(&runtime_dir).expect("seal authority");
        let destination = tmp.path().join("external-preservation");
        Self {
            _tmp: tmp,
            repo,
            authority,
            destination,
            work_dir,
            runtime_dir,
        }
    }

    fn issue(&self) -> bullet_git_workspace::PreservationReceipt {
        self.authority
            .issue(&self.repo, &good_auth(), &self.destination)
            .expect("issue preservation")
    }

    fn assert_workspace_retained(&self) {
        assert!(
            self.work_dir.is_dir(),
            "refusal must retain exact cleanup target"
        );
        assert!(
            self.repo.workspace().repo_dir().is_dir(),
            "refusal must retain active repository"
        );
    }
}

fn attempt_work_dir(repo_dir: &Path) -> PathBuf {
    repo_dir
        .ancestors()
        .nth(3)
        .expect("repo/generation/generations/attempt")
        .to_path_buf()
}

fn assert_refused(fixture: &mut Fixture, token: &str) {
    let error = fixture
        .authority
        .cleanup(&mut fixture.repo, &good_auth(), token, CREATED_AT)
        .expect_err("cleanup authorization must refuse");
    assert_eq!(error.reason_code(), "PRESERVATION_RECEIPT_REFUSED");
    fixture.assert_workspace_retained();
}

#[test]
fn sealed_receipt_preserves_salvage_state_before_exact_cleanup() {
    let mut fixture = Fixture::new();
    let receipt = fixture.issue();
    assert!(
        receipt.token().len() < 16 * 1024,
        "receipt stays frame-safe"
    );
    assert!(fixture
        .runtime_dir
        .join("preservation-seal-v1.key")
        .is_file());
    assert!(
        !fixture
            .repo
            .workspace()
            .repo_dir()
            .join("preservation-seal-v1.key")
            .exists(),
        "seal must be unavailable inside the provider-visible repository"
    );
    assert_eq!(
        receipt.destination(),
        fixture.destination.canonicalize().unwrap()
    );
    assert!(receipt.destination().join("cas").is_dir());
    assert!(receipt.destination().join("generation/journal").is_dir());
    assert!(receipt.destination().join("repository.bundle").is_file());
    assert_eq!(
        fs::read_to_string(receipt.destination().join("generation/repo/src/lib.rs")).unwrap(),
        "pub fn preserved() {}\n"
    );
    assert_eq!(
        fs::read_to_string(
            receipt
                .destination()
                .join("generation/repo/src/untracked.rs")
        )
        .unwrap(),
        "pub fn untracked() {}\n"
    );
    let subject: serde_json::Value = serde_json::from_slice(
        &fs::read(receipt.destination().join("subject.json")).expect("subject"),
    )
    .expect("subject json");
    assert_eq!(subject["attempt_id"], ATTEMPT);
    assert_eq!(subject["attempt_fence"], FENCE);
    assert_eq!(subject["workspace_nonce_hex"], hex::encode(NONCE));
    assert!(subject["generation"].as_u64().is_some());
    assert!(subject["git_tree"].as_str().is_some());
    assert!(subject["journal_end"].as_u64().unwrap() >= 2);
    assert!(subject["journal_root"].as_str().is_some());
    let paths = subject["dirty_untracked"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["path"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert!(paths.contains(&"src/lib.rs"));
    assert!(paths.contains(&"src/untracked.rs"));

    let reopened = PreservationAuthority::open(&fixture.runtime_dir).expect("reopen seal");
    let destination = receipt.destination().to_path_buf();
    assert_ne!(receipt.artifact_digest().to_hex(), "0".repeat(64));
    let receipt_digest = receipt.receipt_digest();
    let work_dir = fixture.work_dir.clone();
    let runtime_dir = fixture.runtime_dir.clone();
    let tombstone = reopened
        .cleanup(&mut fixture.repo, &good_auth(), receipt.token(), CREATED_AT)
        .expect("exact cleanup");
    assert!(!work_dir.exists(), "only the exact work target is deleted");
    assert!(
        runtime_dir.is_dir(),
        "daemon runtime and seal survive cleanup"
    );
    assert!(
        destination.is_dir(),
        "external preservation survives cleanup"
    );
    let tombstone_json: serde_json::Value =
        serde_json::from_slice(&fs::read(tombstone).expect("durable tombstone"))
            .expect("tombstone json");
    assert_eq!(tombstone_json["schema_version"], 1);
    assert_eq!(
        tombstone_json["preservation_receipt_digest"],
        receipt_digest.to_hex()
    );
    assert_eq!(
        tombstone_json["preservation_artifact_digest"],
        receipt.artifact_digest().to_hex()
    );
    assert_eq!(
        tombstone_json["preservation_destination"],
        destination.to_string_lossy().as_ref()
    );
}

#[test]
fn post_delete_tombstone_failure_is_unknown_and_preservation_survives() {
    let mut fixture = Fixture::new();
    let receipt = fixture.issue();
    let destination = receipt.destination().to_path_buf();
    fs::create_dir(fixture.runtime_dir.join("tombstone.json"))
        .expect("hostile pre-existing tombstone entry");

    let error = fixture
        .authority
        .cleanup(&mut fixture.repo, &good_auth(), receipt.token(), CREATED_AT)
        .expect_err("post-delete persistence failure is indeterminate");

    assert_eq!(error.reason_code(), "PRESERVATION_OUTCOME_UNKNOWN");
    assert!(
        !fixture.work_dir.exists(),
        "the failure happened after destructive cleanup"
    );
    assert!(destination.is_dir(), "salvage remains external and durable");
    assert!(destination.join("repository.bundle").is_file());
}

#[cfg(unix)]
#[test]
fn post_delete_tombstone_symlink_is_not_followed_or_truncated() {
    use std::os::unix::fs::symlink;

    let mut fixture = Fixture::new();
    let receipt = fixture.issue();
    let target = fixture._tmp.path().join("external-tombstone-target");
    fs::write(&target, b"sentinel").expect("external sentinel");
    symlink(&target, fixture.runtime_dir.join("tombstone.json"))
        .expect("hostile tombstone symlink");

    let error = fixture
        .authority
        .cleanup(&mut fixture.repo, &good_auth(), receipt.token(), CREATED_AT)
        .expect_err("post-delete symlink is indeterminate");

    assert_eq!(error.reason_code(), "PRESERVATION_OUTCOME_UNKNOWN");
    assert!(!fixture.work_dir.exists());
    assert_eq!(fs::read(target).expect("sentinel survives"), b"sentinel");
    assert!(receipt.destination().join("repository.bundle").is_file());
}

#[test]
fn forged_stale_or_mutated_subject_receipts_never_clean() {
    let mut fixture = Fixture::new();
    let receipt = fixture.issue();
    let mut forged = receipt.token().as_bytes().to_vec();
    let changed_index = forged.len() / 2;
    forged[changed_index] = if forged[changed_index] == b'a' {
        b'b'
    } else {
        b'a'
    };
    assert_refused(&mut fixture, std::str::from_utf8(&forged).unwrap());
    assert_refused(&mut fixture, &receipt.token().to_ascii_uppercase());

    for auth in [
        envelope(ATTEMPT, FENCE + 1, NONCE),
        envelope(ATTEMPT, FENCE, [8; 32]),
    ] {
        let error = fixture
            .authority
            .cleanup(&mut fixture.repo, &auth, receipt.token(), CREATED_AT)
            .expect_err("stale authority");
        assert_eq!(error.reason_code(), "STALE_AUTHORITY");
        fixture.assert_workspace_retained();
    }

    let mut fixture = Fixture::new();
    let receipt = fixture.issue();
    fixture
        .repo
        .apply_change(
            &good_auth(),
            &[PatchHunk::write("src/lib.rs", b"mutated\n".to_vec())],
        )
        .expect("new generation");
    assert_refused(&mut fixture, receipt.token());

    let mut fixture = Fixture::new();
    let receipt = fixture.issue();
    fs::write(
        fixture.repo.workspace().journal_dir().join("post-receipt"),
        b"journal mutation",
    )
    .expect("mutate journal");
    assert_refused(&mut fixture, receipt.token());
}

#[test]
fn artifact_or_destination_mutation_never_cleans() {
    let mut fixture = Fixture::new();
    let receipt = fixture.issue();
    fs::write(
        receipt.destination().join("generation/repo/src/lib.rs"),
        b"tampered\n",
    )
    .expect("tamper artifact");
    assert_refused(&mut fixture, receipt.token());

    let mut fixture = Fixture::new();
    let receipt = fixture.issue();
    fs::remove_file(receipt.destination().join("repository.bundle")).expect("remove bundle");
    assert!(!receipt.destination().join("repository.bundle").exists());
    assert_refused(&mut fixture, receipt.token());
    assert!(
        !receipt.destination().join("repository.bundle").exists(),
        "verification must never recreate missing preservation bytes"
    );

    let mut fixture = Fixture::new();
    let receipt = fixture.issue();
    let moved = fixture._tmp.path().join("moved-preservation");
    fs::rename(receipt.destination(), &moved).expect("remove named destination");
    assert_refused(&mut fixture, receipt.token());

    let mut fixture = Fixture::new();
    let receipt = fixture.issue();
    let moved = fixture._tmp.path().join("original-preservation");
    fs::rename(receipt.destination(), &moved).expect("move original destination");
    fs::create_dir(receipt.destination()).expect("replacement destination");
    assert_refused(&mut fixture, receipt.token());
}

#[test]
fn destination_must_be_new_external_and_not_a_symlink() {
    let fixture = Fixture::new();
    let inside = fixture.runtime_dir.join("inside-preservation");
    let error = fixture
        .authority
        .issue(&fixture.repo, &good_auth(), &inside)
        .expect_err("runtime overlap");
    assert_eq!(error.reason_code(), "PRESERVATION_INVALID_DESTINATION");
    fixture.assert_workspace_retained();

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;
        let target = fixture._tmp.path().join("symlink-target");
        fs::create_dir(&target).expect("target");
        symlink(&target, &fixture.destination).expect("destination symlink");
        let error = fixture
            .authority
            .issue(&fixture.repo, &good_auth(), &fixture.destination)
            .expect_err("symlink destination");
        assert_eq!(error.reason_code(), "PRESERVATION_INVALID_DESTINATION");
        fixture.assert_workspace_retained();
    }
}
