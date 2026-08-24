//! Private clone creation guarantees and receipt-gated cleanup.

mod support;

use bullet_git_workspace::{CloneRequest, FileProtocol, PreservationReceipt, PrivateClone};
use support::{clone_workspace, init_source, ATTEMPT, CREATED_AT, NONCE, VARIANT};

#[test]
fn clone_has_no_remote_and_manifest_lives_outside_the_tree() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let remotes = workspace
        .git()
        .run(
            Some(workspace.repo_dir()),
            FileProtocol::Never,
            &["remote"],
            &[],
        )
        .expect("remotes")
        .text();
    assert!(remotes.is_empty(), "no remote may survive clone: {remotes}");
    assert_eq!(workspace.branch(), format!("bullet/{VARIANT}/{ATTEMPT}"));
    assert_eq!(workspace.base_sha(), base);
    let manifest_path = workspace.runtime_dir().join("manifest.json");
    assert!(manifest_path.is_file(), "manifest in the runtime dir");
    assert!(
        !workspace.repo_dir().join("manifest.json").exists(),
        "manifest never lands inside the repo tree"
    );
    let manifest = workspace.manifest();
    assert_eq!(manifest.nonce_hex, hex::encode(NONCE));
    assert_eq!(manifest.created_at, CREATED_AT);
}

#[test]
fn missing_or_invalid_base_sha_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, _base) = init_source(tmp.path());
    let absent = "0123456789abcdef0123456789abcdef01234567";
    let err = PrivateClone::create(&CloneRequest {
        source_repo: &src,
        base_sha: absent,
        variant_id: VARIANT,
        attempt_id: ATTEMPT,
        root: tmp.path(),
        created_at: CREATED_AT,
        nonce: NONCE,
    })
    .expect_err("absent base");
    assert_eq!(err.reason_code(), "BASE_MISSING");
    let err = PrivateClone::create(&CloneRequest {
        source_repo: &src,
        base_sha: "not-a-sha",
        variant_id: VARIANT,
        attempt_id: ATTEMPT,
        root: tmp.path(),
        created_at: CREATED_AT,
        nonce: NONCE,
    })
    .expect_err("malformed base");
    assert_eq!(err.reason_code(), "INVALID_TYPES");
}

#[test]
fn cleanup_refuses_wrong_nonce() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let bundle = tmp.path().join("preserve.bundle");
    let receipt = workspace.preserve(&bundle).expect("receipt");
    let err = workspace
        .cleanup(&[0u8; 32], &receipt, CREATED_AT)
        .expect_err("wrong nonce");
    assert_eq!(err.reason_code(), "CLEANUP_NONCE_MISMATCH");
}

#[test]
fn cleanup_refuses_unverified_or_missing_receipt() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let fake = PreservationReceipt {
        bundle_path: tmp.path().join("never-written.bundle"),
        verified: false,
    };
    let err = workspace
        .cleanup(&NONCE, &fake, CREATED_AT)
        .expect_err("no receipt");
    assert_eq!(err.reason_code(), "CLEANUP_RECEIPT_REQUIRED");
}

#[test]
fn cleanup_with_verified_receipt_deletes_and_writes_tombstone() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    let repo_dir = workspace.repo_dir().to_path_buf();
    let runtime_dir = workspace.runtime_dir().to_path_buf();
    let bundle = tmp.path().join("preserve.bundle");
    let receipt = workspace.preserve(&bundle).expect("receipt");
    assert!(receipt.verified);
    assert!(bundle.is_file(), "bundle receipt written");
    let tombstone = workspace
        .cleanup(&NONCE, &receipt, "2026-08-24T01:00:00Z")
        .expect("cleanup");
    assert!(!repo_dir.exists(), "workspace deleted");
    assert!(tombstone.is_file(), "tombstone written");
    assert!(tombstone.starts_with(&runtime_dir));
    let text = std::fs::read_to_string(&tombstone).expect("tombstone json");
    assert!(text.contains(&hex::encode(NONCE)));
}
