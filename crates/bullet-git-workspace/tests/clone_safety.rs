//! Private clone creation guarantees and receipt-gated cleanup.

mod support;

use bullet_git_workspace::{CloneRequest, CopyMode, FileProtocol, PrivateClone, WorkspaceManifest};
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
    assert!(matches!(
        manifest.object_materialization,
        CopyMode::Reflink | CopyMode::Fallback
    ));

    let manifest_json = std::fs::read(manifest_path).expect("manifest bytes");
    let mut legacy: serde_json::Value = serde_json::from_slice(&manifest_json).expect("json");
    legacy["base_sha"] = serde_json::Value::String(base[5..].to_string());
    assert!(serde_json::from_value::<WorkspaceManifest>(legacy).is_err());
    let mut incomplete: serde_json::Value = serde_json::from_slice(&manifest_json).expect("json");
    incomplete
        .as_object_mut()
        .expect("manifest object")
        .remove("object_materialization");
    assert!(serde_json::from_value::<WorkspaceManifest>(incomplete).is_err());
    let mut unknown: serde_json::Value = serde_json::from_slice(&manifest_json).expect("json");
    unknown["unexpected"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<WorkspaceManifest>(unknown).is_err());
}

#[test]
fn missing_or_invalid_base_sha_fails_closed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, _base) = init_source(tmp.path());
    let absent = "sha1:0123456789abcdef0123456789abcdef01234567";
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
    for malformed in ["not-a-sha", &absent[5..], "sha1:ABCDEF"] {
        let err = PrivateClone::create(&CloneRequest {
            source_repo: &src,
            base_sha: malformed,
            variant_id: VARIANT,
            attempt_id: ATTEMPT,
            root: tmp.path(),
            created_at: CREATED_AT,
            nonce: NONCE,
        })
        .expect_err("malformed base");
        assert_eq!(err.reason_code(), "INVALID_TYPES");
    }
}
