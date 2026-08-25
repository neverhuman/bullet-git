//! Real-repository fixtures shared by the integration tests.
#![allow(dead_code)]

use bullet_git_types::AuthorityEnvelope;
use bullet_git_workspace::{
    CapabilityError, CloneRequest, CommitIdentity, ExpectedAuthority, PrivateClone, RealRepository,
    ScopeGrant,
};
use std::path::{Path, PathBuf};
use std::process::Command;

pub const NONCE: [u8; 32] = [9u8; 32];
pub const ATTEMPT: &str = "atm_1111111111111111111111111111111111111111111111111111111111111111";
pub const VARIANT: &str = "var_2222222222222222222222222222222222222222222222222222222222222222";
pub const FENCE: u64 = 5;
pub const CREATED_AT: &str = "2026-08-24T00:00:00Z";
pub const COMMIT_DATE: &str = "2026-08-24T00:00:00+00:00";

/// Run git for fixture setup with a scrubbed environment. Commit dates are
/// pinned so identical fixture content yields identical SHAs in every test
/// process.
pub fn fixture_git(home: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .env_clear()
        .env("PATH", std::env::var_os("PATH").expect("PATH"))
        .env("HOME", home)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_AUTHOR_DATE", "2026-08-20T00:00:00+00:00")
        .env("GIT_COMMITTER_DATE", "2026-08-20T00:00:00+00:00")
        .args(args)
        .output()
        .expect("spawn fixture git");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Tag native SHA-1 fixture output as a canonical cross-boundary Git OID.
pub fn sha1_oid(hex: &str) -> String {
    format!("sha1:{hex}")
}

/// Create a source repository with one commit. Returns (path, tagged base OID).
pub fn init_source(root: &Path) -> (PathBuf, String) {
    let home = root.join("fixture-home");
    std::fs::create_dir_all(&home).expect("fixture home");
    let src = root.join("source");
    std::fs::create_dir_all(&src).expect("source dir");
    let src_str = src.to_string_lossy().into_owned();
    fixture_git(&home, &["init", "-q", "-b", "main", &src_str]);
    std::fs::write(src.join("README.md"), "seed\n").expect("seed readme");
    std::fs::create_dir_all(src.join("src")).expect("src dir");
    std::fs::write(src.join("src").join("lib.rs"), "pub fn seed() {}\n").expect("seed lib");
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
            "init",
        ],
    );
    let base = sha1_oid(&fixture_git(&home, &["-C", &src_str, "rev-parse", "HEAD"]));
    (src, base)
}

/// Authority envelope with the kernel token shape (extra fields included).
pub fn envelope(attempt: &str, fence: u64, nonce: [u8; 32]) -> AuthorityEnvelope {
    AuthorityEnvelope {
        token: serde_json::to_vec(&serde_json::json!({
            "organization_id": "org_fixture",
            "variant_id": VARIANT,
            "attempt_id": attempt,
            "attempt_fence": fence,
            "workspace_nonce": nonce.to_vec(),
            "runner_epoch": 1,
            "scope_revision": 1,
        }))
        .expect("token json"),
    }
}

/// The envelope matching the fixture's expected authority.
pub fn good_auth() -> AuthorityEnvelope {
    envelope(ATTEMPT, FENCE, NONCE)
}

/// Clone a private workspace for the given attempt id.
/// Create a private clone, returning the capability error instead of panicking.
///
/// Clone creation is allowed to fail while the mirror is being repacked: a refused
/// clone is fail-closed and safe. Only a clone that *succeeds* is required to be
/// intact, so the hostile-GC tests use this variant and assert on the successes.
pub fn try_clone_workspace(
    root: &Path,
    src: &Path,
    base: &str,
    attempt: &str,
) -> Result<PrivateClone, CapabilityError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
            .expect("private workspace root");
    }
    PrivateClone::create(&CloneRequest {
        source_repo: src,
        base_sha: base,
        variant_id: VARIANT,
        attempt_id: attempt,
        root,
        created_at: CREATED_AT,
        nonce: NONCE,
    })
}

pub fn clone_workspace(root: &Path, src: &Path, base: &str, attempt: &str) -> PrivateClone {
    try_clone_workspace(root, src, base, attempt).expect("private clone")
}

/// Bind a workspace to the fixture grant (src + docs) and fixed identity.
pub fn real_repo(workspace: PrivateClone, attempt: &str) -> RealRepository {
    RealRepository::new(
        workspace,
        ScopeGrant::new(&["src".into(), "docs".into()]).expect("grant"),
        ExpectedAuthority {
            attempt_id: attempt.into(),
            attempt_fence: FENCE,
            workspace_nonce: NONCE,
        },
        CommitIdentity::farm(COMMIT_DATE),
    )
    .expect("open durable repository journal")
}
