//! Private clone creation (spec §20.2) and receipt-gated cleanup (spec §20.8).

use crate::safe_git::{FileProtocol, HeadState, SafeGit};
use crate::{io_err, CapabilityError};
use bullet_git_types::GitOid;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// Inputs for private clone creation. Clock and nonce come from the caller so
/// the workspace layer stays deterministic and testable.
#[derive(Debug)]
pub struct CloneRequest<'a> {
    /// Source repository (the mirror). Never contacted again after creation.
    pub source_repo: &'a Path,
    /// Exact base commit to check out.
    pub base_sha: &'a str,
    /// Variant that owns the writer lease.
    pub variant_id: &'a str,
    /// Attempt incarnation.
    pub attempt_id: &'a str,
    /// Root under which `work/` and `runtime/` live.
    pub root: &'a Path,
    /// RFC 3339 creation timestamp from the caller's clock.
    pub created_at: &'a str,
    /// Caller-supplied 32-byte workspace nonce.
    pub nonce: [u8; 32],
}

/// Manifest recorded outside the repository tree at creation time.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceManifest {
    /// Attempt incarnation.
    pub attempt_id: String,
    /// Variant that owns the writer lease.
    pub variant_id: String,
    /// Exact base commit.
    pub base_sha: String,
    /// Private branch `bullet/<variant_id>/<attempt_id>`.
    pub branch: String,
    /// RFC 3339 creation timestamp from the caller's clock.
    pub created_at: String,
    /// Hex of the 32-byte workspace nonce.
    pub nonce_hex: String,
    /// Source repository path at creation time.
    pub source_repo: String,
    /// Private clone path.
    pub repo_dir: String,
}

/// Verified preservation receipt required before cleanup.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreservationReceipt {
    /// Bundle file written by `git bundle create`.
    pub bundle_path: PathBuf,
    /// Whether `git bundle verify` succeeded.
    pub verified: bool,
}

/// A private writable clone with no remote and no credential path.
#[derive(Debug)]
pub struct PrivateClone {
    repo_dir: PathBuf,
    runtime_dir: PathBuf,
    manifest: WorkspaceManifest,
    nonce: [u8; 32],
    git: SafeGit,
}

impl PrivateClone {
    /// Create a private clone per spec §20.2.
    ///
    /// Verify base exists → clone without checkout → remove the origin remote
    /// (no remote survives: that is the no-credential/no-push guarantee) →
    /// detached checkout of the exact base → create the private branch →
    /// record the manifest in the runtime dir, never inside the repo tree.
    ///
    /// # Errors
    ///
    /// Fails closed with `BASE_MISSING`, `WORKTREE_FORBIDDEN`,
    /// `WRONG_REPOSITORY`, `GIT_FAILED`, or `IO_FAILED`.
    pub fn create(req: &CloneRequest<'_>) -> Result<Self, CapabilityError> {
        let base = GitOid::new(req.base_sha)?;
        let runtime_dir = req.root.join("runtime").join(req.attempt_id);
        fs::create_dir_all(&runtime_dir).map_err(|err| io_err("create runtime dir", &err))?;
        let git = SafeGit::new(&runtime_dir)?;
        let commitish = format!("{base}^{{commit}}");
        let base_exists = git.probe(
            Some(req.source_repo),
            &["rev-parse", "--verify", "--quiet", &commitish],
        )?;
        if !base_exists {
            return Err(CapabilityError::BaseMissing(base.as_str().to_string()));
        }
        let repo_dir = req.root.join("work").join(req.attempt_id).join("repo");
        fs::create_dir_all(repo_dir.parent().unwrap_or(&repo_dir))
            .map_err(|err| io_err("create work dir", &err))?;
        let source = req.source_repo.to_string_lossy().into_owned();
        let dest = repo_dir.to_string_lossy().into_owned();
        git.run(
            None,
            FileProtocol::User,
            &["clone", "--no-checkout", &source, &dest],
            &[],
        )?;
        git.run(
            Some(&repo_dir),
            FileProtocol::Never,
            &["remote", "remove", "origin"],
            &[],
        )?;
        guard_repository(&git, &repo_dir)?;
        let branch = format!("bullet/{}/{}", req.variant_id, req.attempt_id);
        checkout_private_branch(&git, &repo_dir, &base, &branch)?;
        let manifest = WorkspaceManifest {
            attempt_id: req.attempt_id.to_string(),
            variant_id: req.variant_id.to_string(),
            base_sha: base.as_str().to_string(),
            branch,
            created_at: req.created_at.to_string(),
            nonce_hex: hex::encode(req.nonce),
            source_repo: source,
            repo_dir: dest,
        };
        let manifest_json = serde_json::to_vec_pretty(&manifest)
            .map_err(|err| CapabilityError::Io(format!("encode manifest: {err}")))?;
        fs::write(runtime_dir.join("manifest.json"), manifest_json)
            .map_err(|err| io_err("write manifest", &err))?;
        Ok(Self {
            repo_dir,
            runtime_dir,
            manifest,
            nonce: req.nonce,
            git,
        })
    }

    /// The private clone directory.
    #[must_use]
    pub fn repo_dir(&self) -> &Path {
        &self.repo_dir
    }

    /// The per-workspace runtime directory (manifest, isolation dirs).
    #[must_use]
    pub fn runtime_dir(&self) -> &Path {
        &self.runtime_dir
    }

    /// The private branch name.
    #[must_use]
    pub fn branch(&self) -> &str {
        &self.manifest.branch
    }

    /// The exact base commit.
    #[must_use]
    pub fn base_sha(&self) -> &str {
        &self.manifest.base_sha
    }

    /// The recorded manifest.
    #[must_use]
    pub fn manifest(&self) -> &WorkspaceManifest {
        &self.manifest
    }

    /// The hardened git builder for this workspace.
    #[must_use]
    pub fn git(&self) -> &SafeGit {
        &self.git
    }

    /// Write and verify a preservation bundle for cleanup.
    ///
    /// # Errors
    ///
    /// Returns `GIT_FAILED` when the bundle cannot be created or verified.
    pub fn preserve(&self, bundle_path: &Path) -> Result<PreservationReceipt, CapabilityError> {
        let bundle = bundle_path.to_string_lossy().into_owned();
        self.git.run(
            Some(&self.repo_dir),
            FileProtocol::Never,
            &["bundle", "create", &bundle, "--all"],
            &[],
        )?;
        self.git.run(
            Some(&self.repo_dir),
            FileProtocol::Never,
            &["bundle", "verify", &bundle],
            &[],
        )?;
        Ok(PreservationReceipt {
            bundle_path: bundle_path.to_path_buf(),
            verified: true,
        })
    }

    /// Delete the workspace. Refuses without a nonce match and a verified
    /// preservation receipt; writes a tombstone JSON and returns its path.
    ///
    /// # Errors
    ///
    /// Returns `CLEANUP_NONCE_MISMATCH` or `CLEANUP_RECEIPT_REQUIRED` when the
    /// preconditions fail, `IO_FAILED` when deletion fails.
    pub fn cleanup(
        self,
        nonce: &[u8; 32],
        receipt: &PreservationReceipt,
        deleted_at: &str,
    ) -> Result<PathBuf, CapabilityError> {
        if nonce != &self.nonce {
            return Err(CapabilityError::CleanupNonceMismatch);
        }
        if !receipt.verified || !receipt.bundle_path.is_file() {
            return Err(CapabilityError::CleanupReceiptRequired(
                "bundle missing or unverified".into(),
            ));
        }
        let bundle = receipt.bundle_path.to_string_lossy().into_owned();
        self.git
            .run(
                Some(&self.repo_dir),
                FileProtocol::Never,
                &["bundle", "verify", &bundle],
                &[],
            )
            .map_err(|err| CapabilityError::CleanupReceiptRequired(err.to_string()))?;
        let attempt_dir = self.repo_dir.parent().unwrap_or(&self.repo_dir);
        fs::remove_dir_all(attempt_dir).map_err(|err| io_err("delete workspace", &err))?;
        let tombstone = serde_json::json!({
            "attempt_id": self.manifest.attempt_id,
            "variant_id": self.manifest.variant_id,
            "deleted_at": deleted_at,
            "nonce_hex": self.manifest.nonce_hex,
            "bundle_path": bundle,
        });
        let path = self.runtime_dir.join("tombstone.json");
        fs::write(&path, tombstone.to_string()).map_err(|err| io_err("write tombstone", &err))?;
        Ok(path)
    }
}

/// Detached checkout of the exact base, then creation of the private branch.
///
/// Detached HEAD between the two steps is the expected state and is detected
/// structurally via `symbolic-ref`, never by comparing a branch name to
/// the string "HEAD".
fn checkout_private_branch(
    git: &SafeGit,
    repo_dir: &Path,
    base: &GitOid,
    branch: &str,
) -> Result<(), CapabilityError> {
    git.run(
        Some(repo_dir),
        FileProtocol::Never,
        &["checkout", "--detach", base.as_str()],
        &[],
    )?;
    match git.head_state(repo_dir)? {
        HeadState::Detached => {}
        HeadState::Branch(name) => {
            return Err(CapabilityError::Git(format!(
                "expected detached base checkout, found branch {name}"
            )));
        }
    }
    git.run(
        Some(repo_dir),
        FileProtocol::Never,
        &["checkout", "-b", branch],
        &[],
    )?;
    Ok(())
}

/// Fail closed unless `repo` is a plain repository rooted exactly at `repo`.
///
/// A `.git` file (the on-disk shape of a worktree) is `WORKTREE_FORBIDDEN`; a
/// toplevel other than `repo` (upward discovery) is `WRONG_REPOSITORY`.
///
/// # Errors
///
/// Returns `WORKTREE_FORBIDDEN`, `WRONG_REPOSITORY`, or `IO_FAILED`.
pub fn guard_repository(git: &SafeGit, repo: &Path) -> Result<(), CapabilityError> {
    let dot_git = repo.join(".git");
    let meta = fs::symlink_metadata(&dot_git)
        .map_err(|_| CapabilityError::WrongRepository(format!("{} has no .git", repo.display())))?;
    if !meta.is_dir() {
        return Err(CapabilityError::WorktreeForbidden(
            repo.display().to_string(),
        ));
    }
    let toplevel = git
        .run(
            Some(repo),
            FileProtocol::Never,
            &["rev-parse", "--show-toplevel"],
            &[],
        )?
        .text();
    let expected = fs::canonicalize(repo).map_err(|err| io_err("canonicalize repo", &err))?;
    let actual =
        fs::canonicalize(&toplevel).map_err(|err| io_err("canonicalize toplevel", &err))?;
    if expected != actual {
        return Err(CapabilityError::WrongRepository(format!(
            "toplevel {} != expected {}",
            actual.display(),
            expected.display()
        )));
    }
    Ok(())
}

/// Refuse when sequencer state is present (spec: checkpoint/prepare time).
///
/// # Errors
///
/// Returns `SEQUENCER_ACTIVE` naming the state file.
pub fn sequencer_check(repo: &Path) -> Result<(), CapabilityError> {
    for name in ["CHERRY_PICK_HEAD", "MERGE_HEAD", "REBASE_HEAD"] {
        if repo.join(".git").join(name).exists() {
            return Err(CapabilityError::SequencerActive(name.to_string()));
        }
    }
    Ok(())
}
