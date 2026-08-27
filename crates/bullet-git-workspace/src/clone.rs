//! Private clone creation (spec §20.2) and receipt-gated cleanup (spec §20.8).

mod repository_setup;

use crate::fsync::write_new_durable_file;
use crate::generation::{
    ActiveGenerationBinding, GenerationBootstrap, GenerationStore, StagedGeneration,
};
use crate::mirror::sync_mirror;
use crate::preservation::{CleanupPermit, PreservationError};
use crate::reflink::CopyMode;
use crate::safe_git::{FileProtocol, SafeGit};
use crate::{io_err, CapabilityError};
use bullet_git_journal::{Checkpoint, DurableJournal};
use bullet_git_types::GitOid;
use repository_setup::{checkout_private_branch, clone_from_mirror, prepare_private_directory};
pub use repository_setup::{guard_repository, sequencer_check};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::path::{Path, PathBuf};

/// Inputs for private clone creation. Clock and nonce come from the caller so
/// the workspace layer stays deterministic and testable.
#[derive(Debug)]
pub struct CloneRequest<'a> {
    /// Source repository. Synced into a per-repository mirror under the
    /// root; never contacted again after creation.
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
#[serde(deny_unknown_fields)]
pub struct WorkspaceManifest {
    /// Attempt incarnation.
    pub attempt_id: String,
    /// Variant that owns the writer lease.
    pub variant_id: String,
    /// Exact base commit.
    pub base_sha: GitOid,
    /// Private branch `bullet/<variant_id>/<attempt_id>`.
    pub branch: String,
    /// RFC 3339 creation timestamp from the caller's clock.
    pub created_at: String,
    /// Hex of the 32-byte workspace nonce.
    pub nonce_hex: String,
    /// Source repository path at creation time.
    pub source_repo: String,
    /// Bare mirror the workspace was cloned from.
    pub mirror_dir: String,
    /// How the private object store was independently materialized.
    pub object_materialization: CopyMode,
    /// Private clone path.
    pub repo_dir: String,
}

/// A private writable clone with no remote and no credential path.
#[derive(Debug)]
pub struct PrivateClone {
    generations: GenerationStore,
    runtime_dir: PathBuf,
    manifest: WorkspaceManifest,
    git: SafeGit,
}

impl PrivateClone {
    /// Create a private clone per spec §20.2.
    ///
    /// Sync the per-repository mirror under the exclusive lock → verify base
    /// exists in the mirror → initialize a remote-free repository with the
    /// exact object format → reflink or bounded-copy the mirror object store
    /// without alternates → detached
    /// checkout of the exact base → create the private branch → record the
    /// manifest in the runtime dir, never inside the repo tree.
    ///
    /// # Errors
    ///
    /// Fails closed with `BASE_MISSING`, `WORKTREE_FORBIDDEN`,
    /// `WRONG_REPOSITORY`, `GIT_FAILED`, or `IO_FAILED`.
    pub fn create(req: &CloneRequest<'_>) -> Result<Self, CapabilityError> {
        let base = GitOid::new(req.base_sha)?;
        let runtime_root = req.root.join("runtime");
        prepare_private_directory(&runtime_root)?;
        let runtime_dir = runtime_root.join(req.attempt_id);
        prepare_private_directory(&runtime_dir)?;
        let git = SafeGit::new(&runtime_dir)?;
        let mirror = sync_mirror(&git, req.root, req.source_repo)?;
        let commitish = format!("{}^{{commit}}", base.hex());
        let base_exists = git.probe(
            Some(&mirror.dir),
            &["rev-parse", "--verify", "--quiet", &commitish],
        )?;
        if !base_exists {
            return Err(CapabilityError::BaseMissing(base.as_str().to_string()));
        }
        let work_root = req.root.join("work");
        prepare_private_directory(&work_root)?;
        let work_dir = work_root.join(req.attempt_id);
        prepare_private_directory(&work_dir)?;
        let bootstrap = GenerationBootstrap::prepare(&work_dir)?;
        let repo_dir = bootstrap.repo_dir();
        let source = req.source_repo.to_string_lossy().into_owned();
        let mirror_str = mirror.dir.to_string_lossy().into_owned();
        let dest = repo_dir.to_string_lossy().into_owned();
        let object_materialization =
            clone_from_mirror(&git, &mirror.dir, &repo_dir, base.algorithm())?;
        mirror.release();
        guard_repository(&git, &repo_dir)?;
        let branch = format!("bullet/{}/{}", req.variant_id, req.attempt_id);
        checkout_private_branch(&git, &repo_dir, &base, &branch)?;
        git.run(
            Some(&repo_dir),
            FileProtocol::Never,
            &["fsck", "--full", "--strict", "--no-dangling"],
            &[],
        )?;
        let journal = DurableJournal::open(bootstrap.journal_dir())?;
        let base_tree = git
            .run(
                Some(&repo_dir),
                FileProtocol::Never,
                &["rev-parse", "HEAD^{tree}"],
                &[],
            )?
            .text();
        let initial_checkpoint = journal
            .checkpoint()
            .bind_git_tree(GitOid::from_hex(base.algorithm(), base_tree)?);
        let nonce_hex = hex::encode(req.nonce);
        let generations = bootstrap.finish(req.attempt_id, &nonce_hex, initial_checkpoint)?;
        let manifest = WorkspaceManifest {
            attempt_id: req.attempt_id.to_string(),
            variant_id: req.variant_id.to_string(),
            base_sha: base,
            branch,
            created_at: req.created_at.to_string(),
            nonce_hex,
            source_repo: source,
            mirror_dir: mirror_str,
            object_materialization,
            repo_dir: dest,
        };
        let manifest_json = serde_json::to_vec_pretty(&manifest)
            .map_err(|err| CapabilityError::Io(format!("encode manifest: {err}")))?;
        fs::write(runtime_dir.join("manifest.json"), manifest_json)
            .map_err(|err| io_err("write manifest", &err))?;
        Ok(Self {
            generations,
            runtime_dir,
            manifest,
            git,
        })
    }

    /// The private clone directory.
    #[must_use]
    pub fn repo_dir(&self) -> &Path {
        // The store owns this stable path until the next successful switch.
        // Keeping the path inside the store prevents a second source of truth.
        self.generations.repo_dir_ref()
    }

    /// Durable journal directory of the active generation.
    #[must_use]
    pub fn journal_dir(&self) -> PathBuf {
        self.generations.journal_dir()
    }

    /// Active immutable generation number.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.generations.generation()
    }

    /// Exact manifest, pointer, and checkpoint identity of the active generation.
    #[must_use]
    pub fn active_generation_binding(&self) -> ActiveGenerationBinding {
        self.generations.binding()
    }

    pub(crate) fn work_dir(&self) -> &Path {
        self.generations.work_dir()
    }

    pub(crate) fn active_generation_dir(&self) -> PathBuf {
        self.generations.active_dir()
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
        self.manifest.base_sha.as_str()
    }

    pub(crate) fn git_oid(&self, hex: impl Into<String>) -> Result<GitOid, CapabilityError> {
        Ok(GitOid::from_hex(self.manifest.base_sha.algorithm(), hex)?)
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

    pub(crate) fn reopen_generation(&mut self) -> Result<(), CapabilityError> {
        self.generations = GenerationStore::open(
            self.generations.work_dir(),
            &self.manifest.attempt_id,
            &self.manifest.nonce_hex,
        )?;
        Ok(())
    }

    pub(crate) fn stage_generation(&self) -> Result<StagedGeneration, CapabilityError> {
        self.generations.stage().map_err(Into::into)
    }

    pub(crate) fn publish_generation(
        &mut self,
        stage: StagedGeneration,
        checkpoint: Checkpoint,
    ) -> Result<(), CapabilityError> {
        self.generations
            .publish(stage, checkpoint)
            .map_err(Into::into)
    }

    pub(crate) fn generation_checkpoint(&self) -> &Checkpoint {
        self.generations.checkpoint()
    }

    /// Delete the one exact workspace named by a sealed cleanup permit.
    ///
    /// # Errors
    ///
    /// Returns `PRESERVATION_RECEIPT_REFUSED` when the permit does not bind
    /// this workspace. Once deletion starts, any failure is
    /// `PRESERVATION_OUTCOME_UNKNOWN` because removal may be partial.
    pub(crate) fn cleanup(
        &mut self,
        permit: CleanupPermit,
        deleted_at: &str,
    ) -> Result<PathBuf, CapabilityError> {
        let work_dir = self.generations.work_dir().to_path_buf();
        if !permit.matches(
            &self.manifest.attempt_id,
            &self.manifest.nonce_hex,
            &work_dir,
        ) {
            return Err(crate::preservation::PreservationError::ReceiptRefused(
                "cleanup permit does not bind this exact workspace".into(),
            )
            .into());
        }
        permit.revalidate(self)?;
        let metadata = fs::symlink_metadata(&work_dir)
            .map_err(|error| io_err("inspect cleanup target", &error))?;
        let canonical = fs::canonicalize(&work_dir)
            .map_err(|error| io_err("canonicalize cleanup target", &error))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() || canonical != work_dir {
            return Err(crate::preservation::PreservationError::ReceiptRefused(
                "cleanup target path identity changed".into(),
            )
            .into());
        }
        fs::remove_dir_all(&work_dir).map_err(|error| {
            PreservationError::OutcomeUnknown(format!("delete workspace: {error}"))
        })?;
        if let Some(parent) = work_dir.parent() {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .map_err(|error| {
                    PreservationError::OutcomeUnknown(format!("sync cleanup parent: {error}"))
                })?;
        }
        let tombstone = serde_json::json!({
            "schema_version": 1,
            "attempt_id": self.manifest.attempt_id,
            "variant_id": self.manifest.variant_id,
            "deleted_at": deleted_at,
            "nonce_hex": self.manifest.nonce_hex,
            "preservation_receipt_digest": permit.receipt_digest().to_hex(),
            "preservation_artifact_digest": permit.artifact_digest().to_hex(),
            "preservation_destination": permit.destination().display().to_string(),
        });
        let path = self.runtime_dir.join("tombstone.json");
        let bytes = serde_json::to_vec(&tombstone).map_err(|error| {
            PreservationError::OutcomeUnknown(format!("encode cleanup tombstone: {error}"))
        })?;
        write_new_durable_file(&path, &bytes).map_err(|error| {
            PreservationError::OutcomeUnknown(format!("persist cleanup tombstone: {error}"))
        })?;
        Ok(path)
    }
}
