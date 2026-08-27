//! Immutable workspace generations with one durable active-pointer switch.

mod binding;
pub use binding::{ActiveGenerationBinding, GenerationParentBinding};

use crate::tree_copy::{
    allocate_pointer_stage, allocate_staging, copy_tree, create_directory,
    inspect_generation_entries, next_generation, read_json, replace_pointer,
    require_ordinary_directory, sync_directory, sync_tree, write_json, write_json_file,
};
use bullet_git_journal::Checkpoint;
use bullet_git_types::{framed_digest, Digest};
use serde::{Deserialize, Serialize};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use thiserror::Error;

const SCHEMA_VERSION: u32 = 1;
const MANIFEST_DOMAIN: &[u8] = b"bullet-git-generation-manifest-v1";
const POINTER_DOMAIN: &[u8] = b"bullet-git-active-generation-v1";
const ACTIVE_FILE: &str = "active.json";
const GENERATIONS_DIR: &str = "generations";

/// Generation publication or recovery failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum GenerationError {
    /// Persisted control data or filesystem shape is invalid.
    #[error("corrupt workspace generation: {0}")]
    Corrupt(String),
    /// The platform lacks the required filesystem primitive.
    #[error("unsupported generation backend: {0}")]
    Unsupported(String),
    /// A filesystem operation failed before the authoritative switch.
    #[error("workspace generation io failure: {0}")]
    Io(String),
    /// The atomic pointer switched but its containing directory did not sync.
    #[error("generation publication outcome is unknown: {0}")]
    OutcomeUnknown(String),
}

impl GenerationError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Corrupt(_) => "GENERATION_CORRUPT",
            Self::Unsupported(_) => "GENERATION_UNSUPPORTED",
            Self::Io(_) => "GENERATION_IO_FAILED",
            Self::OutcomeUnknown(_) => "GENERATION_OUTCOME_UNKNOWN",
        }
    }

    #[must_use]
    pub(crate) fn may_have_published(&self) -> bool {
        matches!(self, Self::OutcomeUnknown(_))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ParentGeneration {
    generation: u64,
    manifest_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct GenerationManifest {
    schema_version: u32,
    attempt_id: String,
    workspace_nonce_hex: String,
    generation: u64,
    parent: Option<ParentGeneration>,
    checkpoint: Checkpoint,
    manifest_digest: Digest,
}

impl GenerationManifest {
    fn new(
        attempt_id: &str,
        workspace_nonce_hex: &str,
        generation: u64,
        parent: Option<ParentGeneration>,
        checkpoint: Checkpoint,
    ) -> Result<Self, GenerationError> {
        if !checkpoint.identity_is_valid() || checkpoint.git_tree.is_none() {
            return Err(GenerationError::Corrupt(
                "generation checkpoint lacks an exact valid Git tree".into(),
            ));
        }
        let manifest_digest = manifest_digest(
            attempt_id,
            workspace_nonce_hex,
            generation,
            parent.as_ref(),
            &checkpoint,
        );
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            attempt_id: attempt_id.into(),
            workspace_nonce_hex: workspace_nonce_hex.into(),
            generation,
            parent,
            checkpoint,
            manifest_digest,
        })
    }

    fn validate(&self) -> Result<(), GenerationError> {
        let expected = manifest_digest(
            &self.attempt_id,
            &self.workspace_nonce_hex,
            self.generation,
            self.parent.as_ref(),
            &self.checkpoint,
        );
        if self.schema_version != SCHEMA_VERSION
            || !self.checkpoint.identity_is_valid()
            || self.checkpoint.git_tree.is_none()
            || self.manifest_digest != expected
        {
            return Err(GenerationError::Corrupt(
                "generation manifest identity mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ActivePointer {
    schema_version: u32,
    generation: u64,
    manifest_digest: Digest,
    pointer_digest: Digest,
}

impl ActivePointer {
    fn new(manifest: &GenerationManifest) -> Self {
        let pointer_digest = pointer_digest(manifest.generation, &manifest.manifest_digest);
        Self {
            schema_version: SCHEMA_VERSION,
            generation: manifest.generation,
            manifest_digest: manifest.manifest_digest,
            pointer_digest,
        }
    }

    fn validate(&self) -> Result<(), GenerationError> {
        if self.schema_version != SCHEMA_VERSION
            || self.pointer_digest != pointer_digest(self.generation, &self.manifest_digest)
        {
            return Err(GenerationError::Corrupt(
                "active generation pointer identity mismatch".into(),
            ));
        }
        Ok(())
    }
}

/// A generation being built outside the authoritative active pointer.
#[derive(Debug)]
pub(crate) struct StagedGeneration {
    staging_dir: PathBuf,
    final_dir: PathBuf,
    generation: u64,
}

impl StagedGeneration {
    pub(crate) fn repo_dir(&self) -> PathBuf {
        self.staging_dir.join("repo")
    }

    pub(crate) fn journal_dir(&self) -> PathBuf {
        self.staging_dir.join("journal")
    }
}

/// Initial-generation layout before an active pointer exists.
pub(crate) struct GenerationBootstrap {
    work_dir: PathBuf,
    generation_dir: PathBuf,
}

impl GenerationBootstrap {
    pub(crate) fn prepare(work_dir: &Path) -> Result<Self, GenerationError> {
        require_ordinary_directory(work_dir)?;
        let generations = work_dir.join(GENERATIONS_DIR);
        create_directory(&generations)?;
        let generation_dir = generations.join(generation_name(0));
        create_directory(&generation_dir)?;
        create_directory(&generation_dir.join("journal"))?;
        Ok(Self {
            work_dir: work_dir.to_path_buf(),
            generation_dir,
        })
    }

    pub(crate) fn repo_dir(&self) -> PathBuf {
        self.generation_dir.join("repo")
    }

    pub(crate) fn journal_dir(&self) -> PathBuf {
        self.generation_dir.join("journal")
    }

    pub(crate) fn finish(
        self,
        attempt_id: &str,
        nonce_hex: &str,
        checkpoint: Checkpoint,
    ) -> Result<GenerationStore, GenerationError> {
        let manifest = GenerationManifest::new(attempt_id, nonce_hex, 0, None, checkpoint)?;
        write_json(&self.generation_dir.join("manifest.json"), &manifest)?;
        sync_tree(&self.generation_dir)?;
        sync_directory(&self.work_dir.join(GENERATIONS_DIR))
            .map_err(|error| io("sync initial generations directory", error))?;
        write_initial_pointer(&self.work_dir, &ActivePointer::new(&manifest))?;
        Ok(GenerationStore {
            work_dir: self.work_dir,
            attempt_id: attempt_id.into(),
            nonce_hex: nonce_hex.into(),
            active: manifest,
            active_repo: self.generation_dir.join("repo"),
        })
    }
}

/// Reopenable authority over one active generation.
#[derive(Debug)]
pub(crate) struct GenerationStore {
    work_dir: PathBuf,
    attempt_id: String,
    nonce_hex: String,
    active: GenerationManifest,
    active_repo: PathBuf,
}

impl GenerationStore {
    pub(crate) fn open(
        work_dir: &Path,
        attempt_id: &str,
        nonce_hex: &str,
    ) -> Result<Self, GenerationError> {
        require_ordinary_directory(work_dir)?;
        let generations = work_dir.join(GENERATIONS_DIR);
        require_ordinary_directory(&generations)?;
        inspect_generation_entries(&generations)?;
        let pointer: ActivePointer = read_json(&work_dir.join(ACTIVE_FILE))?;
        pointer.validate()?;
        let generation_dir = generations.join(generation_name(pointer.generation));
        let manifest: GenerationManifest = read_json(&generation_dir.join("manifest.json"))?;
        manifest.validate()?;
        if manifest.attempt_id != attempt_id
            || manifest.workspace_nonce_hex != nonce_hex
            || manifest.generation != pointer.generation
            || manifest.manifest_digest != pointer.manifest_digest
        {
            return Err(GenerationError::Corrupt(
                "active pointer does not bind the requested workspace".into(),
            ));
        }
        validate_lineage(&generations, &manifest, attempt_id, nonce_hex)?;
        require_ordinary_directory(&generation_dir.join("repo"))?;
        require_ordinary_directory(&generation_dir.join("journal"))?;
        Ok(Self {
            work_dir: work_dir.to_path_buf(),
            attempt_id: attempt_id.into(),
            nonce_hex: nonce_hex.into(),
            active: manifest,
            active_repo: generation_dir.join("repo"),
        })
    }

    pub(crate) fn work_dir(&self) -> &Path {
        &self.work_dir
    }

    pub(crate) fn generation(&self) -> u64 {
        self.active.generation
    }

    pub(crate) fn repo_dir(&self) -> PathBuf {
        self.active_repo.clone()
    }

    pub(crate) fn repo_dir_ref(&self) -> &Path {
        &self.active_repo
    }

    pub(crate) fn journal_dir(&self) -> PathBuf {
        self.active_dir().join("journal")
    }

    pub(crate) fn checkpoint(&self) -> &Checkpoint {
        &self.active.checkpoint
    }

    pub(crate) fn stage(&self) -> Result<StagedGeneration, GenerationError> {
        let generations = self.work_dir.join(GENERATIONS_DIR);
        let generation = next_generation(&generations)?;
        let final_dir = generations.join(generation_name(generation));
        let staging_dir = allocate_staging(&generations, generation)?;
        copy_tree(&self.repo_dir(), &staging_dir.join("repo"))?;
        copy_tree(&self.journal_dir(), &staging_dir.join("journal"))?;
        Ok(StagedGeneration {
            staging_dir,
            final_dir,
            generation,
        })
    }

    pub(crate) fn publish(
        &mut self,
        stage: StagedGeneration,
        checkpoint: Checkpoint,
    ) -> Result<(), GenerationError> {
        self.publish_with(stage, checkpoint, &mut NoGenerationFault)
    }

    pub(crate) fn publish_with(
        &mut self,
        stage: StagedGeneration,
        checkpoint: Checkpoint,
        faults: &mut impl GenerationFaults,
    ) -> Result<(), GenerationError> {
        let parent = ParentGeneration {
            generation: self.active.generation,
            manifest_digest: self.active.manifest_digest,
        };
        let manifest = GenerationManifest::new(
            &self.attempt_id,
            &self.nonce_hex,
            stage.generation,
            Some(parent),
            checkpoint,
        )?;
        faults.check(GenerationBoundary::GenerationFileSync)?;
        write_json(&stage.staging_dir.join("manifest.json"), &manifest)?;
        sync_tree(&stage.staging_dir)?;
        faults.check(GenerationBoundary::GenerationRename)?;
        fs::rename(&stage.staging_dir, &stage.final_dir)
            .map_err(|error| io("publish generation directory", error))?;
        faults.check(GenerationBoundary::GenerationDirectorySync)?;
        sync_directory(&self.work_dir.join(GENERATIONS_DIR))
            .map_err(|error| io("sync generations directory", error))?;
        let pointer = ActivePointer::new(&manifest);
        let pointer_stage = allocate_pointer_stage(&self.work_dir, stage.generation)?;
        faults.check(GenerationBoundary::PointerWrite)?;
        write_json_file(&pointer_stage, &pointer)?;
        faults.check(GenerationBoundary::PointerFileSync)?;
        File::open(&pointer_stage)
            .and_then(|file| file.sync_all())
            .map_err(|error| io("sync staged active pointer", error))?;
        faults.check(GenerationBoundary::PointerRename)?;
        replace_pointer(&pointer_stage, &self.work_dir.join(ACTIVE_FILE))?;
        if faults.trips(GenerationBoundary::PointerDirectorySync) {
            return Err(GenerationError::OutcomeUnknown(
                "injected active-pointer directory-sync failure".into(),
            ));
        }
        sync_directory(&self.work_dir).map_err(|error| {
            GenerationError::OutcomeUnknown(format!("sync active-pointer directory: {error}"))
        })?;
        self.active_repo = stage.final_dir.join("repo");
        self.active = manifest;
        Ok(())
    }

    pub(crate) fn active_dir(&self) -> PathBuf {
        self.active_repo
            .parent()
            .expect("active repo always has a generation parent")
            .to_path_buf()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum GenerationBoundary {
    GenerationFileSync,
    GenerationRename,
    GenerationDirectorySync,
    PointerWrite,
    PointerFileSync,
    PointerRename,
    PointerDirectorySync,
}

pub(crate) trait GenerationFaults {
    fn trips(&mut self, _boundary: GenerationBoundary) -> bool {
        false
    }

    fn check(&mut self, boundary: GenerationBoundary) -> Result<(), GenerationError> {
        if self.trips(boundary) {
            Err(GenerationError::Io(format!(
                "injected {boundary:?} failure"
            )))
        } else {
            Ok(())
        }
    }
}

struct NoGenerationFault;
impl GenerationFaults for NoGenerationFault {}

fn manifest_digest(
    attempt_id: &str,
    nonce_hex: &str,
    generation: u64,
    parent: Option<&ParentGeneration>,
    checkpoint: &Checkpoint,
) -> Digest {
    let generation_bytes = generation.to_le_bytes();
    let parent_generation = parent.map_or([0; 8], |value| value.generation.to_le_bytes());
    let parent_digest = parent.map_or([0; 32], |value| *value.manifest_digest.as_bytes());
    let parent_tag: &[u8] = if parent.is_some() { b"parent" } else { b"root" };
    framed_digest(&[
        MANIFEST_DOMAIN,
        attempt_id.as_bytes(),
        nonce_hex.as_bytes(),
        &generation_bytes,
        parent_tag,
        &parent_generation,
        &parent_digest,
        checkpoint.digest.as_bytes(),
    ])
}

fn pointer_digest(generation: u64, manifest: &Digest) -> Digest {
    framed_digest(&[
        POINTER_DOMAIN,
        &generation.to_le_bytes(),
        manifest.as_bytes(),
    ])
}

fn validate_lineage(
    generations: &Path,
    active: &GenerationManifest,
    attempt_id: &str,
    nonce_hex: &str,
) -> Result<(), GenerationError> {
    let mut current = active.clone();
    loop {
        let Some(parent) = current.parent.as_ref() else {
            return if current.generation == 0 {
                Ok(())
            } else {
                Err(GenerationError::Corrupt(
                    "non-root generation lacks a parent".into(),
                ))
            };
        };
        if parent.generation >= current.generation {
            return Err(GenerationError::Corrupt(
                "generation parent does not precede its child".into(),
            ));
        }
        let prior: GenerationManifest = read_json(
            &generations
                .join(generation_name(parent.generation))
                .join("manifest.json"),
        )?;
        prior.validate()?;
        if prior.attempt_id != attempt_id
            || prior.workspace_nonce_hex != nonce_hex
            || prior.generation != parent.generation
            || prior.manifest_digest != parent.manifest_digest
        {
            return Err(GenerationError::Corrupt(
                "generation parent identity mismatch".into(),
            ));
        }
        current = prior;
    }
}

pub(crate) fn generation_name(generation: u64) -> String {
    format!("generation-{generation:020}")
}

fn write_initial_pointer(work_dir: &Path, pointer: &ActivePointer) -> Result<(), GenerationError> {
    let stage = allocate_pointer_stage(work_dir, pointer.generation)?;
    write_json_file(&stage, pointer)?;
    File::open(&stage)
        .and_then(|file| file.sync_all())
        .map_err(|error| io("sync initial active pointer", error))?;
    replace_pointer(&stage, &work_dir.join(ACTIVE_FILE))?;
    sync_directory(work_dir).map_err(|error| io("sync initial active pointer directory", error))
}

fn io(context: &str, error: std::io::Error) -> GenerationError {
    GenerationError::Io(format!("{context}: {error}"))
}
