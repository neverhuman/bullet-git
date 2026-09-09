//! Reopen and publish one active generation.

use super::*;

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
