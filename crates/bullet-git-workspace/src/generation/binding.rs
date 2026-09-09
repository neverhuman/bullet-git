//! Public identity of one durable active workspace generation.

use super::{pointer_digest, GenerationStore};
use bullet_git_journal::Checkpoint;
use bullet_git_types::Digest;
use serde::{Deserialize, Serialize};

/// Parent link committed by a non-root generation manifest.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GenerationParentBinding {
    /// Prior generation number.
    pub generation: u64,
    /// Exact prior manifest digest.
    pub manifest_digest: Digest,
}

/// Exact manifest, pointer, and checkpoint identity of the active generation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveGenerationBinding {
    /// Monotonic generation number.
    pub generation: u64,
    /// Parent identity, absent only for generation zero.
    pub parent: Option<GenerationParentBinding>,
    /// Exact generation-manifest digest.
    pub manifest_digest: Digest,
    /// Exact active-pointer digest.
    pub pointer_digest: Digest,
    /// Exact checkpoint committed by the generation manifest.
    pub checkpoint: Checkpoint,
}

impl GenerationStore {
    pub(crate) fn binding(&self) -> ActiveGenerationBinding {
        ActiveGenerationBinding {
            generation: self.active.generation,
            parent: self
                .active
                .parent
                .as_ref()
                .map(|parent| GenerationParentBinding {
                    generation: parent.generation,
                    manifest_digest: parent.manifest_digest,
                }),
            manifest_digest: self.active.manifest_digest,
            pointer_digest: pointer_digest(self.active.generation, &self.active.manifest_digest),
            checkpoint: self.active.checkpoint.clone(),
        }
    }
}
