//! Immutable, checksummed, batch-atomic journal persistence.

use std::path::{Path, PathBuf};

use bullet_git_types::Digest;
use thiserror::Error;

use crate::storage::{load_batches, prepare_directory, publish_batch, StoredBatch};
use crate::{Checkpoint, Journal, JournalOp, JournalOpKind};

/// Durable journal failure with a stable reason code.
#[derive(Debug, Error)]
pub enum JournalError {
    /// Filesystem operation failed.
    #[error("journal io failure: {0}")]
    Io(String),
    /// Persisted state is malformed, discontinuous, or checksum-invalid.
    #[error("corrupt journal: {0}")]
    Corrupt(String),
    /// A prior append reached an indeterminate durability boundary.
    #[error("journal is poisoned after a failed append")]
    Poisoned,
}

impl JournalError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Io(_) => "JOURNAL_IO_FAILED",
            Self::Corrupt(_) => "CORRUPT_JOURNAL",
            Self::Poisoned => "JOURNAL_POISONED",
        }
    }

    /// Whether an immutable batch may already be visible on disk.
    #[must_use]
    pub fn may_have_published(&self) -> bool {
        matches!(self, Self::Poisoned)
    }
}

/// One admitted mutation before its durable sequence is allocated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct JournalMutation {
    path: String,
    kind: JournalOpKind,
    before: Option<Digest>,
    after: Option<Digest>,
}

impl JournalMutation {
    /// Bind a write to immutable before/after content objects.
    #[must_use]
    pub fn write(path: &str, before: Option<Digest>, after: Digest) -> Self {
        Self {
            path: path.to_owned(),
            kind: JournalOpKind::Write,
            before,
            after: Some(after),
        }
    }

    /// Bind a deletion to its immutable destroyed before-state object.
    #[must_use]
    pub fn delete(path: &str, before: Digest) -> Self {
        Self {
            path: path.to_owned(),
            kind: JournalOpKind::Delete,
            before: Some(before),
            after: None,
        }
    }
}

/// Journal whose authoritative batches are immutable files under one directory.
#[derive(Debug)]
pub struct DurableJournal {
    directory: PathBuf,
    journal: Journal,
    head_checksum: Option<Digest>,
    healthy: bool,
}

impl DurableJournal {
    /// Open an existing journal or create an empty one, validating every batch.
    ///
    /// Recognizable pre-publication `.tmp` files are non-authoritative crash orphans
    /// and are ignored. Every other entry must be a contiguous batch file.
    pub fn open(directory: impl AsRef<Path>) -> Result<Self, JournalError> {
        let directory = directory.as_ref().to_path_buf();
        prepare_directory(&directory)?;
        let (ops, head_checksum) = load_batches(&directory)?;
        Ok(Self {
            directory,
            journal: Journal { ops },
            head_checksum,
            healthy: true,
        })
    }

    /// Append one admitted patch batch durably and atomically.
    pub fn record_batch(&mut self, mutations: &[JournalMutation]) -> Result<(), JournalError> {
        if !self.healthy {
            return Err(JournalError::Poisoned);
        }
        if mutations.is_empty() {
            return Ok(());
        }
        let result = self.append_batch(mutations);
        if result.is_err() {
            self.healthy = false;
        }
        result
    }

    fn append_batch(&mut self, mutations: &[JournalMutation]) -> Result<(), JournalError> {
        let current_len = u64::try_from(self.journal.ops.len())
            .map_err(|_| JournalError::Corrupt("journal is too large".into()))?;
        let start_seq = current_len
            .checked_add(1)
            .ok_or_else(|| JournalError::Corrupt("sequence overflow".into()))?;
        let mut ops = Vec::with_capacity(mutations.len());
        for (offset, mutation) in mutations.iter().enumerate() {
            if mutation.path.is_empty() || mutation.path.contains('\0') {
                return Err(JournalError::Corrupt("invalid empty or NUL path".into()));
            }
            let offset = u64::try_from(offset)
                .map_err(|_| JournalError::Corrupt("batch is too large".into()))?;
            let seq = start_seq
                .checked_add(offset)
                .ok_or_else(|| JournalError::Corrupt("sequence overflow".into()))?;
            ops.push(JournalOp {
                seq,
                path: mutation.path.clone(),
                kind: mutation.kind,
                before: mutation.before,
                after: mutation.after,
            });
        }
        let end_seq = ops
            .last()
            .ok_or_else(|| JournalError::Corrupt("empty batch".into()))?
            .seq;
        let batch = StoredBatch::new(start_seq, end_seq, self.head_checksum, ops);
        publish_batch(&self.directory, &batch)?;
        let checksum = batch.checksum;
        self.journal.ops.extend(batch.ops);
        self.head_checksum = Some(checksum);
        Ok(())
    }

    /// Freeze a checkpoint over all recovered and appended operations.
    #[must_use]
    pub fn checkpoint(&self) -> Checkpoint {
        self.journal.checkpoint()
    }

    /// Operations recovered and appended so far.
    #[must_use]
    pub fn ops(&self) -> &[JournalOp] {
        self.journal.ops()
    }
}
