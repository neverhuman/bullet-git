//! Append-only workspace journal. Uncommitted work is recoverable state.

use bullet_git_types::{CheckpointId, Digest};
use serde::{Deserialize, Serialize};

/// One filesystem mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalOp {
    /// Sequence number.
    pub seq: u64,
    /// Path.
    pub path: String,
    /// Content digest after the op.
    pub after: Digest,
}

/// Immutable checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Identity.
    pub id: CheckpointId,
    /// Inclusive op range end.
    pub through_seq: u64,
    /// Tree digest.
    pub tree: Digest,
}

/// In-memory journal.
#[derive(Default)]
pub struct Journal {
    ops: Vec<JournalOp>,
}

impl Journal {
    /// Empty journal.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a mutation.
    pub fn record(&mut self, path: &str, contents: &[u8]) {
        let seq = self.ops.len() as u64 + 1;
        self.ops.push(JournalOp {
            seq,
            path: path.to_string(),
            after: Digest::of(contents),
        });
    }

    /// Freeze a checkpoint at the current head.
    #[must_use]
    pub fn checkpoint(&self) -> Checkpoint {
        let through_seq = self.ops.last().map_or(0, |op| op.seq);
        let mut buf = Vec::new();
        for op in &self.ops {
            buf.extend_from_slice(op.path.as_bytes());
            buf.extend_from_slice(op.after.to_hex().as_bytes());
        }
        Checkpoint {
            id: CheckpointId::from_seed(&through_seq.to_string()),
            through_seq,
            tree: Digest::of(&buf),
        }
    }

    /// Ops recorded so far.
    #[must_use]
    pub fn ops(&self) -> &[JournalOp] {
        &self.ops
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_covers_ops() {
        let mut journal = Journal::new();
        journal.record("a.rs", b"one");
        journal.record("a.rs", b"two");
        let ck = journal.checkpoint();
        assert_eq!(ck.through_seq, 2);
        assert_eq!(journal.ops().len(), 2);
    }
}
