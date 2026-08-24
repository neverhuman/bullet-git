//! Append-only workspace journal. Uncommitted work is recoverable state.

use bullet_git_types::{frame, CheckpointId, Digest, GitOid};
use serde::{Deserialize, Serialize};

/// What a journal entry did to its path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JournalOpKind {
    /// Full-file write (create or modify).
    Write,
    /// File deletion.
    Delete,
}

impl JournalOpKind {
    fn frame_tag(self) -> &'static [u8] {
        match self {
            Self::Write => b"w",
            Self::Delete => b"d",
        }
    }
}

/// One filesystem mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalOp {
    /// Sequence number.
    pub seq: u64,
    /// Path.
    pub path: String,
    /// Write or delete.
    pub kind: JournalOpKind,
    /// Content digest: after the op for a write, before the op for a delete.
    pub digest: Digest,
}

/// Immutable checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint {
    /// Identity.
    pub id: CheckpointId,
    /// Inclusive op range end.
    pub through_seq: u64,
    /// Journal tree digest over all framed ops.
    pub tree: Digest,
    /// Exact Git tree of the working copy, when a real repository backs it.
    pub git_tree: Option<GitOid>,
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

    /// Record a full-file write. The digest covers the contents after the op.
    pub fn record(&mut self, path: &str, contents: &[u8]) {
        self.push(path, JournalOpKind::Write, Digest::of(contents));
    }

    /// Record a deletion. The digest covers the contents before the op, so
    /// the destroyed state stays recoverable evidence.
    pub fn record_delete(&mut self, path: &str, before: &[u8]) {
        self.push(path, JournalOpKind::Delete, Digest::of(before));
    }

    fn push(&mut self, path: &str, kind: JournalOpKind, digest: Digest) {
        let seq = self.ops.len() as u64 + 1;
        self.ops.push(JournalOp {
            seq,
            path: path.to_string(),
            kind,
            digest,
        });
    }

    /// Freeze a checkpoint at the current head.
    ///
    /// Every op field, including the op kind, is length-prefix framed, so op
    /// boundaries never collide and a delete never hashes like a write.
    #[must_use]
    pub fn checkpoint(&self) -> Checkpoint {
        let through_seq = self.ops.last().map_or(0, |op| op.seq);
        let mut buf = Vec::new();
        for op in &self.ops {
            frame(&mut buf, &op.seq.to_le_bytes());
            frame(&mut buf, op.kind.frame_tag());
            frame(&mut buf, op.path.as_bytes());
            frame(&mut buf, op.digest.as_bytes());
        }
        let tree = Digest::of(&buf);
        Checkpoint {
            id: CheckpointId::from_seed(&format!("{through_seq}:{}", tree.to_hex())),
            through_seq,
            tree,
            git_tree: None,
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
        assert_eq!(ck.git_tree, None);
    }

    #[test]
    fn checkpoint_preimage_is_framed() {
        let mut ab = Journal::new();
        ab.record("ab", b"");
        let mut a = Journal::new();
        a.record("a", b"b");
        assert_ne!(ab.checkpoint().tree, a.checkpoint().tree);
    }

    #[test]
    fn delete_records_before_state_and_never_hashes_like_a_write() {
        let mut deleted = Journal::new();
        deleted.record_delete("x.rs", b"body");
        let op = &deleted.ops()[0];
        assert_eq!(op.kind, JournalOpKind::Delete);
        assert_eq!(op.digest, Digest::of(b"body"));
        let mut written = Journal::new();
        written.record("x.rs", b"body");
        assert_ne!(deleted.checkpoint().tree, written.checkpoint().tree);
    }
}
