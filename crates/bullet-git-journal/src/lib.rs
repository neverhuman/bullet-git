//! Append-only workspace journal. Uncommitted work is recoverable state.

mod durable;
mod storage;

pub use durable::{DurableJournal, JournalError, JournalMutation};

use bullet_git_types::{frame, framed_digest, CheckpointId, Digest, GitOid};
use serde::{Deserialize, Serialize};

const CHECKPOINT_DOMAIN: &[u8] = b"bullet-git.checkpoint.v3";
const JOURNAL_TREE_DOMAIN: &[u8] = b"bullet-git.journal-tree.v2";

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
    pub(crate) fn frame_tag(self) -> &'static [u8] {
        match self {
            Self::Write => b"w",
            Self::Delete => b"d",
        }
    }
}

/// One filesystem mutation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalOp {
    /// Sequence number.
    pub seq: u64,
    /// Path.
    pub path: String,
    /// Write or delete.
    pub kind: JournalOpKind,
    /// Immutable content-object digest before the mutation, when a file existed.
    pub before: Option<Digest>,
    /// Immutable content-object digest after the mutation, when a file remains.
    pub after: Option<Digest>,
}

/// Immutable checkpoint.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Checkpoint {
    /// Identity.
    pub id: CheckpointId,
    /// Inclusive op range end.
    pub through_seq: u64,
    /// Journal tree digest over all framed ops.
    pub tree: Digest,
    /// Exact Git tree of the working copy, when a real repository backs it.
    pub git_tree: Option<GitOid>,
    /// Full digest of the sequence, journal root, and algorithm-tagged Git tree.
    pub digest: Digest,
}

impl Checkpoint {
    /// Bind this journal checkpoint to an exact algorithm-tagged Git tree.
    ///
    /// The full digest and short typed address are both recomputed; attaching a
    /// tree after identity derivation is therefore impossible through this API.
    #[must_use]
    pub fn bind_git_tree(mut self, git_tree: GitOid) -> Self {
        self.git_tree = Some(git_tree);
        self.rebind_identity();
        self
    }

    /// Recompute and compare the persisted full digest and typed address.
    #[must_use]
    pub fn identity_is_valid(&self) -> bool {
        let digest = checkpoint_digest(self.through_seq, &self.tree, self.git_tree.as_ref());
        self.digest == digest && self.id == checkpoint_id(&digest)
    }

    fn rebind_identity(&mut self) {
        self.digest = checkpoint_digest(self.through_seq, &self.tree, self.git_tree.as_ref());
        self.id = checkpoint_id(&self.digest);
    }
}

/// In-memory journal.
#[derive(Debug, Default)]
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
        self.push(path, JournalOpKind::Write, None, Some(Digest::of(contents)));
    }

    /// Record a deletion. The digest covers the contents before the op, so
    /// the destroyed state stays recoverable evidence.
    pub fn record_delete(&mut self, path: &str, before: &[u8]) {
        self.push(path, JournalOpKind::Delete, Some(Digest::of(before)), None);
    }

    fn push(
        &mut self,
        path: &str,
        kind: JournalOpKind,
        before: Option<Digest>,
        after: Option<Digest>,
    ) {
        let seq = self.ops.len() as u64 + 1;
        self.ops.push(JournalOp {
            seq,
            path: path.to_string(),
            kind,
            before,
            after,
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
        frame(&mut buf, JOURNAL_TREE_DOMAIN);
        for op in &self.ops {
            frame(&mut buf, &op.seq.to_le_bytes());
            frame(&mut buf, op.kind.frame_tag());
            frame(&mut buf, op.path.as_bytes());
            frame_optional_digest(&mut buf, op.before.as_ref());
            frame_optional_digest(&mut buf, op.after.as_ref());
        }
        let tree = Digest::of(&buf);
        let digest = checkpoint_digest(through_seq, &tree, None);
        let checkpoint = Checkpoint {
            id: checkpoint_id(&digest),
            through_seq,
            tree,
            git_tree: None,
            digest,
        };
        debug_assert!(checkpoint.identity_is_valid());
        checkpoint
    }

    /// Ops recorded so far.
    #[must_use]
    pub fn ops(&self) -> &[JournalOp] {
        &self.ops
    }
}

fn frame_optional_digest(buffer: &mut Vec<u8>, digest: Option<&Digest>) {
    match digest {
        Some(digest) => {
            frame(buffer, b"present");
            frame(buffer, digest.as_bytes());
        }
        None => frame(buffer, b"absent"),
    }
}

fn checkpoint_digest(through_seq: u64, tree: &Digest, git_tree: Option<&GitOid>) -> Digest {
    let sequence = through_seq.to_le_bytes();
    match git_tree {
        Some(git_tree) => framed_digest(&[
            CHECKPOINT_DOMAIN,
            &sequence,
            tree.as_bytes(),
            git_tree.as_str().as_bytes(),
        ]),
        None => framed_digest(&[CHECKPOINT_DOMAIN, &sequence, tree.as_bytes(), b"none"]),
    }
}

fn checkpoint_id(digest: &Digest) -> CheckpointId {
    CheckpointId::from_seed(&digest.to_hex())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bullet_git_types::GitOidAlgorithm;

    #[test]
    fn checkpoint_covers_ops() {
        let mut journal = Journal::new();
        journal.record("a.rs", b"one");
        journal.record("a.rs", b"two");
        let ck = journal.checkpoint();
        assert_eq!(ck.through_seq, 2);
        assert_eq!(journal.ops().len(), 2);
        assert_eq!(ck.git_tree, None);
        assert!(ck.identity_is_valid());
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
        assert_eq!(op.before, Some(Digest::of(b"body")));
        assert_eq!(op.after, None);
        let mut written = Journal::new();
        written.record("x.rs", b"body");
        assert_ne!(deleted.checkpoint().tree, written.checkpoint().tree);
    }

    #[test]
    fn checkpoint_identity_binds_the_exact_git_tree() {
        let mut journal = Journal::new();
        journal.record("a.rs", b"body");
        let draft = journal.checkpoint();
        let a = draft.clone().bind_git_tree(
            GitOid::from_hex(GitOidAlgorithm::Sha1, "a".repeat(40)).expect("tree a"),
        );
        let b = draft.clone().bind_git_tree(
            GitOid::from_hex(GitOidAlgorithm::Sha1, "b".repeat(40)).expect("tree b"),
        );
        assert_eq!(a.tree, b.tree, "journal subject is unchanged");
        assert_ne!(a.digest, b.digest);
        assert_ne!(a.id, b.id);
        assert!(a.identity_is_valid() && b.identity_is_valid());

        let mut forged = a;
        forged.git_tree = b.git_tree;
        assert!(!forged.identity_is_valid());
    }
}
