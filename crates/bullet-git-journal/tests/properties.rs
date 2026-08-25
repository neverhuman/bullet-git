//! Property tests for journal sequence and checkpoint identity.

use bullet_git_journal::Journal;
use proptest::prelude::*;

proptest! {
    #[test]
    fn sequences_are_monotonic_and_checkpoints_bind(ops in prop::collection::vec("[a-z]{1,6}", 1..8)) {
        let mut journal = Journal::new();
        for (index, name) in ops.iter().enumerate() {
            journal.record(&format!("src/{name}.rs"), name.as_bytes());
            prop_assert_eq!(journal.ops()[index].seq, (index as u64) + 1);
        }
        let checkpoint = journal.checkpoint();
        prop_assert!(checkpoint.identity_is_valid());
        prop_assert_eq!(checkpoint.through_seq, ops.len() as u64);
    }

    #[test]
    fn write_and_delete_do_not_share_a_tree(name in "[a-z]{1,8}") {
        let mut write = Journal::new();
        write.record("src/lib.rs", name.as_bytes());
        let mut delete = Journal::new();
        delete.record_delete("src/lib.rs", name.as_bytes());
        prop_assert_ne!(write.checkpoint().tree, delete.checkpoint().tree);
    }
}
