//! Property tests for write-set proof and evidence invalidation.

use bullet_git_types::{write_set_within_grant, EvolutionKind, RepoPath};
use proptest::prelude::*;
use std::str::FromStr;

fn repo_path(label: &str) -> RepoPath {
    RepoPath::from_str(&format!("src/{label}.rs")).expect("path")
}

proptest! {
    #[test]
    fn granted_prefix_covers_nested_paths(label in "[a-z]{1,8}") {
        let grant = RepoPath::from_str("src").expect("grant");
        let actual = repo_path(&label);
        prop_assert!(write_set_within_grant(&[grant], &[actual]).is_ok());
    }

    #[test]
    fn sibling_path_is_outside_the_grant(label in "[a-z]{1,8}") {
        let grant = RepoPath::from_str("src").expect("grant");
        let actual = RepoPath::from_str(&format!("doc/{label}.md")).expect("path");
        prop_assert_eq!(
            write_set_within_grant(&[grant], &[actual])
                .expect_err("outside")
                .reason_code(),
            "ACTUAL_SCOPE_EXCEEDS_GRANT"
        );
    }

    #[test]
    fn rebase_family_invalidates_and_repair_does_not(_seed in 0u8..16) {
        prop_assert!(EvolutionKind::Rebase.invalidates_evidence());
        prop_assert!(EvolutionKind::Squash.invalidates_evidence());
        prop_assert!(EvolutionKind::Split.invalidates_evidence());
        prop_assert!(EvolutionKind::CherryPick.invalidates_evidence());
        prop_assert!(EvolutionKind::MergeComposition.invalidates_evidence());
        prop_assert!(!EvolutionKind::Repair.invalidates_evidence());
        prop_assert!(!EvolutionKind::Amend.invalidates_evidence());
        prop_assert!(!EvolutionKind::Synthesis.invalidates_evidence());
        prop_assert!(!EvolutionKind::GeneratedRefresh.invalidates_evidence());
    }
}
