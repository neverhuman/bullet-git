//! Property tests for scope normalization. Advice is never authority.

use bullet_git_types::RepoPath;
use bullet_git_workspace::{forecast_conflicts, normalize_rel_path};
use proptest::prelude::*;
use std::str::FromStr;

proptest! {
    #[test]
    fn parent_and_git_segments_are_refused(name in "[A-Za-z]{1,6}") {
        let dotted = format!("src/../{name}");
        let git_dir = format!("src/.git/{name}");
        let absolute = format!("/{name}");
        prop_assert!(normalize_rel_path(&dotted).is_err());
        prop_assert!(normalize_rel_path(&git_dir).is_err());
        prop_assert!(normalize_rel_path(&absolute).is_err());
    }

    #[test]
    fn forecast_never_claims_authority(label in "[a-z]{1,6}") {
        let path = RepoPath::from_str(&format!("src/{label}.rs")).expect("path");
        let advice = forecast_conflicts(&[
            std::slice::from_ref(&path),
            std::slice::from_ref(&path),
        ]);
        prop_assert!(!advice.paths.is_empty());
        prop_assert!(advice.note.contains("write-set proof still decides"));
    }
}
