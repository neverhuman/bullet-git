//! Post-G2 advisers. None of these grant mutation, Evidence, or integration.

use bullet_git_types::RepoPath;

/// Non-authoritative advice. Callers must still enforce write-set proof.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Advice {
    /// Human-readable note.
    pub note: String,
    /// Paths the adviser thinks may collide.
    pub paths: Vec<String>,
}

/// Forecast textual/path collisions. Never a mutex.
#[must_use]
pub fn forecast_conflicts(intents: &[&[RepoPath]]) -> Advice {
    let mut seen = Vec::new();
    let mut collisions = Vec::new();
    for intent in intents {
        for path in *intent {
            let key = path.as_str().to_string();
            if seen.iter().any(|existing: &String| {
                existing == &key
                    || existing.starts_with(&format!("{key}/"))
                    || key.starts_with(&format!("{existing}/"))
            }) {
                collisions.push(key.clone());
            }
            seen.push(key);
        }
    }
    Advice {
        note: if collisions.is_empty() {
            "no path overlap forecast".into()
        } else {
            "path overlap forecast; write-set proof still decides".into()
        },
        paths: collisions,
    }
}

/// Inverse of a write set. Advises a revert; does not apply it.
#[must_use]
pub fn intent_aware_revert(written: &[RepoPath]) -> Advice {
    Advice {
        note: "revert advice only; apply_change remains the writer".into(),
        paths: written.iter().map(ToString::to_string).collect(),
    }
}

/// Commute two write paths when they are disjoint. Not a merge engine.
#[must_use]
pub fn patch_algebra_disjoint(left: &[RepoPath], right: &[RepoPath]) -> Advice {
    let overlap = forecast_conflicts(&[left, right]);
    Advice {
        note: if overlap.paths.is_empty() {
            "disjoint writes may commute; still require independent Evidence".into()
        } else {
            "writes overlap; do not commute without a new Candidate".into()
        },
        paths: overlap.paths,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn forecast_is_not_authority() {
        let a = RepoPath::from_str("src/lib.rs").expect("path");
        let advice = forecast_conflicts(&[std::slice::from_ref(&a), std::slice::from_ref(&a)]);
        assert!(!advice.paths.is_empty());
        assert!(advice.note.contains("write-set proof still decides"));
    }

    #[test]
    fn disjoint_algebra_does_not_merge() {
        let a = RepoPath::from_str("src/a.rs").expect("path");
        let b = RepoPath::from_str("src/b.rs").expect("path");
        let advice = patch_algebra_disjoint(&[a], &[b]);
        assert!(advice.paths.is_empty());
        assert!(advice.note.contains("independent Evidence"));
    }
}
