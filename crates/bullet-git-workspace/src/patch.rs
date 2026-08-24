//! Patch batch shapes and pre-mutation validation shared by every writer.

use crate::scope::ScopeGrant;
use crate::CapabilityError;
use std::collections::HashSet;

/// One patch operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PatchOp {
    /// Full replacement contents for the path.
    Write(Vec<u8>),
    /// Remove the regular file at the path.
    Delete,
}

/// One entry in an `apply_change` batch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PatchHunk {
    /// Relative path.
    pub path: String,
    /// Operation.
    pub op: PatchOp,
}

impl PatchHunk {
    /// A full-file write.
    #[must_use]
    pub fn write(path: impl Into<String>, contents: Vec<u8>) -> Self {
        Self {
            path: path.into(),
            op: PatchOp::Write(contents),
        }
    }

    /// A file deletion.
    #[must_use]
    pub fn delete(path: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            op: PatchOp::Delete,
        }
    }
}

/// Validate a whole batch before any mutation and return the normalized
/// paths, one per patch in order.
///
/// Scope covers deletes exactly like writes. Delete targets must exist:
/// `exists` reports whether a regular file currently backs a normalized path,
/// and the batch is simulated in order, so a write earlier in the batch
/// satisfies a later delete of the same path while an earlier delete
/// invalidates it.
///
/// # Errors
///
/// Returns `OUT_OF_SCOPE` for any path outside the grant and `PATH_ABSENT`
/// for a delete whose target would not exist; either error means nothing was
/// mutated.
pub fn validate_batch(
    grant: &ScopeGrant,
    patches: &[PatchHunk],
    exists: impl Fn(&str) -> bool,
) -> Result<Vec<String>, CapabilityError> {
    let mut normalized = Vec::with_capacity(patches.len());
    let mut created: HashSet<String> = HashSet::new();
    let mut deleted: HashSet<String> = HashSet::new();
    for patch in patches {
        let path = grant.check(&patch.path)?;
        match &patch.op {
            PatchOp::Write(_) => {
                deleted.remove(&path);
                created.insert(path.clone());
            }
            PatchOp::Delete => {
                let present =
                    created.contains(&path) || (!deleted.contains(&path) && exists(&path));
                if !present {
                    return Err(CapabilityError::PathAbsent(path));
                }
                created.remove(&path);
                deleted.insert(path.clone());
            }
        }
        normalized.push(path);
    }
    Ok(normalized)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> ScopeGrant {
        ScopeGrant::new(&["src".into()]).expect("grant")
    }

    #[test]
    fn delete_of_absent_path_is_typed_and_named() {
        let err = validate_batch(&grant(), &[PatchHunk::delete("src/ghost.rs")], |_| false)
            .expect_err("refused");
        assert_eq!(err.reason_code(), "PATH_ABSENT");
        assert!(err.to_string().contains("src/ghost.rs"));
    }

    #[test]
    fn delete_is_scope_checked_like_a_write() {
        let err = validate_batch(&grant(), &[PatchHunk::delete("README.md")], |_| true)
            .expect_err("refused");
        assert_eq!(err.reason_code(), "OUT_OF_SCOPE");
    }

    #[test]
    fn batch_simulation_orders_writes_and_deletes() {
        let ok = validate_batch(
            &grant(),
            &[
                PatchHunk::write("src/new.rs", b"x".to_vec()),
                PatchHunk::delete("src/new.rs"),
            ],
            |_| false,
        )
        .expect("write satisfies later delete");
        assert_eq!(ok, vec!["src/new.rs".to_string(), "src/new.rs".to_string()]);

        let err = validate_batch(
            &grant(),
            &[
                PatchHunk::delete("src/lib.rs"),
                PatchHunk::delete("src/lib.rs"),
            ],
            |path| path == "src/lib.rs",
        )
        .expect_err("second delete has no target");
        assert_eq!(err.reason_code(), "PATH_ABSENT");

        validate_batch(
            &grant(),
            &[
                PatchHunk::delete("src/lib.rs"),
                PatchHunk::write("src/lib.rs", b"y".to_vec()),
                PatchHunk::delete("src/lib.rs"),
            ],
            |path| path == "src/lib.rs",
        )
        .expect("recreate then delete");
    }
}
