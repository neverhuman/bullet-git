//! Patch batch shapes and pre-mutation validation shared by every writer.

use crate::scope::ScopeGrant;
use crate::CapabilityError;
pub use bullet_git_types::{MAX_AGGREGATE_CONTENT_BYTES, MAX_CONTENT_BYTES, MAX_PATCH_OPERATIONS};
use std::collections::{HashMap, HashSet};

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
/// `exists` reports whether a regular file currently backs a normalized path.
/// Every normalized path may appear only once; multi-operation sequences must
/// be collapsed by the proposal producer before admission.
///
/// # Errors
///
/// Returns `OUT_OF_SCOPE` for any path outside the grant, `DUPLICATE_PATH`
/// for repeated/conflicting paths, and `PATH_ABSENT` for a delete whose target
/// does not exist; any error means nothing was mutated.
pub fn validate_batch(
    grant: &ScopeGrant,
    patches: &[PatchHunk],
    exists: impl Fn(&str) -> bool,
) -> Result<Vec<String>, CapabilityError> {
    if patches.is_empty() || patches.len() > MAX_PATCH_OPERATIONS {
        return Err(CapabilityError::InvalidOperationCount {
            max: MAX_PATCH_OPERATIONS,
            actual: patches.len(),
        });
    }
    let mut normalized = Vec::with_capacity(patches.len());
    let mut seen: HashSet<String> = HashSet::new();
    let mut portable: HashMap<String, String> = HashMap::new();
    let mut aggregate_content_bytes = 0_usize;
    for patch in patches {
        let path = grant.check(&patch.path)?;
        if let PatchOp::Write(contents) = &patch.op {
            if contents.len() > MAX_CONTENT_BYTES {
                return Err(CapabilityError::ContentTooLarge {
                    path,
                    max: MAX_CONTENT_BYTES,
                    actual: contents.len(),
                });
            }
            aggregate_content_bytes = aggregate_content_bytes.checked_add(contents.len()).ok_or(
                CapabilityError::AggregateContentTooLarge {
                    max: MAX_AGGREGATE_CONTENT_BYTES,
                    actual: usize::MAX,
                },
            )?;
            if aggregate_content_bytes > MAX_AGGREGATE_CONTENT_BYTES {
                return Err(CapabilityError::AggregateContentTooLarge {
                    max: MAX_AGGREGATE_CONTENT_BYTES,
                    actual: aggregate_content_bytes,
                });
            }
        }
        if !seen.insert(path.clone()) {
            return Err(CapabilityError::DuplicatePath(path));
        }
        let portable_key = path
            .chars()
            .flat_map(char::to_lowercase)
            .collect::<String>();
        if let Some(first) = portable.insert(portable_key, path.clone()) {
            return Err(CapabilityError::PathCollision {
                first,
                second: path,
            });
        }
        if matches!(patch.op, PatchOp::Delete) && !exists(&path) {
            return Err(CapabilityError::PathAbsent(path));
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
    fn duplicate_and_conflicting_paths_are_typed_and_named() {
        for patches in [
            vec![
                PatchHunk::write("src/new.rs", b"x".to_vec()),
                PatchHunk::write("src/new.rs", b"y".to_vec()),
            ],
            vec![
                PatchHunk::write("src/new.rs", b"x".to_vec()),
                PatchHunk::delete("src/new.rs"),
            ],
        ] {
            let err = validate_batch(&grant(), &patches, |_| true).expect_err("duplicate refused");
            assert_eq!(err.reason_code(), "DUPLICATE_PATH");
            assert!(err.to_string().contains("src/new.rs"));
        }

        let equivalent = vec![
            PatchHunk::write("src/caf\u{e9}.rs", b"x".to_vec()),
            PatchHunk::write("src/cafe\u{301}.rs", b"y".to_vec()),
        ];
        let err = validate_batch(&grant(), &equivalent, |_| false).expect_err("NFC duplicate");
        assert_eq!(err.reason_code(), "DUPLICATE_PATH");

        let case_collision = vec![
            PatchHunk::write("src/Name.rs", b"x".to_vec()),
            PatchHunk::write("src/name.rs", b"y".to_vec()),
        ];
        let err = validate_batch(&grant(), &case_collision, |_| false).expect_err("case collision");
        assert_eq!(err.reason_code(), "PATH_COLLISION");
    }

    #[test]
    fn empty_oversized_and_overlong_batches_are_refused() {
        let empty = validate_batch(&grant(), &[], |_| false).expect_err("empty refused");
        assert_eq!(empty.reason_code(), "INVALID_OPERATION_COUNT");

        let too_many = vec![PatchHunk::write("src/x.rs", vec![]); MAX_PATCH_OPERATIONS + 1];
        let error = validate_batch(&grant(), &too_many, |_| false).expect_err("count refused");
        assert_eq!(error.reason_code(), "INVALID_OPERATION_COUNT");

        let error = validate_batch(
            &grant(),
            &[PatchHunk::write(
                "src/huge.rs",
                vec![0; MAX_CONTENT_BYTES + 1],
            )],
            |_| false,
        )
        .expect_err("content refused");
        assert_eq!(error.reason_code(), "CONTENT_TOO_LARGE");
        assert!(error.to_string().contains("src/huge.rs"));
    }

    #[test]
    fn exact_path_and_aggregate_content_bounds_are_admitted() {
        let patches = (0..MAX_PATCH_OPERATIONS)
            .map(|index| PatchHunk::write(format!("src/{index}.rs"), Vec::new()))
            .collect::<Vec<_>>();
        assert_eq!(
            validate_batch(&grant(), &patches, |_| false).expect("exact path bound"),
            (0..MAX_PATCH_OPERATIONS)
                .map(|index| format!("src/{index}.rs"))
                .collect::<Vec<_>>()
        );

        let patches = (0..(MAX_AGGREGATE_CONTENT_BYTES / MAX_CONTENT_BYTES))
            .map(|index| {
                PatchHunk::write(
                    format!("src/aggregate-{index}.bin"),
                    vec![0; MAX_CONTENT_BYTES],
                )
            })
            .collect::<Vec<_>>();
        validate_batch(&grant(), &patches, |_| false).expect("exact aggregate bound");
    }

    #[test]
    fn aggregate_content_over_bound_is_typed() {
        let full_files = MAX_AGGREGATE_CONTENT_BYTES / MAX_CONTENT_BYTES;
        let mut patches = (0..full_files)
            .map(|index| {
                PatchHunk::write(
                    format!("src/aggregate-{index}.bin"),
                    vec![0; MAX_CONTENT_BYTES],
                )
            })
            .collect::<Vec<_>>();
        patches.push(PatchHunk::write("src/one-byte-over.bin", vec![0]));

        let error = validate_batch(&grant(), &patches, |_| false).expect_err("aggregate refused");
        assert_eq!(error.reason_code(), "AGGREGATE_CONTENT_TOO_LARGE");
        assert!(error
            .to_string()
            .contains(&(MAX_AGGREGATE_CONTENT_BYTES + 1).to_string()));
    }
}
