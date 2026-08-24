//! Scope grants: normalized path prefixes that bound every write.

use crate::CapabilityError;
use serde::{Deserialize, Serialize};
use unicode_normalization::UnicodeNormalization;

/// Normalize a repository-relative path.
///
/// NFC-normalizes Unicode and rejects absolute paths, backslashes, NUL bytes,
/// empty/`.`/`..` segments, any segment named `.git`, Windows alternate-data
/// stream syntax, and trailing dots/spaces. The result contains no escapes.
///
/// # Errors
///
/// Returns `OUT_OF_SCOPE` naming the offending path.
pub fn normalize_rel_path(raw: &str) -> Result<String, CapabilityError> {
    let normalized = raw.nfc().collect::<String>();
    if normalized.is_empty()
        || normalized.starts_with('/')
        || normalized.contains('\\')
        || normalized.contains('\0')
    {
        return Err(CapabilityError::OutOfScope(raw.to_string()));
    }
    let mut parts: Vec<&str> = Vec::new();
    for segment in normalized.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(CapabilityError::OutOfScope(raw.to_string()));
        }
        if segment.eq_ignore_ascii_case(".git")
            || segment.contains(':')
            || segment.ends_with(['.', ' '])
        {
            return Err(CapabilityError::OutOfScope(raw.to_string()));
        }
        parts.push(segment);
    }
    Ok(parts.join("/"))
}

/// Granted write scope: normalized relative path prefixes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScopeGrant {
    /// Normalized prefixes; a path is permitted when one prefix covers it.
    pub allowed_prefixes: Vec<String>,
}

impl ScopeGrant {
    /// Build a grant from raw prefixes, normalizing each.
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_SCOPE` when a prefix fails normalization.
    pub fn new(prefixes: &[String]) -> Result<Self, CapabilityError> {
        let mut allowed_prefixes = Vec::with_capacity(prefixes.len());
        for prefix in prefixes {
            let trimmed = prefix.strip_suffix('/').unwrap_or(prefix);
            allowed_prefixes.push(normalize_rel_path(trimmed)?);
        }
        Ok(Self { allowed_prefixes })
    }

    /// Whether an already-normalized path is covered by the grant.
    ///
    /// Coverage is segment-wise: prefix `src` covers `src/lib.rs` but never
    /// `src2/lib.rs`.
    #[must_use]
    pub fn permits(&self, normalized_path: &str) -> bool {
        let path_segments: Vec<&str> = normalized_path.split('/').collect();
        self.allowed_prefixes.iter().any(|prefix| {
            let prefix_segments: Vec<&str> = prefix.split('/').collect();
            prefix_segments.len() <= path_segments.len()
                && prefix_segments
                    .iter()
                    .zip(&path_segments)
                    .all(|(a, b)| a == b)
        })
    }

    /// Normalize a raw path and check coverage in one step.
    ///
    /// # Errors
    ///
    /// Returns `OUT_OF_SCOPE` naming the path when normalization fails or the
    /// grant does not cover it.
    pub fn check(&self, raw: &str) -> Result<String, CapabilityError> {
        let normalized = normalize_rel_path(raw)?;
        if self.permits(&normalized) {
            Ok(normalized)
        } else {
            Err(CapabilityError::OutOfScope(raw.to_string()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalization_rejects_escapes() {
        for bad in [
            "",
            "/etc/passwd",
            "../up",
            "src/../up",
            "src/./x",
            "src//x",
            ".git/hooks/pre-commit",
            "src/.git/config",
            "src\\win",
            "src/file:stream",
            "src/file.",
            "src/file ",
            "a\0b",
        ] {
            assert!(normalize_rel_path(bad).is_err(), "accepted {bad:?}");
        }
        assert_eq!(normalize_rel_path("src/lib.rs").expect("ok"), "src/lib.rs");
        assert_eq!(
            normalize_rel_path("src/cafe\u{301}.rs").expect("NFC"),
            "src/caf\u{e9}.rs"
        );
    }

    #[test]
    fn coverage_is_segment_wise() {
        let grant = ScopeGrant::new(&["src".into(), "docs/api".into()]).expect("grant");
        assert!(grant.permits("src/lib.rs"));
        assert!(grant.permits("src"));
        assert!(grant.permits("docs/api/index.md"));
        assert!(!grant.permits("src2/lib.rs"));
        assert!(!grant.permits("docs/other.md"));
        assert!(!grant.permits("README.md"));
    }

    #[test]
    fn empty_grant_permits_nothing() {
        let grant = ScopeGrant::new(&[]).expect("grant");
        assert!(!grant.permits("src/lib.rs"));
        let err = grant.check("src/lib.rs").expect_err("refused");
        assert_eq!(err.reason_code(), "OUT_OF_SCOPE");
        assert_eq!(err.to_string(), "path out of scope: src/lib.rs");
    }
}
