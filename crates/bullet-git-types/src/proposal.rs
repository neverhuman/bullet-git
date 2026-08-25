//! Canonical schema-1 patch proposal consumed by the repository writer.

use crate::{AttemptId, CheckpointId, ContentId, Digest, GateId};
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;
use thiserror::Error;
use unicode_normalization::UnicodeNormalization;

/// Frozen pure proposal schema version.
pub const PATCH_PROPOSAL_SCHEMA_VERSION: u32 = 1;
/// Maximum operations admitted in one proposal.
pub const MAX_PATCH_OPERATIONS: usize = 128;
/// Maximum UTF-8 bytes admitted in one replacement body.
pub const MAX_CONTENT_BYTES: usize = 1_048_576;
/// Maximum UTF-8 bytes admitted across all replacement bodies.
pub const MAX_AGGREGATE_CONTENT_BYTES: usize = 32 * 1_048_576;

/// Canonical repository-relative path.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RepoPath(String);

impl RepoPath {
    /// Borrow the validated path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn collision_key(&self) -> String {
        self.0.nfc().flat_map(char::to_lowercase).collect()
    }
}

impl FromStr for RepoPath {
    type Err = ProposalError;

    fn from_str(raw: &str) -> Result<Self, Self::Err> {
        validate_repo_path(raw)?;
        Ok(Self(raw.to_owned()))
    }
}

impl fmt::Display for RepoPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for RepoPath {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RepoPath {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(de::Error::custom)
    }
}

/// Expected bytes at one proposal path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Preimage {
    /// No filesystem entry may exist.
    Absent,
    /// A regular file with the exact BLAKE3 digest must exist.
    Digest { digest: Digest },
}

/// Requested full-file mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum PatchMutation {
    /// Replace or create a UTF-8 file.
    Write { content_utf8: String },
    /// Delete an existing regular file.
    Delete,
}

/// One exact preconditioned mutation.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchOperation {
    /// Canonical repository-relative path.
    pub path: RepoPath,
    /// Expected current state.
    pub preimage: Preimage,
    /// Requested next state.
    pub mutation: PatchMutation,
}

/// Canonical schema-1 provider patch proposal.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PatchProposal {
    /// Must equal [`PATCH_PROPOSAL_SCHEMA_VERSION`].
    pub schema_version: u32,
    /// Exact content subject assigned by the proposal producer.
    pub proposal_id: ContentId,
    /// Attempt that produced the proposal.
    pub producing_attempt_id: AttemptId,
    /// Active checkpoint required before application.
    pub base_checkpoint_id: CheckpointId,
    /// Full active checkpoint digest required before application.
    pub base_checkpoint_digest: Digest,
    /// Atomic preconditioned mutations.
    pub operations: Vec<PatchOperation>,
    /// Admitted gate identifiers; never shell text.
    pub gate_ids: Vec<GateId>,
}

impl PatchProposal {
    /// Validate semantic bounds and whole-batch conflicts.
    ///
    /// # Errors
    ///
    /// Returns a typed refusal without changing repository state.
    pub fn validate(&self) -> Result<(), ProposalError> {
        if self.schema_version != PATCH_PROPOSAL_SCHEMA_VERSION {
            return Err(ProposalError::UnsupportedSchema(self.schema_version));
        }
        if self.operations.is_empty() || self.operations.len() > MAX_PATCH_OPERATIONS {
            return Err(ProposalError::InvalidOperationCount(self.operations.len()));
        }
        if self.gate_ids.is_empty() {
            return Err(ProposalError::GateRequired);
        }
        let mut gates = self.gate_ids.iter().collect::<Vec<_>>();
        gates.sort_unstable();
        if gates.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(ProposalError::DuplicateGate);
        }

        let mut paths = BTreeMap::new();
        let mut aggregate_content_bytes = 0_usize;
        for operation in &self.operations {
            if let PatchMutation::Write { content_utf8 } = &operation.mutation {
                if content_utf8.len() > MAX_CONTENT_BYTES {
                    return Err(ProposalError::ContentTooLarge(operation.path.to_string()));
                }
                aggregate_content_bytes =
                    aggregate_content_bytes
                        .checked_add(content_utf8.len())
                        .ok_or(ProposalError::AggregateContentTooLarge(usize::MAX))?;
                if aggregate_content_bytes > MAX_AGGREGATE_CONTENT_BYTES {
                    return Err(ProposalError::AggregateContentTooLarge(
                        aggregate_content_bytes,
                    ));
                }
            }
            if matches!(operation.mutation, PatchMutation::Delete)
                && matches!(operation.preimage, Preimage::Absent)
            {
                return Err(ProposalError::MissingPreimage(operation.path.to_string()));
            }
            if let Some(existing) =
                paths.insert(operation.path.collision_key(), operation.path.as_str())
            {
                return Err(ProposalError::PathCollision {
                    first: existing.to_owned(),
                    second: operation.path.to_string(),
                });
            }
        }
        for (index, (left_key, left)) in paths.iter().enumerate() {
            for (right_key, right) in paths.iter().skip(index + 1) {
                if contains_path(left_key, right_key) || contains_path(right_key, left_key) {
                    return Err(ProposalError::PathConflict {
                        first: (*left).to_owned(),
                        second: (*right).to_owned(),
                    });
                }
            }
        }
        Ok(())
    }
}

/// Typed proposal validation failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProposalError {
    /// The schema version is not supported.
    #[error("PatchProposal schema {0} is unsupported")]
    UnsupportedSchema(u32),
    /// Operations were empty or over the fixed bound.
    #[error("operations must contain 1..={MAX_PATCH_OPERATIONS} entries, got {0}")]
    InvalidOperationCount(usize),
    /// No admitted gates were provided.
    #[error("PatchProposal must reference at least one admitted gate")]
    GateRequired,
    /// One gate was repeated.
    #[error("PatchProposal repeats an admitted gate ID")]
    DuplicateGate,
    /// One write exceeded the fixed bound.
    #[error("patch contents too large at {0}")]
    ContentTooLarge(String),
    /// The sum of all replacement bodies exceeded the fixed bound.
    #[error("aggregate patch contents too large: {0} bytes exceeds {MAX_AGGREGATE_CONTENT_BYTES}")]
    AggregateContentTooLarge(usize),
    /// A delete claimed an absent preimage.
    #[error("delete requires an existing preimage at {0}")]
    MissingPreimage(String),
    /// Two paths collide under portable case folding.
    #[error("portable path collision: {first} conflicts with {second}")]
    PathCollision { first: String, second: String },
    /// One operation contains another operation's path.
    #[error("conflicting patch paths: {first} conflicts with {second}")]
    PathConflict { first: String, second: String },
    /// A path violates the cross-platform repository rules.
    #[error("invalid repository path {path:?}: {reason}")]
    InvalidRepoPath { path: String, reason: &'static str },
}

impl ProposalError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::UnsupportedSchema(_) => "UNSUPPORTED_SCHEMA",
            Self::InvalidOperationCount(_) => "INVALID_OPERATION_COUNT",
            Self::GateRequired => "GATE_REQUIRED",
            Self::DuplicateGate => "DUPLICATE_GATE",
            Self::ContentTooLarge(_) => "CONTENT_TOO_LARGE",
            Self::AggregateContentTooLarge(_) => "AGGREGATE_CONTENT_TOO_LARGE",
            Self::MissingPreimage(_) => "MISSING_PREIMAGE",
            Self::PathCollision { .. } => "PATH_COLLISION",
            Self::PathConflict { .. } => "PATH_CONFLICT",
            Self::InvalidRepoPath { .. } => "INVALID_REPO_PATH",
        }
    }
}

fn validate_repo_path(raw: &str) -> Result<(), ProposalError> {
    let invalid = |reason| ProposalError::InvalidRepoPath {
        path: raw.to_owned(),
        reason,
    };
    if raw.is_empty() || raw.len() > 4_096 || raw.starts_with('/') || raw.contains('\\') {
        return Err(invalid(
            "path must be a non-empty repository-relative UTF-8 path",
        ));
    }
    if raw.nfc().collect::<String>() != raw {
        return Err(invalid("path must already be NFC normalized"));
    }
    for segment in raw.split('/') {
        if segment.is_empty() || matches!(segment, "." | "..") {
            return Err(invalid("empty and dot segments are forbidden"));
        }
        if segment.eq_ignore_ascii_case(".git") {
            return Err(invalid(".git is outside proposal authority"));
        }
        if segment.contains(':')
            || segment.ends_with('.')
            || segment.ends_with(' ')
            || segment.chars().any(char::is_control)
        {
            return Err(invalid("path contains a platform-unsafe component"));
        }
    }
    Ok(())
}

fn contains_path(parent: &str, child: &str) -> bool {
    child
        .strip_prefix(parent)
        .is_some_and(|suffix| suffix.starts_with('/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proposal(operations: Vec<PatchOperation>) -> PatchProposal {
        PatchProposal {
            schema_version: PATCH_PROPOSAL_SCHEMA_VERSION,
            proposal_id: ContentId::from_seed("proposal"),
            producing_attempt_id: AttemptId::from_seed("attempt"),
            base_checkpoint_id: CheckpointId::from_seed("checkpoint"),
            base_checkpoint_digest: Digest::of(b"checkpoint"),
            operations,
            gate_ids: vec![GateId::from_seed("gate")],
        }
    }

    fn write(path: &str, preimage: Preimage) -> PatchOperation {
        write_with_content(path, preimage, "next".into())
    }

    fn write_with_content(path: &str, preimage: Preimage, content_utf8: String) -> PatchOperation {
        PatchOperation {
            path: path.parse().expect("path"),
            preimage,
            mutation: PatchMutation::Write { content_utf8 },
        }
    }

    #[test]
    fn canonical_json_shape_round_trips_and_denies_unknown_fields() {
        let expected = serde_json::json!({
            "schema_version": 1,
            "proposal_id": format!("cnt_{}", "1".repeat(64)),
            "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
            "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
            "base_checkpoint_digest": "04".repeat(32),
            "operations": [{
                "path": "PONG.txt",
                "preimage": { "kind": "absent" },
                "mutation": { "kind": "write", "content_utf8": "PONG\n" }
            }],
            "gate_ids": [format!("gat_{}", "5".repeat(64))]
        });
        assert_eq!(expected.as_object().expect("object").len(), 7);

        let proposal = serde_json::from_value::<PatchProposal>(expected.clone()).expect("decode");
        proposal.validate().expect("validate");
        assert_eq!(serde_json::to_value(&proposal).expect("encode"), expected);

        let mut unknown = serde_json::to_value(&proposal).expect("encode");
        unknown["model_comment"] = serde_json::json!("not authoritative");
        assert!(serde_json::from_value::<PatchProposal>(unknown).is_err());
    }

    #[test]
    fn ids_digests_paths_and_semantics_fail_closed() {
        let valid = serde_json::to_value(proposal(vec![write("src/lib.rs", Preimage::Absent)]))
            .expect("encode");
        for (pointer, replacement) in [
            ("/proposal_id", serde_json::json!("cnt_short")),
            ("/producing_attempt_id", serde_json::json!("atm_short")),
            ("/base_checkpoint_id", serde_json::json!("ckp_short")),
            ("/base_checkpoint_digest", serde_json::json!("A".repeat(64))),
            ("/gate_ids/0", serde_json::json!("gat_short")),
            ("/operations/0/path", serde_json::json!("src/../escape")),
        ] {
            let mut bad = valid.clone();
            *bad.pointer_mut(pointer).expect("pointer") = replacement;
            assert!(
                serde_json::from_value::<PatchProposal>(bad).is_err(),
                "accepted malformed {pointer}"
            );
        }

        let mut empty_gates = proposal(vec![write("src/lib.rs", Preimage::Absent)]);
        empty_gates.gate_ids.clear();
        assert_eq!(
            empty_gates
                .validate()
                .expect_err("gate required")
                .reason_code(),
            "GATE_REQUIRED"
        );
        for (parent, child) in [
            ("src", "src/lib.rs"),
            ("Src", "src/lib.rs"),
            ("Étage", "étage/file.rs"),
        ] {
            let conflict = proposal(vec![
                write(parent, Preimage::Absent),
                write(child, Preimage::Absent),
            ]);
            assert_eq!(
                conflict.validate().expect_err("conflict").reason_code(),
                "PATH_CONFLICT",
                "accepted portable ancestor conflict {parent:?} and {child:?}"
            );
        }

        let exact_path_bound = proposal(
            (0..MAX_PATCH_OPERATIONS)
                .map(|index| write(&format!("src/{index}.rs"), Preimage::Absent))
                .collect(),
        );
        exact_path_bound.validate().expect("exact path bound");
        let over_path_bound = proposal(
            (0..=MAX_PATCH_OPERATIONS)
                .map(|index| write(&format!("src/{index}.rs"), Preimage::Absent))
                .collect(),
        );
        assert_eq!(
            over_path_bound
                .validate()
                .expect_err("operation bound")
                .reason_code(),
            "INVALID_OPERATION_COUNT"
        );

        let full_files = MAX_AGGREGATE_CONTENT_BYTES / MAX_CONTENT_BYTES;
        let aggregate_bound = (0..full_files)
            .map(|index| {
                write_with_content(
                    &format!("src/aggregate-{index}.txt"),
                    Preimage::Absent,
                    "x".repeat(MAX_CONTENT_BYTES),
                )
            })
            .collect::<Vec<_>>();
        proposal(aggregate_bound.clone())
            .validate()
            .expect("exact aggregate bound");
        let mut over_aggregate_bound = aggregate_bound;
        over_aggregate_bound.push(write_with_content(
            "src/one-byte-over.txt",
            Preimage::Absent,
            "x".into(),
        ));
        assert_eq!(
            proposal(over_aggregate_bound)
                .validate()
                .expect_err("aggregate bound")
                .reason_code(),
            "AGGREGATE_CONTENT_TOO_LARGE"
        );
    }
}
