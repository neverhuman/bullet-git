//! Typed identifiers. Display names, paths, and PIDs are never identifiers.

use crate::{framed_digest, Digest, TypesError};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

macro_rules! typed_id {
    ($name:ident, $prefix:literal) => {
        #[doc = concat!("Typed `", $prefix, "` identifier.")]
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
        pub struct $name(String);

        impl $name {
            /// Deterministic id from a seed. Production callers use unique seeds.
            #[must_use]
            pub fn from_seed(seed: &str) -> Self {
                let digest = Digest::of(format!("{}:{}", $prefix, seed).as_bytes());
                Self(format!("{}_{}", $prefix, &digest.to_hex()[..32]))
            }

            /// Parse a prefixed hex id.
            ///
            /// # Errors
            ///
            /// Returns `TypesError::InvalidId` when the prefix, length, or hex
            /// body is wrong.
            pub fn parse(raw: impl AsRef<str>) -> Result<Self, TypesError> {
                let raw = raw.as_ref();
                let expected = concat!($prefix, "_");
                if !raw.starts_with(expected) || raw.len() != expected.len() + 32 {
                    return Err(TypesError::InvalidId(raw.to_string()));
                }
                let body = &raw[expected.len()..];
                if !body.chars().all(|c| c.is_ascii_hexdigit()) {
                    return Err(TypesError::InvalidId(raw.to_string()));
                }
                Ok(Self(raw.to_string()))
            }

            /// Borrow the prefixed string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
                f.write_str(&self.0)
            }
        }
    };
}

typed_id!(ChangeId, "chg");
typed_id!(CandidateId, "can");
typed_id!(CheckpointId, "ckp");

impl CandidateId {
    /// Content-derived identity: the exact change, tree, and head commit.
    ///
    /// Two different trees under one Change always produce different ids;
    /// identical content produces the identical id.
    #[must_use]
    pub fn from_content(change: &ChangeId, tree: &GitOid, head: &GitOid) -> Self {
        let digest = framed_digest(&[
            b"candidate.v1",
            change.as_str().as_bytes(),
            tree.as_str().as_bytes(),
            head.as_str().as_bytes(),
        ]);
        Self(format!("can_{}", &digest.to_hex()[..32]))
    }
}

/// Exported ordinary Git object id: exactly 40 lowercase hex characters.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct GitOid(String);

impl GitOid {
    /// Validate and wrap a 40-hex object id.
    ///
    /// # Errors
    ///
    /// Returns `TypesError::InvalidOid` unless the input is exactly 40
    /// lowercase hex characters.
    pub fn new(raw: impl Into<String>) -> Result<Self, TypesError> {
        let raw = raw.into();
        let valid = raw.len() == 40
            && raw
                .chars()
                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase());
        if valid {
            Ok(Self(raw))
        } else {
            Err(TypesError::InvalidOid(raw))
        }
    }

    /// Borrow the hex string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for GitOid {
    type Error = TypesError;

    fn try_from(raw: String) -> Result<Self, Self::Error> {
        Self::new(raw)
    }
}

impl From<GitOid> for String {
    fn from(oid: GitOid) -> Self {
        oid.0
    }
}

impl Display for GitOid {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_seeded_ids_and_rejects_malformed() {
        let id = ChangeId::from_seed("auth");
        assert_eq!(ChangeId::parse(id.as_str()).expect("round trip"), id);
        for bad in [
            "",
            "chg_",
            "can_abc",
            "chg_zz",
            &format!("can_{}", "0".repeat(32)),
        ] {
            assert!(ChangeId::parse(bad).is_err(), "accepted {bad:?}");
        }
        assert!(CandidateId::parse(format!("can_{}", "0".repeat(32))).is_ok());
        assert_eq!(
            ChangeId::parse("nope").expect_err("reject").reason_code(),
            "INVALID_ID"
        );
    }

    #[test]
    fn git_oid_requires_forty_lowercase_hex() {
        let good = "d6d3b35c8e418f44db2264c04548dafd009a934a";
        assert_eq!(GitOid::new(good).expect("valid").as_str(), good);
        for bad in ["", "abc", "git-x"] {
            assert!(GitOid::new(bad).is_err(), "accepted {bad:?}");
        }
        assert!(GitOid::new(good.to_uppercase()).is_err());
        assert!(GitOid::new(format!("{good}0")).is_err());
        let json = format!("\"{good}\"");
        let oid: GitOid = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(serde_json::to_string(&oid).expect("serialize"), json);
        assert!(serde_json::from_str::<GitOid>("\"short\"").is_err());
    }

    #[test]
    fn candidate_id_is_content_derived() {
        let change = ChangeId::from_seed("c");
        let tree_a = GitOid::new("a".repeat(40)).expect("oid");
        let tree_b = GitOid::new("b".repeat(40)).expect("oid");
        let head = GitOid::new("c".repeat(40)).expect("oid");
        let one = CandidateId::from_content(&change, &tree_a, &head);
        let two = CandidateId::from_content(&change, &tree_b, &head);
        assert_ne!(one, two);
        assert_eq!(one, CandidateId::from_content(&change, &tree_a, &head));
        assert!(CandidateId::parse(one.as_str()).is_ok());
    }
}
