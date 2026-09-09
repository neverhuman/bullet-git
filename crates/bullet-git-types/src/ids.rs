//! Typed identifiers. Display names, paths, and PIDs are never identifiers.

use crate::{Digest, TypesError};
use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};

const ID_HEX_LEN: usize = 64;

macro_rules! typed_id {
    ($name:ident, $prefix:literal) => {
        #[doc = concat!("Typed `", $prefix, "` identifier.")]
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl $name {
            /// Deterministic id from a seed. Production callers use unique seeds.
            #[must_use]
            pub fn from_seed(seed: &str) -> Self {
                let digest = Digest::of(format!("{}:{}", $prefix, seed).as_bytes());
                Self(format!("{}_{}", $prefix, digest.to_hex()))
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
                if !raw.starts_with(expected) || raw.len() != expected.len() + ID_HEX_LEN {
                    return Err(TypesError::InvalidId(raw.to_string()));
                }
                let body = &raw[expected.len()..];
                if !is_lower_hex(body, ID_HEX_LEN) {
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

        impl TryFrom<String> for $name {
            type Error = TypesError;

            fn try_from(raw: String) -> Result<Self, Self::Error> {
                Self::parse(raw)
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> Self {
                id.0
            }
        }
    };
}

typed_id!(ChangeId, "chg");
typed_id!(CandidateId, "can");
typed_id!(CheckpointId, "ckp");
typed_id!(AttemptId, "atm");
typed_id!(ContentId, "cnt");
typed_id!(GateId, "gat");
typed_id!(RepositoryId, "rep");
typed_id!(WorkPackageId, "wpk");
typed_id!(VariantId, "var");
typed_id!(PlanRevisionId, "pln");
typed_id!(GraphRevisionId, "grf");

impl CandidateId {
    /// Provenance-bound identity from the canonical Candidate manifest digest.
    #[must_use]
    pub fn from_digest(digest: Digest) -> Self {
        Self(format!("can_{}", digest.to_hex()))
    }
}

impl ContentId {
    /// Reusable content identity from a canonical content-manifest digest.
    #[must_use]
    pub fn from_digest(digest: Digest) -> Self {
        Self(format!("cnt_{}", digest.to_hex()))
    }
}

/// Git object hashing algorithm carried by a canonical [`GitOid`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum GitOidAlgorithm {
    /// SHA-1 object format.
    Sha1,
    /// SHA-256 object format.
    Sha256,
}

impl GitOidAlgorithm {
    /// Canonical wire tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    const fn hex_len(self) -> usize {
        match self {
            Self::Sha1 => 40,
            Self::Sha256 => 64,
        }
    }
}

/// Exported ordinary Git object id with an explicit hashing algorithm.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct GitOid(String);

impl GitOid {
    /// Validate `sha1:<40 lowercase hex>` or `sha256:<64 lowercase hex>`.
    ///
    /// # Errors
    ///
    /// Returns `TypesError::InvalidOid` unless the input is canonical and
    /// algorithm-tagged.
    pub fn new(raw: impl Into<String>) -> Result<Self, TypesError> {
        let raw = raw.into();
        let Some((tag, hex)) = raw.split_once(':') else {
            return Err(TypesError::InvalidOid(raw));
        };
        let algorithm = match tag {
            "sha1" => GitOidAlgorithm::Sha1,
            "sha256" => GitOidAlgorithm::Sha256,
            _ => return Err(TypesError::InvalidOid(raw)),
        };
        if !is_lower_hex(hex, algorithm.hex_len()) {
            return Err(TypesError::InvalidOid(raw));
        }
        Ok(Self(raw))
    }

    /// Tag validated native Git output with its repository algorithm.
    ///
    /// # Errors
    ///
    /// Returns `TypesError::InvalidOid` when `hex` is not the algorithm's
    /// exact lowercase width.
    pub fn from_hex(
        algorithm: GitOidAlgorithm,
        hex: impl Into<String>,
    ) -> Result<Self, TypesError> {
        let hex = hex.into();
        if !is_lower_hex(&hex, algorithm.hex_len()) {
            return Err(TypesError::InvalidOid(hex));
        }
        Ok(Self(format!("{}:{hex}", algorithm.as_str())))
    }

    /// Borrow the canonical tagged string.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Hash algorithm bound by this identifier.
    #[must_use]
    pub fn algorithm(&self) -> GitOidAlgorithm {
        if self.0.starts_with("sha1:") {
            GitOidAlgorithm::Sha1
        } else {
            GitOidAlgorithm::Sha256
        }
    }

    /// Borrow the native hexadecimal object name for Git argv only.
    #[must_use]
    pub fn hex(&self) -> &str {
        self.0
            .split_once(':')
            .expect("validated GitOid always has an algorithm tag")
            .1
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

fn is_lower_hex(value: &str, expected_len: usize) -> bool {
    value.len() == expected_len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn typed_id_deserialization_is_validated() {
        let id = ChangeId::from_seed("auth");
        let json = serde_json::to_string(&id).expect("serialize");
        let back: ChangeId = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, id);
        assert!(serde_json::from_str::<ChangeId>("\"nope\"").is_err());
        let wrong_prefix = format!("\"chg_{}\"", "0".repeat(64));
        assert!(serde_json::from_str::<CandidateId>(&wrong_prefix).is_err());
        assert!(serde_json::from_str::<ChangeId>(r#"{"id":"chg_00","unknown":true}"#).is_err());
    }

    #[test]
    fn parse_accepts_seeded_ids_and_rejects_malformed() {
        let id = ChangeId::from_seed("auth");
        assert_eq!(ChangeId::parse(id.as_str()).expect("round trip"), id);
        for bad in [
            "",
            "chg_",
            "can_abc",
            "chg_zz",
            &format!("chg_{}", "0".repeat(32)),
            &format!("chg_{}", "A".repeat(64)),
            &format!("can_{}", "0".repeat(64)),
        ] {
            assert!(ChangeId::parse(bad).is_err(), "accepted {bad:?}");
        }
        assert!(CandidateId::parse(format!("can_{}", "0".repeat(64))).is_ok());
        assert_eq!(
            ChangeId::parse("nope").expect_err("reject").reason_code(),
            "INVALID_ID"
        );
    }

    #[test]
    fn exact_identifier_json_goldens_are_full_width() {
        const CHANGE: &str =
            "\"chg_0000000000000000000000000000000000000000000000000000000000000000\"";
        const CANDIDATE: &str =
            "\"can_1111111111111111111111111111111111111111111111111111111111111111\"";
        const CHECKPOINT: &str =
            "\"ckp_2222222222222222222222222222222222222222222222222222222222222222\"";
        assert_eq!(
            serde_json::to_string(&serde_json::from_str::<ChangeId>(CHANGE).unwrap()).unwrap(),
            CHANGE
        );
        assert_eq!(
            serde_json::to_string(&serde_json::from_str::<CandidateId>(CANDIDATE).unwrap())
                .unwrap(),
            CANDIDATE
        );
        assert_eq!(
            serde_json::to_string(&serde_json::from_str::<CheckpointId>(CHECKPOINT).unwrap())
                .unwrap(),
            CHECKPOINT
        );
    }

    #[test]
    fn git_oid_requires_a_known_algorithm_and_exact_lowercase_hex() {
        let sha1 = "sha1:d6d3b35c8e418f44db2264c04548dafd009a934a";
        let sha256 = "sha256:abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd";
        let oid1 = GitOid::new(sha1).expect("sha1");
        let oid256 = GitOid::new(sha256).expect("sha256");
        assert_eq!(oid1.algorithm(), GitOidAlgorithm::Sha1);
        assert_eq!(oid1.hex(), &sha1[5..]);
        assert_eq!(oid256.algorithm(), GitOidAlgorithm::Sha256);
        assert_eq!(oid256.hex(), &sha256[7..]);
        for bad in ["", "abc", "git-x", &sha1[5..], "sha512:abcd"] {
            assert!(GitOid::new(bad).is_err(), "accepted {bad:?}");
        }
        assert!(GitOid::new(sha1.to_uppercase()).is_err());
        assert!(GitOid::new(format!("{sha1}0")).is_err());
        assert!(GitOid::new(format!("sha256:{}", "a".repeat(40))).is_err());
        assert!(GitOid::from_hex(GitOidAlgorithm::Sha1, "A".repeat(40)).is_err());
        for (text, oid) in [(sha1, oid1), (sha256, oid256)] {
            let json = format!("\"{text}\"");
            let decoded: GitOid = serde_json::from_str(&json).expect("deserialize");
            assert_eq!(decoded, oid);
            assert_eq!(serde_json::to_string(&decoded).expect("serialize"), json);
        }
        assert!(serde_json::from_str::<GitOid>("\"short\"").is_err());
        assert!(serde_json::from_str::<GitOid>(r#"{"oid":"sha1:00","unknown":true}"#).is_err());
    }

    #[test]
    fn candidate_and_content_ids_are_distinct_digest_addresses() {
        let digest = Digest::of(b"same digest bytes");
        let candidate = CandidateId::from_digest(digest);
        let content = ContentId::from_digest(digest);
        assert_eq!(&candidate.as_str()[4..], &content.as_str()[4..]);
        assert_ne!(candidate.as_str(), content.as_str());
        assert!(CandidateId::parse(candidate.as_str()).is_ok());
        assert!(ContentId::parse(content.as_str()).is_ok());
    }
}
