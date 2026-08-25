//! MAC-bound disposable fixture permit. Compiled only into `bullet-gitd-fixture`.

use bullet_git_types::framed_digest;
use serde::{Deserialize, Serialize};
use std::io::Write as _;
use std::path::{Path, PathBuf};

const MAC_DOMAIN: &[u8] = b"bullet-gitd.fixture-permit.mac.v1";
const SCHEMA: &str = "v1";
/// Marker written after the first admitted fixture clone.
pub const FIXTURE_GENERATION_MARKER: &str = ".bullet-fixture-generation";

/// Claims covered by one fixture MAC. Field order is part of the contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixturePermitClaims {
    /// Always `v1`.
    pub schema_version: String,
    /// Writer attempt (`atm_` + 64 hex).
    pub attempt_id: String,
    /// Permanent fence.
    pub attempt_fence: u64,
    /// 64-hex workspace nonce.
    pub workspace_nonce_hex: String,
    /// Canonical pre-opened fixture root.
    pub destination: String,
}

/// Signed fixture permit envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FixturePermit {
    /// Exact claims.
    pub claims: FixturePermitClaims,
    /// 64-hex MAC.
    pub mac_hex: String,
}

/// Fixture permit refusal.
#[derive(Debug, thiserror::Error)]
pub enum FixturePermitError {
    #[error("fixture permit refused: {0}")]
    Refused(String),
}

impl FixturePermitError {
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        "AUTHORITY_REFUSED"
    }
}

/// Mint a permit with the same struct serializer the verifier uses.
///
/// # Errors
///
/// Key shape or encoding refusal.
pub fn mint_fixture_permit(
    key: &[u8; 32],
    claims: FixturePermitClaims,
) -> Result<FixturePermit, FixturePermitError> {
    if key.iter().all(|byte| *byte == 0) {
        return Err(FixturePermitError::Refused(
            "fixture MAC key must be 32 nonzero bytes".into(),
        ));
    }
    if claims.schema_version != SCHEMA {
        return Err(FixturePermitError::Refused(
            "schema_version must be v1".into(),
        ));
    }
    let body = serde_json::to_vec(&claims)
        .map_err(|err| FixturePermitError::Refused(format!("encode claims: {err}")))?;
    let mac = framed_digest(&[MAC_DOMAIN, key, &body]);
    Ok(FixturePermit {
        claims,
        mac_hex: mac.to_hex(),
    })
}

/// Verify a permit against the constructor key.
///
/// # Errors
///
/// Unsigned, wrong-key, or malformed claims.
pub fn verify_fixture_permit(
    key: &[u8; 32],
    permit: &FixturePermit,
) -> Result<FixturePermitClaims, FixturePermitError> {
    let expected = mint_fixture_permit(key, permit.claims.clone())?;
    if expected.mac_hex != permit.mac_hex {
        return Err(FixturePermitError::Refused(
            "fixture permit MAC does not match".into(),
        ));
    }
    Ok(permit.claims.clone())
}

/// Parse a 64-hex key into 32 nonzero bytes.
///
/// # Errors
///
/// Shape refusal.
pub fn parse_fixture_key(hex_text: &str) -> Result<[u8; 32], FixturePermitError> {
    let bytes = hex::decode(hex_text)
        .map_err(|err| FixturePermitError::Refused(format!("fixture key hex: {err}")))?;
    let key: [u8; 32] = bytes
        .try_into()
        .map_err(|_| FixturePermitError::Refused("fixture MAC key must be 32 bytes".into()))?;
    if key.iter().all(|byte| *byte == 0) {
        return Err(FixturePermitError::Refused(
            "fixture MAC key must be 32 nonzero bytes".into(),
        ));
    }
    Ok(key)
}

/// Fail closed unless `root` is an already-created private ordinary directory.
///
/// # Errors
///
/// Missing, relative, symlink, or group/other-writable root.
pub fn require_preopened_fixture_root(root: &Path) -> Result<PathBuf, String> {
    if !root.is_absolute() {
        return Err("fixture root must be an absolute pre-opened path".into());
    }
    let metadata = std::fs::symlink_metadata(root)
        .map_err(|error| format!("fixture root must already exist: {error}"))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("fixture root must be an ordinary directory".into());
    }
    let canonical = std::fs::canonicalize(root)
        .map_err(|error| format!("fixture root is not canonical: {error}"))?;
    if canonical != root {
        return Err("fixture root must be the canonical pre-opened path".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err("fixture root must be mode 0700".into());
        }
    }
    Ok(canonical)
}

/// Consume the single disposable generation on this fixture root.
///
/// # Errors
///
/// Root already consumed or marker write failed.
pub fn consume_fixture_generation(root: &Path) -> Result<(), String> {
    let marker = root.join(FIXTURE_GENERATION_MARKER);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&marker)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                "fixture workspace generation 1 is already consumed".to_string()
            } else {
                format!("create fixture generation marker: {error}")
            }
        })?;
    file.write_all(b"1\n")
        .map_err(|error| format!("write fixture generation marker: {error}"))?;
    file.sync_all()
        .map_err(|error| format!("sync fixture generation marker: {error}"))
}

/// True when `requested` is exactly the pre-opened fixture root.
#[must_use]
pub fn destination_is_fixture_root(requested: &Path, fixture_root: &Path) -> bool {
    if requested == fixture_root {
        return true;
    }
    std::fs::canonicalize(requested)
        .ok()
        .is_some_and(|path| path == fixture_root)
}
