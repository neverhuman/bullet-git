//! Authority envelope verification. An empty or unparseable token grants nothing.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Opaque authority envelope supplied by Bullet Farm.
///
/// The bytes are the serde JSON of the kernel `AuthorityToken`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorityEnvelope {
    /// Raw token bytes (JSON of AuthorityToken).
    pub token: Vec<u8>,
}

impl AuthorityEnvelope {
    /// Reject an empty envelope.
    #[must_use]
    pub fn is_present(&self) -> bool {
        !self.token.is_empty()
    }
}

/// Typed authority error with stable reason codes.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum AuthorityError {
    /// Missing, empty, or unparseable authority token.
    #[error("authority required: {0}")]
    Unauthorized(String),
    /// Token names a different attempt, fence, or workspace nonce.
    #[error("stale authority: {0}")]
    StaleAuthority(String),
}

impl AuthorityError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub fn reason_code(&self) -> &'static str {
        match self {
            Self::Unauthorized(_) => "UNAUTHORIZED",
            Self::StaleAuthority(_) => "STALE_AUTHORITY",
        }
    }
}

/// Wire mirror of the kernel `AuthorityToken` serde JSON.
///
/// Field names match the kernel struct exactly; unknown fields are ignored so
/// the kernel may extend the token without breaking this daemon. The four
/// fields below are required.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct WireAuthorityToken {
    /// Variant that owns the writer lease.
    pub variant_id: String,
    /// Attempt incarnation.
    pub attempt_id: String,
    /// Permanent fence epoch. Never reused.
    pub attempt_fence: u64,
    /// Workspace nonce.
    pub workspace_nonce: [u8; 32],
}

impl WireAuthorityToken {
    /// Parse token bytes. Empty or unparseable bytes are `UNAUTHORIZED`.
    ///
    /// # Errors
    ///
    /// Returns `AuthorityError::Unauthorized` when the bytes are empty or do
    /// not decode as an `AuthorityToken` JSON object.
    pub fn parse(token: &[u8]) -> Result<Self, AuthorityError> {
        if token.is_empty() {
            return Err(AuthorityError::Unauthorized("empty authority token".into()));
        }
        serde_json::from_slice(token).map_err(|err| {
            AuthorityError::Unauthorized(format!("unparseable authority token: {err}"))
        })
    }

    /// Verify the token names the expected attempt, fence, and nonce.
    ///
    /// # Errors
    ///
    /// Returns `AuthorityError::StaleAuthority` on any mismatch.
    pub fn verify(
        &self,
        expected_attempt: &str,
        expected_fence: u64,
        expected_nonce: &[u8; 32],
    ) -> Result<(), AuthorityError> {
        if self.attempt_id != expected_attempt {
            return Err(AuthorityError::StaleAuthority(format!(
                "token attempt {} != {expected_attempt}",
                self.attempt_id
            )));
        }
        if self.attempt_fence != expected_fence {
            return Err(AuthorityError::StaleAuthority(format!(
                "token fence {} != {expected_fence}",
                self.attempt_fence
            )));
        }
        if &self.workspace_nonce != expected_nonce {
            return Err(AuthorityError::StaleAuthority(
                "token workspace nonce mismatch".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token_json(attempt: &str, fence: u64, nonce: [u8; 32]) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "organization_id": "org_x",
            "variant_id": "var_v1",
            "attempt_id": attempt,
            "attempt_fence": fence,
            "workspace_nonce": nonce.to_vec(),
            "scope_revision": 1,
        }))
        .expect("token json")
    }

    #[test]
    fn empty_and_garbage_tokens_are_unauthorized() {
        for bytes in [b"".as_slice(), b"x".as_slice(), b"{}".as_slice()] {
            let err = WireAuthorityToken::parse(bytes).expect_err("reject");
            assert_eq!(err.reason_code(), "UNAUTHORIZED");
        }
    }

    #[test]
    fn matching_token_verifies_and_unknown_fields_are_ignored() {
        let nonce = [7u8; 32];
        let token = WireAuthorityToken::parse(&token_json("atm_1", 3, nonce)).expect("parse");
        assert_eq!(token.variant_id, "var_v1");
        token.verify("atm_1", 3, &nonce).expect("verify");
    }

    #[test]
    fn mismatches_are_stale_authority() {
        let nonce = [7u8; 32];
        let token = WireAuthorityToken::parse(&token_json("atm_1", 3, nonce)).expect("parse");
        for err in [
            token.verify("atm_2", 3, &nonce).expect_err("attempt"),
            token.verify("atm_1", 4, &nonce).expect_err("fence"),
            token.verify("atm_1", 3, &[8u8; 32]).expect_err("nonce"),
        ] {
            assert_eq!(err.reason_code(), "STALE_AUTHORITY");
        }
    }
}
