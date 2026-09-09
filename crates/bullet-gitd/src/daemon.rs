//! Request dispatch. The daemon holds the expected attempt/fence/nonce from
//! the initial `clone` token and verifies every subsequent call against them.

mod codec;
#[path = "daemon_handlers.rs"]
mod handlers;

use crate::authority_gateway::{AuthorityGateway, MutationPermit, PendingMutation};
use crate::mutation_ledger::{MutationOperation, MutationOutcome};
use crate::protocol::{
    self, ApplyParams, ApplyProposalParams, BindProofParams, CleanupParams, CloneParams,
    PrepareParams, PreserveParams, Request, VerifyProofParams,
};
use bullet_git_types::{framed_digest, verify_proof_root, Digest, ProofRoot, WireAuthorityToken};
use bullet_git_workspace::{
    AgentRepository, CloneRequest, CommitIdentity, ExpectedAuthority, PreservationAuthority,
    PrivateClone, RealRepository, ScopeGrant,
};
use serde_json::{json, Value};
use std::path::Path;

use codec::{
    auth, candidate_manifest, cap, decode_patch, gateway, not_cloned, parse_params, proof_inputs,
    to_value, MethodError, MethodResult,
};

struct Session {
    repo: RealRepository,
    expected: ExpectedAuthority,
    preservation: PreservationAuthority,
}

/// One daemon instance serves one workspace session.
pub struct Daemon {
    session: Option<Session>,
    authority: AuthorityGateway,
    mutation_frozen: bool,
    #[cfg(feature = "fixture-authority")]
    fixture_root: Option<std::path::PathBuf>,
}

#[cfg(feature = "fixture-authority")]
pub use crate::authority_gateway::{
    consume_fixture_generation, destination_is_fixture_root, mint_fixture_permit,
    parse_fixture_key, require_preopened_fixture_root, verify_fixture_permit, FixturePermit,
    FixturePermitClaims, FixturePermitError,
};

impl Default for Daemon {
    fn default() -> Self {
        Self::new()
    }
}

impl Daemon {
    /// A daemon with no session and a fail-closed production Kernel checker.
    ///
    /// On Linux, mutation requires admitted Kernel UDS configuration, a
    /// one-use permit, and matching online check and settlement. Missing or
    /// invalid authority fails closed; non-Linux builds have no positive path.
    #[must_use]
    pub fn new() -> Self {
        Self {
            session: None,
            authority: AuthorityGateway::kernel(),
            mutation_frozen: false,
            #[cfg(feature = "fixture-authority")]
            fixture_root: None,
        }
    }

    /// Demo-only daemon bound to one pre-opened fixture root and MAC permit.
    ///
    /// `new()` stays fail-closed. Compiled only under `fixture-authority`.
    ///
    /// # Errors
    ///
    /// Root is missing/unsafe, the permit MAC does not verify, or the
    /// mutation ledger cannot open.
    #[cfg(feature = "fixture-authority")]
    pub fn fixture(
        fixture_root: &Path,
        key: [u8; 32],
        permit: FixturePermit,
    ) -> Result<Self, String> {
        let fixture_root = require_preopened_fixture_root(fixture_root)?;
        Ok(Self {
            session: None,
            authority: AuthorityGateway::fixture(&fixture_root, key, permit)
                .map_err(|error| format!("{}: {error}", error.reason_code()))?,
            mutation_frozen: false,
            fixture_root: Some(fixture_root),
        })
    }

    /// Handle one request line and produce one response line.
    pub fn handle_line(&mut self, line: &str) -> String {
        let req: Request = match serde_json::from_str(line) {
            Ok(req) => req,
            Err(err) => {
                return protocol::err_line(&Value::Null, "BAD_REQUEST", &err.to_string());
            }
        };
        let id = req.id.clone();
        match self.dispatch(&req) {
            Ok(result) => protocol::ok_line(&id, &result),
            Err((code, message)) => protocol::err_line(&id, &code, &message),
        }
    }

    fn dispatch(&mut self, req: &Request) -> MethodResult {
        match req.method.as_str() {
            "clone" => self.handle_clone(req),
            "read_tree" | "apply_change" | "apply_proposal" | "checkpoint"
            | "prepare_candidate" => self.handle_repo(req),
            "preserve" => self.handle_preserve(req),
            "cleanup" => self.handle_cleanup(req),
            "bind_proof" => self.handle_bind_proof(req),
            "verify_proof_root" => self.handle_verify_proof_root(req),
            other => Err(("UNKNOWN_METHOD".into(), format!("unknown method: {other}"))),
        }
    }

    fn verify_token(&self, req: &Request) -> Result<WireAuthorityToken, MethodError> {
        let session = self.session.as_ref().ok_or_else(not_cloned)?;
        let envelope = protocol::envelope(&req.token);
        let token = WireAuthorityToken::parse(&envelope.token).map_err(|e| auth(&e))?;
        token
            .verify(
                &session.expected.attempt_id,
                session.expected.attempt_fence,
                &session.expected.workspace_nonce,
            )
            .map_err(|e| auth(&e))?;
        Ok(token)
    }

    fn authorize_mutation(
        &mut self,
        req: &Request,
        operation: MutationOperation,
        token: &WireAuthorityToken,
    ) -> Result<MutationPermit, MethodError> {
        if self.mutation_frozen {
            return Err((
                "MUTATION_OUTCOME_UNKNOWN".into(),
                "daemon mutation is frozen after an indeterminate repository outcome".into(),
            ));
        }
        self.authority
            .authorize(
                operation,
                &req.token,
                &req.params,
                &token.attempt_id,
                token.attempt_fence,
                &token.workspace_nonce,
            )
            .map_err(|error| gateway(&error))
    }

    fn consume_permit(
        &mut self,
        req: &Request,
        operation: MutationOperation,
        permit: MutationPermit,
    ) -> Result<PendingMutation, MethodError> {
        self.authority
            .consume(permit, operation, &req.token, &req.params)
            .map_err(|error| gateway(&error))
    }

    fn settle_result(
        &mut self,
        operation: MutationOperation,
        pending: PendingMutation,
        result: MethodResult,
    ) -> MethodResult {
        let (outcome, payload) = match &result {
            Ok(value) => (MutationOutcome::Committed, value.clone()),
            Err((code, message)) => (
                MutationOutcome::Unknown,
                json!({"code": code, "message": message}),
            ),
        };
        let encoded = match serde_json::to_vec(&payload) {
            Ok(encoded) => encoded,
            Err(error) => {
                self.mutation_frozen = true;
                return Err((
                    "MUTATION_OUTCOME_UNKNOWN".into(),
                    format!("cannot encode exact mutation result: {error}"),
                ));
            }
        };
        let result_digest = framed_digest(&[
            b"bullet-gitd.mutation-result.v1",
            operation.as_str().as_bytes(),
            match outcome {
                MutationOutcome::Committed => b"committed",
                MutationOutcome::Aborted => b"aborted",
                MutationOutcome::Unknown => b"unknown",
            },
            &encoded,
        ])
        .to_hex();
        if let Err(error) = self.authority.settle(pending, outcome, &result_digest) {
            self.mutation_frozen = true;
            return Err(gateway(&error));
        }
        match result {
            Ok(value) => Ok(value),
            Err((code, message)) => {
                self.mutation_frozen = true;
                Err((
                    "MUTATION_OUTCOME_UNKNOWN".into(),
                    format!("repository returned {code} after permit consumption: {message}"),
                ))
            }
        }
    }
}

#[cfg(test)]
#[path = "daemon/tests.rs"]
mod tests;
