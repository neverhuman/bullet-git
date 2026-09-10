//! Request dispatch. The daemon holds the expected attempt/fence/nonce from
//! the initial `clone` token and verifies every subsequent call against them.

mod codec;
#[path = "daemon_handlers.rs"]
mod handlers;

use crate::authority_gateway::{AuthorityGateway, MutationPermit, PendingMutation};
use crate::mutation_ledger::{MutationOperation, MutationOutcome, MutationResult};
use crate::protocol::{
    self, ApplyParams, ApplyProposalParams, BindProofParams, CleanupParams, CloneParams,
    PrepareParams, PreserveParams, Request, VerifyProofParams,
};
use bullet_git_types::{framed_digest, verify_proof_root, ProofRoot, WireAuthorityToken};
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

/// Exact daemon-session facts a receipt-gated cleanup binds into its subject.
///
/// These live with the session rather than with the gateway because every
/// field is read from the sealed receipt or from the live session; none of it
/// is caller-supplied transport data.
pub(crate) struct ReceiptSubject<'a> {
    /// Sealed receipt token bytes, which are the authority envelope here.
    pub(crate) receipt_token: &'a str,
    /// Lowercase hex digest of the exact sealed receipt token.
    pub(crate) receipt_digest: &'a str,
    /// Attempt incarnation verified against the daemon session.
    pub(crate) attempt_id: &'a str,
    /// Permanent, never-reused Attempt fence.
    pub(crate) attempt_fence: u64,
    /// Workspace nonce verified against the daemon session.
    pub(crate) workspace_nonce: &'a [u8; 32],
    /// Daemon-local repository identity for the served workspace.
    pub(crate) repository_id: &'a str,
    /// Daemon-local workspace identity for the served workspace.
    pub(crate) workspace_id: &'a str,
    /// Exact active workspace generation, numbered from one.
    pub(crate) workspace_generation: u64,
}

/// Outcome of one receipt-gated authorization.
pub(crate) enum ReceiptAuthorization {
    /// This process durably created the reservation and must settle it.
    Fresh(Box<MutationPermit>),
    /// An identical cleanup already settled. Never a second permit.
    Replay(Box<MutationResult>),
}

impl Session {
    /// Daemon-local repository and workspace identity for this session.
    ///
    /// Receipt-gated cleanup has no online authority to name the Kernel's
    /// `rep_`/`wsp_` identities, so the durable subject records the exact
    /// workspace this daemon serves, derived from its recorded manifest.
    fn receipt_identity(&self) -> (String, String) {
        let workspace = self.repo.workspace();
        let manifest = workspace.manifest();
        let runtime_dir = workspace.runtime_dir().to_string_lossy();
        let repository_id = framed_digest(&[
            b"bullet-gitd.receipt-repository-id.v1",
            manifest.source_repo.as_bytes(),
            manifest.mirror_dir.as_bytes(),
            manifest.base_sha.as_str().as_bytes(),
        ])
        .to_hex();
        let workspace_id = framed_digest(&[
            b"bullet-gitd.receipt-workspace-id.v1",
            runtime_dir.as_bytes(),
            manifest.attempt_id.as_bytes(),
            manifest.nonce_hex.as_bytes(),
        ])
        .to_hex();
        (
            format!("rep_{repository_id}"),
            format!("wsp_{workspace_id}"),
        )
    }
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

    /// An indeterminate earlier outcome outranks every later authority.
    fn require_unfrozen(&self) -> Result<(), MethodError> {
        if self.mutation_frozen {
            return Err((
                "MUTATION_OUTCOME_UNKNOWN".into(),
                "daemon mutation is frozen after an indeterminate repository outcome".into(),
            ));
        }
        Ok(())
    }

    fn authorize_mutation(
        &mut self,
        req: &Request,
        operation: MutationOperation,
        token: &WireAuthorityToken,
    ) -> Result<MutationPermit, MethodError> {
        self.require_unfrozen()?;
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

    /// Reserve one cleanup on the authority of an already verified receipt.
    ///
    /// A frozen daemon still refuses first: an indeterminate earlier outcome
    /// outranks any receipt.
    fn authorize_cleanup_by_receipt(
        &mut self,
        req: &Request,
        receipt: &ReceiptSubject<'_>,
    ) -> Result<ReceiptAuthorization, MethodError> {
        self.require_unfrozen()?;
        self.authority
            .authorize_by_preservation_receipt(&req.token, &req.params, receipt)
            .map_err(|error| gateway(&error))
    }

    fn consume_receipt_permit(
        &mut self,
        req: &Request,
        permit: Box<MutationPermit>,
    ) -> Result<PendingMutation, MethodError> {
        self.authority
            .consume_by_preservation_receipt(*permit, &req.token, &req.params)
            .map_err(|error| gateway(&error))
    }

    fn settle_result(
        &mut self,
        operation: MutationOperation,
        pending: PendingMutation,
        result: MethodResult,
    ) -> MethodResult {
        self.finish_mutation(operation, pending, result, false)
    }

    /// Settle a receipt-gated cleanup without a Kernel settlement RPC.
    fn settle_receipt_result(
        &mut self,
        pending: PendingMutation,
        result: MethodResult,
    ) -> MethodResult {
        self.finish_mutation(MutationOperation::CleanupWorkspace, pending, result, true)
    }

    fn finish_mutation(
        &mut self,
        operation: MutationOperation,
        pending: PendingMutation,
        result: MethodResult,
        receipt_gated: bool,
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
        let settled = if receipt_gated {
            self.authority
                .settle_locally(pending, outcome, &result_digest)
        } else {
            self.authority.settle(pending, outcome, &result_digest)
        };
        if let Err(error) = settled {
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

#[cfg(all(test, unix))]
#[path = "daemon/cleanup_receipt_tests.rs"]
mod cleanup_receipt_tests;
