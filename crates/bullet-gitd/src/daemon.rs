//! Request dispatch. The daemon holds the expected attempt/fence/nonce from
//! the initial `clone` token and verifies every subsequent call against them.

mod codec;

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

    fn handle_clone(&mut self, req: &Request) -> MethodResult {
        if self.session.is_some() {
            return Err((
                "ALREADY_CLONED".into(),
                "this daemon already serves a workspace".into(),
            ));
        }
        let envelope = protocol::envelope(&req.token);
        let token = WireAuthorityToken::parse(&envelope.token).map_err(|e| auth(&e))?;
        let params: CloneParams = parse_params(&req.params)?;
        self.authority.attach_ledger_root(Path::new(&params.root));
        #[cfg(feature = "fixture-authority")]
        if let Some(fixture_root) = &self.fixture_root {
            if !destination_is_fixture_root(Path::new(&params.root), fixture_root) {
                return Err((
                    "FIXTURE_DESTINATION_REFUSED".into(),
                    "clone root must be the pre-opened fixture root".into(),
                ));
            }
            consume_fixture_generation(fixture_root)
                .map_err(|error| ("FIXTURE_GENERATION_CONSUMED".into(), error))?;
        }
        let clone_req = CloneRequest {
            source_repo: Path::new(&params.source_repo),
            base_sha: &params.base_sha,
            variant_id: &token.variant_id,
            attempt_id: &token.attempt_id,
            root: Path::new(&params.root),
            created_at: &params.created_at,
            nonce: token.workspace_nonce,
        };
        let permit = self.authorize_mutation(req, MutationOperation::CloneWorkspace, &token)?;
        let pending = self.consume_permit(req, MutationOperation::CloneWorkspace, permit)?;
        let result = (|| {
            let workspace = PrivateClone::create(&clone_req).map_err(|e| cap(&e))?;
            let grant = ScopeGrant::new(&params.allowed_prefixes).map_err(|e| cap(&e))?;
            let expected = ExpectedAuthority {
                attempt_id: token.attempt_id.clone(),
                attempt_fence: token.attempt_fence,
                workspace_nonce: token.workspace_nonce,
            };
            let preservation = PreservationAuthority::open(workspace.runtime_dir())
                .map_err(|error| (error.reason_code().into(), error.to_string()))?;
            let repo = RealRepository::new(
                workspace,
                grant,
                expected.clone(),
                CommitIdentity::farm(&params.commit_date),
            )
            .map_err(|error| cap(&error))?;
            let checkpoint = repo.active_checkpoint().clone();
            let result = json!({
                "repo_dir": repo.workspace().repo_dir().display().to_string(),
                "runtime_dir": repo.workspace().runtime_dir().display().to_string(),
                "branch": repo.workspace().branch(),
                "base_sha": repo.workspace().base_sha(),
                "base_checkpoint_id": checkpoint.id,
                "base_checkpoint_digest": checkpoint.digest,
                "active_generation": repo.workspace().active_generation_binding(),
            });
            self.session = Some(Session {
                repo,
                expected,
                preservation,
            });
            Ok(result)
        })();
        self.settle_result(MutationOperation::CloneWorkspace, pending, result)
    }

    fn handle_repo(&mut self, req: &Request) -> MethodResult {
        let token = self.verify_token(req)?;
        let envelope = protocol::envelope(&req.token);
        match req.method.as_str() {
            "read_tree" => {
                let session = self.session.as_mut().ok_or_else(not_cloned)?;
                let files = session.repo.read_tree(&envelope).map_err(|e| cap(&e))?;
                Ok(json!({ "files": files }))
            }
            "apply_change" => {
                let params: ApplyParams = parse_params(&req.params)?;
                let mut patches = Vec::with_capacity(params.patches.len());
                for patch in params.patches {
                    patches.push(decode_patch(patch)?);
                }
                let permit = self.authorize_mutation(req, MutationOperation::ApplyPatch, &token)?;
                let pending = self.consume_permit(req, MutationOperation::ApplyPatch, permit)?;
                let result = self
                    .session
                    .as_mut()
                    .ok_or_else(not_cloned)
                    .and_then(|session| {
                        session
                            .repo
                            .apply_change(&envelope, &patches)
                            .map_err(|e| cap(&e))?;
                        Ok(json!({ "applied": patches.len() }))
                    });
                self.settle_result(MutationOperation::ApplyPatch, pending, result)
            }
            "apply_proposal" => {
                let params: ApplyProposalParams = parse_params(&req.params)?;
                let permit = self.authorize_mutation(req, MutationOperation::ApplyPatch, &token)?;
                let pending = self.consume_permit(req, MutationOperation::ApplyPatch, permit)?;
                let applied = params.proposal.operations.len();
                let proposal_id = params.proposal.proposal_id.clone();
                let result = self
                    .session
                    .as_mut()
                    .ok_or_else(not_cloned)
                    .and_then(|session| {
                        let checkpoint = session
                            .repo
                            .apply_proposal(&envelope, &params.proposal)
                            .map_err(|error| cap(&error))?;
                        Ok(json!({
                            "proposal_id": proposal_id,
                            "applied": applied,
                            "checkpoint": {
                                "id": checkpoint.id,
                                "digest": checkpoint.digest,
                            },
                            "repo_dir": session.repo.workspace().repo_dir(),
                            "active_generation": session.repo.workspace().active_generation_binding(),
                        }))
                    });
                self.settle_result(MutationOperation::ApplyPatch, pending, result)
            }
            "checkpoint" => {
                let permit = self.authorize_mutation(req, MutationOperation::Checkpoint, &token)?;
                let pending = self.consume_permit(req, MutationOperation::Checkpoint, permit)?;
                let result = self
                    .session
                    .as_mut()
                    .ok_or_else(not_cloned)
                    .and_then(|session| {
                        let checkpoint = session.repo.checkpoint(&envelope).map_err(|e| cap(&e))?;
                        to_value(&checkpoint)
                    });
                self.settle_result(MutationOperation::Checkpoint, pending, result)
            }
            "prepare_candidate" => {
                let params: PrepareParams = parse_params(&req.params)?;
                self.session
                    .as_ref()
                    .ok_or_else(not_cloned)?
                    .repo
                    .validate_candidate_preparation(&envelope, &params.provenance)
                    .map_err(|error| cap(&error))?;
                let permit =
                    self.authorize_mutation(req, MutationOperation::PrepareCandidate, &token)?;
                let pending =
                    self.consume_permit(req, MutationOperation::PrepareCandidate, permit)?;
                let result = self
                    .session
                    .as_mut()
                    .ok_or_else(not_cloned)
                    .and_then(|session| {
                        let candidate = session
                            .repo
                            .prepare_candidate(&envelope, &params.change, &params.provenance)
                            .map_err(|e| cap(&e))?;
                        to_value(&candidate)
                    });
                self.settle_result(MutationOperation::PrepareCandidate, pending, result)
            }
            other => Err(("UNKNOWN_METHOD".into(), format!("unknown method: {other}"))),
        }
    }

    fn handle_bind_proof(&self, req: &Request) -> MethodResult {
        let params: BindProofParams = parse_params(&req.params)?;
        params
            .candidate
            .validate_identity()
            .map_err(|error| candidate_manifest(&error))?;
        let inputs = proof_inputs(&params.inputs);
        to_value(&ProofRoot::bind(&params.candidate, &inputs))
    }

    fn handle_verify_proof_root(&self, req: &Request) -> MethodResult {
        let params: VerifyProofParams = parse_params(&req.params)?;
        params
            .candidate
            .validate_identity()
            .map_err(|error| candidate_manifest(&error))?;
        let inputs = proof_inputs(&params.inputs);
        verify_proof_root(&params.root, &params.candidate, &inputs)
            .map_err(|error| (error.reason_code().to_string(), error.to_string()))?;
        Ok(json!({"verified": true}))
    }

    fn handle_preserve(&mut self, req: &Request) -> MethodResult {
        let token = self.verify_token(req)?;
        let params: PreserveParams = parse_params(&req.params)?;
        let permit = self.authorize_mutation(req, MutationOperation::PreserveWorkspace, &token)?;
        let pending = self.consume_permit(req, MutationOperation::PreserveWorkspace, permit)?;
        let envelope = protocol::envelope(&req.token);
        let result = self
            .session
            .as_ref()
            .ok_or_else(not_cloned)
            .and_then(|session| {
                let receipt = session
                    .preservation
                    .issue(&session.repo, &envelope, Path::new(&params.destination))
                    .map_err(|error| cap(&error))?;
                Ok(json!({
                    "preservation_receipt": receipt.token(),
                    "preservation_receipt_digest": receipt.receipt_digest().to_hex(),
                    "artifact_digest": receipt.artifact_digest().to_hex(),
                    "destination": receipt.destination().display().to_string(),
                }))
            });
        self.settle_result(MutationOperation::PreserveWorkspace, pending, result)
    }

    fn handle_cleanup(&mut self, req: &Request) -> MethodResult {
        let token = self.verify_token(req)?;
        let params: CleanupParams = parse_params(&req.params)?;
        let permit = self.authorize_mutation(req, MutationOperation::CleanupWorkspace, &token)?;
        let pending = self.consume_permit(req, MutationOperation::CleanupWorkspace, permit)?;
        let envelope = protocol::envelope(&req.token);
        let result = (|| {
            let session = self.session.as_mut().ok_or_else(not_cloned)?;
            let tombstone = session
                .preservation
                .cleanup(
                    &mut session.repo,
                    &envelope,
                    &params.preservation_receipt,
                    &params.deleted_at,
                )
                .map_err(|error| cap(&error))?;
            self.session = None;
            Ok(json!({
                "tombstone": tombstone.display().to_string(),
                "preservation_receipt_digest": Digest::of(params.preservation_receipt.as_bytes()).to_hex(),
                "verified": true,
            }))
        })();
        self.settle_result(MutationOperation::CleanupWorkspace, pending, result)
    }
}

#[cfg(test)]
#[path = "daemon/tests.rs"]
mod tests;
