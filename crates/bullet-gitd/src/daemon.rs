//! Request dispatch. The daemon holds the expected attempt/fence/nonce from
//! the initial `clone` token and verifies every subsequent call against them.

use crate::authority_gateway::{AuthorityGateway, GatewayError, MutationPermit, PendingMutation};
use crate::mutation_ledger::{MutationOperation, MutationOutcome};
use crate::protocol::{
    self, ApplyParams, ApplyProposalParams, CleanupParams, CloneParams, PatchParam, PrepareParams,
    PreserveParams, Request,
};
use bullet_git_types::{
    framed_digest, AuthorityError, Change, ChangeId, Digest, WireAuthorityToken,
};
use bullet_git_workspace::{
    AgentRepository, CapabilityError, CloneRequest, CommitIdentity, ExpectedAuthority, PatchHunk,
    PreservationAuthority, PrivateClone, RealRepository, ScopeGrant, MAX_CONTENT_BYTES,
};
use serde::de::DeserializeOwned;
use serde_json::{json, Value};
use std::path::Path;

type MethodError = (String, String);
type MethodResult = Result<Value, MethodError>;

fn cap(err: &CapabilityError) -> MethodError {
    (err.reason_code().to_string(), err.to_string())
}

fn auth(err: &AuthorityError) -> MethodError {
    (err.reason_code().to_string(), err.to_string())
}

fn gateway(err: &GatewayError) -> MethodError {
    (err.reason_code().to_string(), err.to_string())
}

fn not_cloned() -> MethodError {
    ("NOT_CLONED".into(), "clone must be the first call".into())
}

fn parse_params<T: DeserializeOwned>(params: &Value) -> Result<T, MethodError> {
    serde_json::from_value(params.clone())
        .map_err(|err| ("BAD_REQUEST".into(), format!("invalid params: {err}")))
}

fn to_value<T: serde::Serialize>(value: &T) -> MethodResult {
    serde_json::to_value(value).map_err(|err| ("ENCODING".into(), format!("encode result: {err}")))
}

/// Decode one wire patch entry into a typed hunk.
///
/// `op` absent or `write` keeps the v1 shape and requires `contents_hex`;
/// `delete` forbids it. Anything else is `BAD_REQUEST`.
fn decode_patch(patch: PatchParam) -> Result<PatchHunk, MethodError> {
    let bad = |message: String| ("BAD_REQUEST".to_string(), message);
    match patch.op.as_deref() {
        None | Some("write") => {
            let Some(hex_text) = patch.contents_hex else {
                return Err(bad(format!(
                    "contents_hex required for write op: {}",
                    patch.path
                )));
            };
            if hex_text.len() > MAX_CONTENT_BYTES.saturating_mul(2) {
                return Err((
                    "CONTENT_TOO_LARGE".into(),
                    format!("{} exceeds {MAX_CONTENT_BYTES} decoded bytes", patch.path),
                ));
            }
            let contents = hex::decode(&hex_text)
                .map_err(|err| bad(format!("contents_hex for {}: {err}", patch.path)))?;
            Ok(PatchHunk::write(patch.path, contents))
        }
        Some("delete") => {
            if patch.contents_hex.is_some() {
                return Err(bad(format!(
                    "delete op must not carry contents_hex: {}",
                    patch.path
                )));
            }
            Ok(PatchHunk::delete(patch.path))
        }
        Some(other) => Err(bad(format!("unknown patch op {other:?}: {}", patch.path))),
    }
}

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
}

impl Default for Daemon {
    fn default() -> Self {
        Self::new()
    }
}

impl Daemon {
    /// A daemon with no session and no positive production authority path.
    ///
    /// Until the frozen `bullet-wire` crate is available from an immutable
    /// permitted source and a Kernel final-check client is installed, every
    /// mutation fails closed with `AUTHORITY_CONTRACT_UNAVAILABLE`.
    #[must_use]
    pub fn new() -> Self {
        Self {
            session: None,
            authority: AuthorityGateway::unavailable(),
            mutation_frozen: false,
        }
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
        &self,
        req: &Request,
        operation: MutationOperation,
        permit: MutationPermit,
    ) -> Result<PendingMutation, MethodError> {
        let now = self
            .authority
            .now_unix_ms()
            .map_err(|error| gateway(&error))?;
        permit
            .consume(operation, &req.token, &req.params, now)
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
                            "checkpoint": checkpoint,
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
                let change = Change {
                    id: ChangeId::from_seed(&params.change_seed),
                    mission: params.mission.clone(),
                    acceptance_root: Digest::of(params.mission.as_bytes()),
                };
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
                            .prepare_candidate(&envelope, &change)
                            .map_err(|e| cap(&e))?;
                        to_value(&candidate)
                    });
                self.settle_result(MutationOperation::PrepareCandidate, pending, result)
            }
            other => Err(("UNKNOWN_METHOD".into(), format!("unknown method: {other}"))),
        }
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
mod tests {
    use super::*;

    #[test]
    fn indeterminate_daemon_refuses_later_mutation_before_authority() {
        let mut daemon = Daemon::new();
        daemon.mutation_frozen = true;
        let request = Request {
            id: json!(1),
            method: "apply_change".into(),
            token: json!({"paseto": "never consulted"}),
            params: json!({"patches": []}),
        };
        let token = WireAuthorityToken {
            variant_id: "var_test".into(),
            attempt_id: "atm_test".into(),
            attempt_fence: 1,
            workspace_nonce: [7; 32],
        };
        let error = match daemon.authorize_mutation(&request, MutationOperation::ApplyPatch, &token)
        {
            Ok(_) => panic!("frozen daemon returned a permit"),
            Err(error) => error,
        };
        assert_eq!(error.0, "MUTATION_OUTCOME_UNKNOWN");
    }

    #[test]
    fn malformed_apply_proposal_is_a_typed_bad_request() {
        let bad = json!({
            "proposal": {
                "schema_version": 1,
                "proposal_id": "cnt_short",
                "producing_attempt_id": format!("atm_{}", "2".repeat(64)),
                "base_checkpoint_id": format!("ckp_{}", "3".repeat(64)),
                "base_checkpoint_digest": "4".repeat(64),
                "operations": [],
                "gate_ids": [format!("gat_{}", "5".repeat(64))]
            }
        });
        let error = parse_params::<ApplyProposalParams>(&bad).expect_err("malformed refused");
        assert_eq!(error.0, "BAD_REQUEST");
    }
}
