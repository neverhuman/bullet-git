//! Request dispatch. The daemon holds the expected attempt/fence/nonce from
//! the initial `clone` token and verifies every subsequent call against them.

use crate::protocol::{
    self, ApplyParams, CleanupParams, CloneParams, PatchParam, PrepareParams, Request,
};
use bullet_git_types::{AuthorityError, Change, ChangeId, Digest, WireAuthorityToken};
use bullet_git_workspace::{
    AgentRepository, CapabilityError, CloneRequest, CommitIdentity, ExpectedAuthority, PatchHunk,
    PrivateClone, RealRepository, ScopeGrant,
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
}

/// One daemon instance serves one workspace session.
#[derive(Default)]
pub struct Daemon {
    session: Option<Session>,
}

impl Daemon {
    /// A daemon with no session; `clone` must be the first call.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
            "read_tree" | "apply_change" | "checkpoint" | "prepare_candidate" => {
                self.handle_repo(req)
            }
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
        let workspace = PrivateClone::create(&clone_req).map_err(|e| cap(&e))?;
        let grant = ScopeGrant::new(&params.allowed_prefixes).map_err(|e| cap(&e))?;
        let expected = ExpectedAuthority {
            attempt_id: token.attempt_id.clone(),
            attempt_fence: token.attempt_fence,
            workspace_nonce: token.workspace_nonce,
        };
        let result = json!({
            "repo_dir": workspace.repo_dir().display().to_string(),
            "runtime_dir": workspace.runtime_dir().display().to_string(),
            "branch": workspace.branch(),
            "base_sha": workspace.base_sha(),
        });
        let repo = RealRepository::new(
            workspace,
            grant,
            expected.clone(),
            CommitIdentity::farm(&params.commit_date),
        )
        .map_err(|error| cap(&error))?;
        self.session = Some(Session { repo, expected });
        Ok(result)
    }

    fn handle_repo(&mut self, req: &Request) -> MethodResult {
        let _ = self.verify_token(req)?;
        let envelope = protocol::envelope(&req.token);
        let session = self.session.as_mut().ok_or_else(not_cloned)?;
        match req.method.as_str() {
            "read_tree" => {
                let files = session.repo.read_tree(&envelope).map_err(|e| cap(&e))?;
                Ok(json!({ "files": files }))
            }
            "apply_change" => {
                let params: ApplyParams = parse_params(&req.params)?;
                let mut patches = Vec::with_capacity(params.patches.len());
                for patch in params.patches {
                    patches.push(decode_patch(patch)?);
                }
                session
                    .repo
                    .apply_change(&envelope, &patches)
                    .map_err(|e| cap(&e))?;
                Ok(json!({ "applied": patches.len() }))
            }
            "checkpoint" => {
                let checkpoint = session.repo.checkpoint(&envelope).map_err(|e| cap(&e))?;
                to_value(&checkpoint)
            }
            "prepare_candidate" => {
                let params: PrepareParams = parse_params(&req.params)?;
                let change = Change {
                    id: ChangeId::from_seed(&params.change_seed),
                    mission: params.mission.clone(),
                    acceptance_root: Digest::of(params.mission.as_bytes()),
                };
                let candidate = session
                    .repo
                    .prepare_candidate(&envelope, &change)
                    .map_err(|e| cap(&e))?;
                to_value(&candidate)
            }
            other => Err(("UNKNOWN_METHOD".into(), format!("unknown method: {other}"))),
        }
    }

    fn handle_cleanup(&mut self, req: &Request) -> MethodResult {
        let token = self.verify_token(req)?;
        let params: CleanupParams = parse_params(&req.params)?;
        let Some(bundle) = params.bundle_path else {
            return Err((
                "CLEANUP_RECEIPT_REQUIRED".into(),
                "cleanup requires bundle_path for the preservation receipt".into(),
            ));
        };
        let receipt = {
            let session = self.session.as_ref().ok_or_else(not_cloned)?;
            session
                .repo
                .workspace()
                .preserve(Path::new(&bundle))
                .map_err(|e| cap(&e))?
        };
        let session = self.session.take().ok_or_else(not_cloned)?;
        let workspace = session.repo.into_workspace();
        let tombstone = workspace
            .cleanup(&token.workspace_nonce, &receipt, &params.deleted_at)
            .map_err(|e| cap(&e))?;
        Ok(json!({
            "tombstone": tombstone.display().to_string(),
            "bundle": bundle,
            "verified": true,
        }))
    }
}
