//! Clone/repo/proof/preserve/cleanup dispatch.

use super::*;

impl Daemon {
    pub(super) fn handle_clone(&mut self, req: &Request) -> MethodResult {
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

    pub(super) fn handle_repo(&mut self, req: &Request) -> MethodResult {
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

    pub(super) fn handle_bind_proof(&self, req: &Request) -> MethodResult {
        let params: BindProofParams = parse_params(&req.params)?;
        params
            .candidate
            .validate_identity()
            .map_err(|error| candidate_manifest(&error))?;
        let inputs = proof_inputs(&params.inputs);
        to_value(&ProofRoot::bind(&params.candidate, &inputs))
    }

    pub(super) fn handle_verify_proof_root(&self, req: &Request) -> MethodResult {
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

    pub(super) fn handle_preserve(&mut self, req: &Request) -> MethodResult {
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

    pub(super) fn handle_cleanup(&mut self, req: &Request) -> MethodResult {
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
