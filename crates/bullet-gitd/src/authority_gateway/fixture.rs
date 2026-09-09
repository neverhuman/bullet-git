use super::*;
use bullet_git_types::framed_digest;

impl AuthorityGateway {
    /// Fixture-only gateway bound to one pre-opened root and MAC key.
    pub(crate) fn fixture(
        root: &std::path::Path,
        key: [u8; 32],
        permit: FixturePermit,
    ) -> Result<Self, GatewayError> {
        let claims = verify_fixture_permit(&key, &permit)
            .map_err(|err| GatewayError::Refused(err.to_string()))?;
        if claims.destination != root.display().to_string()
            && std::fs::canonicalize(root)
                .ok()
                .map(|path| path.display().to_string())
                != Some(claims.destination.clone())
        {
            return Err(GatewayError::Refused(
                "fixture permit destination does not match the pre-opened root".into(),
            ));
        }
        let ledger = MutationLedger::open(root.join(".bullet-mutation-ledger"))?;
        Ok(Self {
            checker: Box::new(FixtureCheck { key, permit }),
            clock: Box::new(SystemClock),
            ledger: Some(ledger),
            ledger_root: None,
        })
    }
}

struct FixtureCheck {
    key: [u8; 32],
    permit: FixturePermit,
}

impl FinalAuthorityCheck for FixtureCheck {
    fn check(&mut self, input: &FinalCheckInput<'_>) -> Result<VerifiedDecision, GatewayError> {
        let claims = verify_fixture_permit(&self.key, &self.permit)
            .map_err(|err| GatewayError::Refused(err.to_string()))?;
        let token = crate::protocol::envelope(input.authority);
        let parsed = bullet_git_types::WireAuthorityToken::parse(&token.token)
            .map_err(|err| GatewayError::Refused(err.to_string()))?;
        let nonce_hex = hex::encode(parsed.workspace_nonce);
        if parsed.attempt_id != claims.attempt_id
            || parsed.attempt_fence != claims.attempt_fence
            || nonce_hex != claims.workspace_nonce_hex
        {
            return Err(GatewayError::Refused(
                "fixture permit does not bind this authority token".into(),
            ));
        }
        if input.operation == MutationOperation::CloneWorkspace {
            let root = input
                .params
                .get("root")
                .and_then(Value::as_str)
                .unwrap_or_default();
            if root != claims.destination {
                return Err(GatewayError::Refused(format!(
                    "FIXTURE_DESTINATION_REFUSED: {root}"
                )));
            }
        }
        let now = SystemClock.now_unix_ms()?;
        let expires_at_unix_ms = now.saturating_add(500);
        let envelope_digest =
            framed_digest(&[b"fixture.authority-envelope", &token.token]).to_hex();
        let token_nonce = framed_digest(&[b"fixture.token-nonce", &token.token]).to_hex();
        let mutation_hex = framed_digest(&[
            b"fixture.mutation",
            input.operation.as_str().as_bytes(),
            input.transport_fingerprint.as_bytes(),
        ])
        .to_hex();
        let reservation_hex =
            framed_digest(&[b"fixture.reservation", mutation_hex.as_bytes()]).to_hex();
        let permit_nonce =
            framed_digest(&[b"fixture.permit-nonce", self.permit.mac_hex.as_bytes()]).to_hex();
        let permit_digest =
            framed_digest(&[b"fixture.permit-digest", self.permit.mac_hex.as_bytes()]).to_hex();
        let repository_id = format!(
            "rep_{}",
            framed_digest(&[b"fixture.repo", claims.destination.as_bytes()]).to_hex()
        );
        let workspace_id = format!(
            "wsp_{}",
            framed_digest(&[b"fixture.workspace", claims.destination.as_bytes()]).to_hex()
        );
        Ok(VerifiedDecision {
            subject: MutationSubject {
                authority_envelope_digest: envelope_digest,
                authority_token_nonce: token_nonce,
                mutation_id: format!("mut_{mutation_hex}"),
                reservation_id: format!("rsv_{reservation_hex}"),
                operation: input.operation,
                request_digest: input.transport_fingerprint.to_hex(),
                repository_id,
                workspace_id,
                workspace_generation: 1,
                workspace_nonce: nonce_hex,
                attempt_id: parsed.attempt_id,
                attempt_fence: parsed.attempt_fence,
                authority_epoch: 1,
                freeze_generation: 0,
                permit_nonce,
                permit_digest,
            },
            operation: input.operation,
            transport_fingerprint: input.transport_fingerprint,
            expires_at_unix_ms,
        })
    }

    fn settle(
        &mut self,
        input: &FinalSettlementInput<'_>,
    ) -> Result<VerifiedSettlement, GatewayError> {
        Ok(VerifiedSettlement {
            mutation_id: input.subject.mutation_id.clone(),
            reservation_id: input.subject.reservation_id.clone(),
            result_digest: input.result_digest.to_string(),
            settlement_fingerprint: input.settlement_fingerprint,
        })
    }
}
