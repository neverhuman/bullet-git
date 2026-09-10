//! Receipt-gated cleanup reserves durably without any Kernel read-back.

use super::*;
use tempfile::TempDir;

const ATTEMPT: &str = "atm_1111111111111111111111111111111111111111111111111111111111111111";
const NONCE: [u8; 32] = [9; 32];
const FENCE: u64 = 7;
const REPOSITORY: &str = "rep_3333333333333333333333333333333333333333333333333333333333333333";
const WORKSPACE: &str = "wsp_4444444444444444444444444444444444444444444444444444444444444444";
const RECEIPT_TOKEN: &str = "sealed-preservation-receipt-token";
const RESULT_DIGEST: &str = "5555555555555555555555555555555555555555555555555555555555555555";

/// A checker that fails the test if a receipt-gated cleanup consults it.
struct NeverCalledCheck;

impl FinalAuthorityCheck for NeverCalledCheck {
    fn check(&mut self, _input: &FinalCheckInput<'_>) -> Result<VerifiedDecision, GatewayError> {
        panic!("receipt-gated cleanup must not run an online Kernel final check")
    }

    fn settle(
        &mut self,
        _input: &FinalSettlementInput<'_>,
    ) -> Result<VerifiedSettlement, GatewayError> {
        panic!("receipt-gated cleanup must not run an online Kernel settlement")
    }
}

fn receipt_gateway(temp: &TempDir) -> AuthorityGateway {
    AuthorityGateway {
        checker: Box::new(NeverCalledCheck),
        clock: Box::new(SystemClock),
        ledger: Some(MutationLedger::open(temp.path()).expect("ledger")),
        ledger_root: None,
    }
}

fn authority() -> Value {
    serde_json::json!({"attempt_id": ATTEMPT, "attempt_fence": FENCE})
}

fn params() -> Value {
    serde_json::json!({
        "preservation_receipt": RECEIPT_TOKEN,
        "deleted_at": "2026-09-09T00:00:00Z",
    })
}

fn receipt_digest() -> String {
    Digest::of(RECEIPT_TOKEN.as_bytes()).to_hex()
}

fn receipt<'a>(digest: &'a str) -> ReceiptSubject<'a> {
    ReceiptSubject {
        receipt_token: RECEIPT_TOKEN,
        receipt_digest: digest,
        attempt_id: ATTEMPT,
        attempt_fence: FENCE,
        workspace_nonce: &NONCE,
        repository_id: REPOSITORY,
        workspace_id: WORKSPACE,
        workspace_generation: 1,
    }
}

fn fresh(gateway: &mut AuthorityGateway, digest: &str) -> MutationPermit {
    match gateway.authorize_by_preservation_receipt(&authority(), &params(), &receipt(digest)) {
        Ok(ReceiptAuthorization::Fresh(permit)) => *permit,
        Ok(ReceiptAuthorization::Replay(_)) => panic!("unexpected replay"),
        Err(error) => panic!("receipt authorization refused: {error}"),
    }
}

#[test]
fn sealed_receipt_reserves_and_settles_without_a_kernel_permit() {
    let temp = TempDir::new().expect("tempdir");
    let mut gateway = receipt_gateway(&temp);
    let digest = receipt_digest();
    let permit = fresh(&mut gateway, &digest);
    assert_eq!(
        permit.subject.operation,
        MutationOperation::CleanupWorkspace
    );
    assert_eq!(permit.subject.attempt_id, ATTEMPT);
    assert_eq!(permit.subject.attempt_fence, FENCE);
    assert_eq!(permit.subject.workspace_nonce, hex::encode(NONCE));
    assert_eq!(permit.subject.authority_token_nonce, digest);
    let pending = gateway
        .consume_by_preservation_receipt(permit, &authority(), &params())
        .expect("consume without a Kernel permit");
    gateway
        .settle_locally(pending, MutationOutcome::Committed, RESULT_DIGEST)
        .expect("local settlement");
}

#[test]
fn exact_replay_returns_the_durable_result_and_never_a_second_permit() {
    let temp = TempDir::new().expect("tempdir");
    let mut gateway = receipt_gateway(&temp);
    let digest = receipt_digest();
    let permit = fresh(&mut gateway, &digest);
    let pending = gateway
        .consume_by_preservation_receipt(permit, &authority(), &params())
        .expect("consume");
    gateway
        .settle_locally(pending, MutationOutcome::Committed, RESULT_DIGEST)
        .expect("local settlement");
    match gateway.authorize_by_preservation_receipt(&authority(), &params(), &receipt(&digest)) {
        Ok(ReceiptAuthorization::Replay(result)) => {
            assert_eq!(result.outcome, MutationOutcome::Committed);
            assert_eq!(result.result_digest, RESULT_DIGEST);
            assert_eq!(
                result.subject.operation,
                MutationOperation::CleanupWorkspace
            );
            assert_eq!(result.subject.authority_token_nonce, digest);
        }
        Ok(ReceiptAuthorization::Fresh(_)) => panic!("replay minted a second permit"),
        Err(error) => panic!("replay refused instead of returning the durable result: {error}"),
    }
}

#[test]
fn an_unsettled_reservation_stays_unknown_rather_than_reauthorizing() {
    let temp = TempDir::new().expect("tempdir");
    let mut gateway = receipt_gateway(&temp);
    let digest = receipt_digest();
    let permit = fresh(&mut gateway, &digest);
    drop(permit);
    let error =
        match gateway.authorize_by_preservation_receipt(&authority(), &params(), &receipt(&digest))
        {
            Ok(_) => panic!("an in-flight reservation was re-authorized"),
            Err(error) => error,
        };
    assert_eq!(error.reason_code(), "MUTATION_OUTCOME_UNKNOWN");
}

#[test]
fn every_identifier_binds_the_exact_receipt_and_writer_incarnation() {
    let digest = receipt_digest();
    let fingerprint = Digest::of(b"request");
    let subject = receipt_mutation_subject(&receipt(&digest), fingerprint);
    let other_digest = Digest::of(b"another sealed receipt").to_hex();
    let other = receipt_mutation_subject(&receipt(&other_digest), fingerprint);
    assert_ne!(subject.mutation_id, other.mutation_id);
    assert_ne!(subject.reservation_id, other.reservation_id);
    assert_ne!(subject.permit_nonce, other.permit_nonce);
    assert_ne!(subject.permit_digest, other.permit_digest);
    assert_ne!(subject.mutation_id[4..], subject.reservation_id[4..]);
    assert_eq!(subject.request_digest, fingerprint.to_hex());
    assert_eq!(
        subject.authority_envelope_digest,
        Digest::of(RECEIPT_TOKEN.as_bytes()).to_hex()
    );
    let mut fenced = receipt(&digest);
    fenced.attempt_fence = FENCE + 1;
    assert_ne!(
        subject.mutation_id,
        receipt_mutation_subject(&fenced, fingerprint).mutation_id
    );
}
