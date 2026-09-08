//! Bundle create/verify helpers for sealed preservation receipts.

use super::*;

pub(super) fn create_and_verify_bundle(
    repository: &RealRepository,
    bundle_path: &Path,
) -> Result<(), CapabilityError> {
    let bundle = bundle_path.to_string_lossy().into_owned();
    if !bundle_path.exists() {
        repository.workspace().git().run(
            Some(repository.workspace().repo_dir()),
            FileProtocol::Never,
            &["bundle", "create", &bundle, "--all"],
            &[],
        )?;
    }
    verify_bundle(repository.workspace(), bundle_path)
}

pub(super) fn verify_bundle(
    workspace: &crate::clone::PrivateClone,
    bundle_path: &Path,
) -> Result<(), CapabilityError> {
    let metadata = fs::symlink_metadata(bundle_path).map_err(|error| {
        PreservationError::ReceiptRefused(format!("preservation bundle missing: {error}"))
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(PreservationError::ReceiptRefused(
            "preservation bundle is not an ordinary file".into(),
        )
        .into());
    }
    let bundle = bundle_path.to_string_lossy().into_owned();
    workspace
        .git()
        .run(
            Some(workspace.repo_dir()),
            FileProtocol::Never,
            &["bundle", "verify", &bundle],
            &[],
        )
        .map(|_| ())
        .map_err(|error| {
            PreservationError::ReceiptRefused(format!("preservation bundle invalid: {error}"))
                .into()
        })
}

pub(super) fn verify_artifact_shape(destination: &Path) -> Result<(), PreservationError> {
    let entries = fs::read_dir(destination)
        .map_err(|error| PreservationError::ReceiptRefused(format!("read artifact: {error}")))?
        .map(|entry| entry.map(|value| value.file_name().to_string_lossy().into_owned()))
        .collect::<Result<BTreeSet<_>, _>>()
        .map_err(|error| PreservationError::ReceiptRefused(format!("read artifact: {error}")))?;
    let expected = EXPECTED_ARTIFACT_ENTRIES
        .into_iter()
        .map(str::to_owned)
        .collect::<BTreeSet<_>>();
    if entries == expected {
        Ok(())
    } else {
        Err(PreservationError::ReceiptRefused(
            "artifact entry set changed".into(),
        ))
    }
}

pub(super) fn seal_payload(
    seal: &[u8; 32],
    payload: &ReceiptPayload,
) -> Result<Digest, PreservationError> {
    let bytes = serde_json::to_vec(payload)
        .map_err(|error| PreservationError::Corrupt(format!("encode receipt payload: {error}")))?;
    let mut hasher = blake3::Hasher::new_keyed(seal);
    hasher.update(SEAL_DOMAIN);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    Digest::from_hex(hasher.finalize().to_hex().as_str())
        .map_err(|error| PreservationError::Corrupt(error.to_string()))
}

pub(super) fn preservation_state_digest(
    state: &PreservationState,
) -> Result<Digest, PreservationError> {
    let bytes = serde_json::to_vec(state)
        .map_err(|error| PreservationError::Corrupt(format!("encode state: {error}")))?;
    Ok(framed_digest(&[STATE_DOMAIN, &bytes]))
}

pub(super) fn encode_receipt(receipt: &SealedReceipt) -> Result<String, PreservationError> {
    serde_json::to_vec(receipt)
        .map(hex::encode)
        .map_err(|error| PreservationError::Corrupt(format!("encode receipt: {error}")))
}

pub(super) fn decode_receipt(token: &str) -> Result<SealedReceipt, PreservationError> {
    if token.is_empty()
        || token.len() > MAX_RECEIPT_HEX_BYTES
        || token.len() % 2 != 0
        || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(PreservationError::ReceiptRefused(
            "receipt encoding is invalid or oversized".into(),
        ));
    }
    let bytes = hex::decode(token)
        .map_err(|error| PreservationError::ReceiptRefused(format!("decode receipt: {error}")))?;
    let receipt: SealedReceipt = serde_json::from_slice(&bytes)
        .map_err(|error| PreservationError::ReceiptRefused(format!("parse receipt: {error}")))?;
    if encode_receipt(&receipt)? != token {
        return Err(PreservationError::ReceiptRefused(
            "receipt encoding is not canonical lowercase JSON hex".into(),
        ));
    }
    Ok(receipt)
}

pub(super) fn require_destination_identity(
    payload: &ReceiptPayload,
    identity: &DestinationIdentity,
) -> Result<(), PreservationError> {
    if identity.canonical.to_string_lossy() == payload.destination
        && identity.device == payload.destination_device
        && identity.inode == payload.destination_inode
    {
        Ok(())
    } else {
        Err(PreservationError::ReceiptRefused(
            "destination device or inode changed".into(),
        ))
    }
}

pub(super) fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}
