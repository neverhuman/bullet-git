//! Daemon-held sealed preservation receipts and cleanup authorization.

#[path = "preservation_cleanup.rs"]
mod cleanup;
use cleanup::verify_salvage_objects;

use crate::cas::ImmutableCas;
use crate::preservation_io::{
    copy_artifact_file, copy_artifact_tree, create_external_destination, destination_identity,
    hash_artifact, open_private_seal, sync_artifact, DestinationIdentity,
};
use crate::repository::{ExpectedAuthority, RealRepository};
use crate::safe_git::FileProtocol;
use crate::CapabilityError;
use bullet_git_journal::DurableJournal;
use bullet_git_types::{framed_digest, AuthorityEnvelope, Digest, GitOid};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

const SCHEMA_VERSION: u32 = 1;
const SEAL_DOMAIN: &[u8] = b"bullet-git-preservation-receipt-v1";
const STATE_DOMAIN: &[u8] = b"bullet-git-preservation-state-v1";
const MAX_RECEIPT_HEX_BYTES: usize = 64 * 1024;
const EXPECTED_ARTIFACT_ENTRIES: [&str; 5] = [
    "cas",
    "generation",
    "repository.bundle",
    "subject.json",
    "workspace.json",
];

/// Preservation and sealed-cleanup failure.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PreservationError {
    /// Destination is not a new canonical external directory.
    #[error("invalid preservation destination: {0}")]
    InvalidDestination(String),
    /// Source or preservation data is corrupt.
    #[error("corrupt preservation state: {0}")]
    Corrupt(String),
    /// Receipt, artifact, or current subject does not match.
    #[error("preservation receipt refused: {0}")]
    ReceiptRefused(String),
    /// The platform lacks an audited safety primitive.
    #[error("unsupported preservation backend: {0}")]
    Unsupported(String),
    /// Filesystem persistence failed.
    #[error("preservation io failure: {0}")]
    Io(String),
    /// Cleanup crossed its first destructive boundary, so completion is unknown.
    #[error("preservation cleanup outcome is unknown: {0}")]
    OutcomeUnknown(String),
}

impl PreservationError {
    /// Stable machine-readable reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidDestination(_) => "PRESERVATION_INVALID_DESTINATION",
            Self::Corrupt(_) => "PRESERVATION_CORRUPT",
            Self::ReceiptRefused(_) => "PRESERVATION_RECEIPT_REFUSED",
            Self::Unsupported(_) => "PRESERVATION_UNSUPPORTED",
            Self::Io(_) => "PRESERVATION_IO_FAILED",
            Self::OutcomeUnknown(_) => "PRESERVATION_OUTCOME_UNKNOWN",
        }
    }
}

/// One exact dirty, untracked, ignored, or deleted path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct WorkingEntry {
    pub(crate) path: String,
    pub(crate) status: String,
    pub(crate) kind: String,
    pub(crate) content_digest: Option<Digest>,
}

/// Exact workspace state bound into an artifact and receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct PreservationState {
    pub(crate) schema_version: u32,
    pub(crate) attempt_id: String,
    pub(crate) attempt_fence: u64,
    pub(crate) workspace_nonce_hex: String,
    pub(crate) generation: u64,
    pub(crate) git_tree: GitOid,
    pub(crate) generation_digest: Digest,
    pub(crate) dirty_untracked: Vec<WorkingEntry>,
    pub(crate) journal_start: u64,
    pub(crate) journal_end: u64,
    pub(crate) journal_root: Digest,
}

impl PreservationState {
    pub(crate) fn new(
        authority: &ExpectedAuthority,
        generation: u64,
        git_tree: GitOid,
        generation_digest: Digest,
        dirty_untracked: Vec<WorkingEntry>,
        journal_end: u64,
        journal_root: Digest,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            attempt_id: authority.attempt_id.clone(),
            attempt_fence: authority.attempt_fence,
            workspace_nonce_hex: hex::encode(authority.workspace_nonce),
            generation,
            git_tree,
            generation_digest,
            dirty_untracked,
            journal_start: u64::from(journal_end > 0),
            journal_end,
            journal_root,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptPayload {
    schema_version: u32,
    state_digest: Digest,
    artifact_digest: Digest,
    destination: String,
    destination_device: u64,
    destination_inode: u64,
    cleanup_target: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedReceipt {
    payload: ReceiptPayload,
    tag: Digest,
}

/// Opaque daemon-issued receipt returned to the controller.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PreservationReceipt {
    token: String,
    receipt_digest: Digest,
    destination: PathBuf,
    artifact_digest: Digest,
}

impl PreservationReceipt {
    /// Opaque sealed token required by cleanup.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// Digest of the exact encoded receipt.
    #[must_use]
    pub fn receipt_digest(&self) -> Digest {
        self.receipt_digest
    }

    /// Canonical preservation destination.
    #[must_use]
    pub fn destination(&self) -> &Path {
        &self.destination
    }

    /// Digest of every artifact entry and byte.
    #[must_use]
    pub fn artifact_digest(&self) -> Digest {
        self.artifact_digest
    }
}

/// Non-constructible authorization to delete one exact workspace target.
#[derive(Debug)]
pub(crate) struct CleanupPermit {
    attempt_id: String,
    workspace_nonce_hex: String,
    work_dir: PathBuf,
    receipt_digest: Digest,
    destination: PathBuf,
    destination_device: u64,
    destination_inode: u64,
    artifact_digest: Digest,
    state: PreservationState,
}

impl CleanupPermit {
    pub(crate) fn matches(&self, attempt_id: &str, nonce_hex: &str, work_dir: &Path) -> bool {
        self.attempt_id == attempt_id
            && self.workspace_nonce_hex == nonce_hex
            && self.work_dir == work_dir
    }

    pub(crate) fn receipt_digest(&self) -> Digest {
        self.receipt_digest
    }

    pub(crate) fn destination(&self) -> &Path {
        &self.destination
    }

    pub(crate) fn artifact_digest(&self) -> Digest {
        self.artifact_digest
    }
}

/// Persisted daemon-only seal authority. The key lives outside the clone.
pub struct PreservationAuthority {
    seal: [u8; 32],
}

impl PreservationAuthority {
    /// Open or create the private persisted seal under the daemon runtime.
    pub fn open(runtime_dir: &Path) -> Result<Self, PreservationError> {
        Ok(Self {
            seal: open_private_seal(runtime_dir)?,
        })
    }

    /// Write a complete salvage artifact and issue its sealed receipt.
    pub fn issue(
        &self,
        repository: &RealRepository,
        auth: &AuthorityEnvelope,
        destination: &Path,
    ) -> Result<PreservationReceipt, CapabilityError> {
        let before = repository.preservation_state(auth)?;
        let workspace = repository.workspace();
        let identity = create_external_destination(
            destination,
            &[workspace.work_dir(), workspace.runtime_dir()],
        )?;
        let subject_json = serde_json::to_vec(&before)
            .map_err(|error| PreservationError::Corrupt(format!("encode subject: {error}")))?;
        fs::write(identity.canonical.join("subject.json"), subject_json)
            .map_err(|error| PreservationError::Io(format!("write subject: {error}")))?;
        copy_artifact_tree(
            &workspace.active_generation_dir(),
            &identity.canonical.join("generation"),
        )?;
        copy_artifact_tree(
            &workspace.runtime_dir().join("cas"),
            &identity.canonical.join("cas"),
        )?;
        copy_artifact_file(
            &workspace.runtime_dir().join("manifest.json"),
            &identity.canonical.join("workspace.json"),
        )?;
        create_and_verify_bundle(repository, &identity.canonical.join("repository.bundle"))?;
        sync_artifact(&identity.canonical)?;
        verify_artifact_shape(&identity.canonical)?;
        verify_salvage_objects(&identity.canonical, &before)?;
        let artifact_digest = hash_artifact(&identity.canonical)?;
        let after = repository.preservation_state(auth)?;
        if before != after {
            return Err(PreservationError::ReceiptRefused(
                "workspace changed while preservation was being written".into(),
            )
            .into());
        }
        let payload = ReceiptPayload {
            schema_version: SCHEMA_VERSION,
            state_digest: preservation_state_digest(&before)?,
            artifact_digest,
            destination: identity.canonical.to_string_lossy().into_owned(),
            destination_device: identity.device,
            destination_inode: identity.inode,
            cleanup_target: workspace.work_dir().to_string_lossy().into_owned(),
        };
        let sealed = SealedReceipt {
            tag: seal_payload(&self.seal, &payload)?,
            payload,
        };
        let encoded = encode_receipt(&sealed)?;
        Ok(PreservationReceipt {
            receipt_digest: Digest::of(encoded.as_bytes()),
            destination: identity.canonical,
            artifact_digest,
            token: encoded,
        })
    }

    /// Verify a receipt, current workspace, artifact, and destination.
    fn authorize_cleanup(
        &self,
        repository: &RealRepository,
        auth: &AuthorityEnvelope,
        token: &str,
    ) -> Result<CleanupPermit, CapabilityError> {
        let sealed = decode_receipt(token)?;
        let expected_tag = seal_payload(&self.seal, &sealed.payload)?;
        if !constant_time_equal(expected_tag.as_bytes(), sealed.tag.as_bytes()) {
            return Err(PreservationError::ReceiptRefused("receipt seal is invalid".into()).into());
        }
        let state = repository.preservation_state(auth)?;
        if sealed.payload.schema_version != SCHEMA_VERSION
            || sealed.payload.state_digest != preservation_state_digest(&state)?
        {
            return Err(PreservationError::ReceiptRefused(
                "receipt subject no longer matches the workspace".into(),
            )
            .into());
        }
        let workspace = repository.workspace();
        if sealed.payload.cleanup_target != workspace.work_dir().to_string_lossy() {
            return Err(PreservationError::ReceiptRefused(
                "cleanup target does not match the sealed receipt".into(),
            )
            .into());
        }
        let destination = PathBuf::from(&sealed.payload.destination);
        let identity = destination_identity(&destination)?;
        require_destination_identity(&sealed.payload, &identity)?;
        verify_artifact_shape(&destination)?;
        let recorded: PreservationState = serde_json::from_slice(
            &fs::read(destination.join("subject.json")).map_err(|error| {
                PreservationError::ReceiptRefused(format!("read artifact subject: {error}"))
            })?,
        )
        .map_err(|error| {
            PreservationError::ReceiptRefused(format!("decode artifact subject: {error}"))
        })?;
        if recorded != state {
            return Err(PreservationError::ReceiptRefused(
                "artifact subject does not match current state".into(),
            )
            .into());
        }
        verify_salvage_objects(&destination, &state)?;
        verify_bundle(
            repository.workspace(),
            &destination.join("repository.bundle"),
        )?;
        if hash_artifact(&destination)? != sealed.payload.artifact_digest {
            return Err(PreservationError::ReceiptRefused("artifact digest changed".into()).into());
        }
        Ok(CleanupPermit {
            attempt_id: state.attempt_id.clone(),
            workspace_nonce_hex: state.workspace_nonce_hex.clone(),
            work_dir: workspace.work_dir().to_path_buf(),
            receipt_digest: Digest::of(token.as_bytes()),
            destination,
            destination_device: identity.device,
            destination_inode: identity.inode,
            artifact_digest: sealed.payload.artifact_digest,
            state,
        })
    }
}

fn create_and_verify_bundle(
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

fn verify_bundle(
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

fn verify_artifact_shape(destination: &Path) -> Result<(), PreservationError> {
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

fn seal_payload(seal: &[u8; 32], payload: &ReceiptPayload) -> Result<Digest, PreservationError> {
    let bytes = serde_json::to_vec(payload)
        .map_err(|error| PreservationError::Corrupt(format!("encode receipt payload: {error}")))?;
    let mut hasher = blake3::Hasher::new_keyed(seal);
    hasher.update(SEAL_DOMAIN);
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    Digest::from_hex(hasher.finalize().to_hex().as_str())
        .map_err(|error| PreservationError::Corrupt(error.to_string()))
}

fn preservation_state_digest(state: &PreservationState) -> Result<Digest, PreservationError> {
    let bytes = serde_json::to_vec(state)
        .map_err(|error| PreservationError::Corrupt(format!("encode state: {error}")))?;
    Ok(framed_digest(&[STATE_DOMAIN, &bytes]))
}

fn encode_receipt(receipt: &SealedReceipt) -> Result<String, PreservationError> {
    serde_json::to_vec(receipt)
        .map(hex::encode)
        .map_err(|error| PreservationError::Corrupt(format!("encode receipt: {error}")))
}

fn decode_receipt(token: &str) -> Result<SealedReceipt, PreservationError> {
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

fn require_destination_identity(
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

fn constant_time_equal(left: &[u8], right: &[u8]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right)
            .fold(0_u8, |difference, (a, b)| difference | (a ^ b))
            == 0
}
