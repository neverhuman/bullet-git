//! Durable local replay state for authority-gated workspace mutations.
//!
//! This module deliberately does not issue authority. It records only the
//! exact subject and outcome supplied by a separately verified final-check
//! decision. A reservation left in flight across process restart is
//! `MUTATION_OUTCOME_UNKNOWN`; it is never silently re-authorized.

#[path = "mutation_recovery.rs"]
mod recovery;

use recovery::{load_record, load_record_for_append, scan_recovery};
pub use recovery::{IndeterminateMutation, IndeterminateMutationState, MutationRecoveryStatus};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use thiserror::Error;

const SCHEMA_VERSION: u32 = 1;
const MAX_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

/// Workspace operations that require a Kernel mutation reservation.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MutationOperation {
    /// Create a private workspace generation.
    CloneWorkspace,
    /// Apply a validated proposal.
    ApplyPatch,
    /// Materialize a checkpoint.
    Checkpoint,
    /// Prepare an exact Candidate.
    PrepareCandidate,
    /// Preserve a workspace outside its cleanup target.
    PreserveWorkspace,
    /// Remove a preservation-bound workspace.
    CleanupWorkspace,
}

impl MutationOperation {
    /// Stable operation label used by local receipt framing.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CloneWorkspace => "clone-workspace",
            Self::ApplyPatch => "apply-patch",
            Self::Checkpoint => "checkpoint",
            Self::PrepareCandidate => "prepare-candidate",
            Self::PreserveWorkspace => "preserve-workspace",
            Self::CleanupWorkspace => "cleanup-workspace",
        }
    }
}

/// Exact durable subject returned by a verified Kernel final check.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationSubject {
    /// Digest of the exact signed authority envelope checked by Kernel.
    pub authority_envelope_digest: String,
    /// Nonce of the exact authority token checked by Kernel.
    pub authority_token_nonce: String,
    /// Full 256-bit Mutation identity.
    pub mutation_id: String,
    /// Full 256-bit reservation identity.
    pub reservation_id: String,
    /// Operation authorized by the reservation.
    pub operation: MutationOperation,
    /// Frozen request digest from the shared contract.
    pub request_digest: String,
    /// Repository named by the verified authority and typed request.
    pub repository_id: String,
    /// Workspace named by the verified authority and typed request.
    pub workspace_id: String,
    /// Exact active workspace generation.
    pub workspace_generation: u64,
    /// Workspace nonce from the verified authority claims.
    pub workspace_nonce: String,
    /// Attempt incarnation named by the verified authority.
    pub attempt_id: String,
    /// Permanent, never-reused Attempt fence.
    pub attempt_fence: u64,
    /// Revocation epoch observed by the online final check.
    pub authority_epoch: u64,
    /// Freeze generation observed by the online final check.
    pub freeze_generation: u64,
    /// Nonce of the signed one-use mutation permit.
    pub permit_nonce: String,
    /// Digest of the verified signed permit, binding every permit claim.
    pub permit_digest: String,
}

impl MutationSubject {
    fn validate(&self) -> Result<(), MutationLedgerError> {
        validate_digest(&self.authority_envelope_digest)?;
        validate_digest(&self.authority_token_nonce)?;
        validate_id(&self.mutation_id, "mut_")?;
        validate_id(&self.reservation_id, "rsv_")?;
        validate_digest(&self.request_digest)?;
        validate_id(&self.repository_id, "rep_")?;
        validate_id(&self.workspace_id, "wsp_")?;
        validate_positive_generation(self.workspace_generation, "workspace_generation")?;
        validate_digest(&self.workspace_nonce)?;
        validate_id(&self.attempt_id, "atm_")?;
        validate_positive_generation(self.attempt_fence, "attempt_fence")?;
        validate_positive_generation(self.authority_epoch, "authority_epoch")?;
        if self.freeze_generation > MAX_SAFE_INTEGER {
            return Err(MutationLedgerError::InvalidSubject(
                "freeze_generation exceeds the interoperable integer range".into(),
            ));
        }
        validate_digest(&self.permit_nonce)?;
        validate_digest(&self.permit_digest)
    }
}

/// Terminal mutation outcome. `Unknown` never satisfies success policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MutationOutcome {
    /// The exact atomic mutation boundary committed.
    Committed,
    /// The mutation was proven not to have committed.
    Aborted,
    /// The durable outcome could not be classified.
    Unknown,
}

/// Durable terminal replay receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationResult {
    /// Exact subject that was settled.
    pub subject: MutationSubject,
    /// Terminal outcome.
    pub outcome: MutationOutcome,
    /// Digest of the typed result bytes.
    pub result_digest: String,
    /// Trusted completion time.
    pub completed_at_unix_ms: u64,
}

/// Result of reserving or settling one exact mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReplayDisposition {
    /// This process durably created the reservation.
    Fresh,
    /// An identical terminal result already exists.
    ExactReplay(Box<MutationResult>),
}

/// Fail-closed ledger error with a stable reason code.
#[derive(Debug, Error)]
pub enum MutationLedgerError {
    /// The caller supplied an invalid identifier, digest, or timestamp.
    #[error("invalid mutation ledger subject: {0}")]
    InvalidSubject(String),
    /// A Mutation ID was reused for a different subject or result.
    #[error("mutation replay conflicts with durable state: {0}")]
    ReplayConflict(String),
    /// A crash, partial record, or corruption makes the outcome unknowable.
    #[error("mutation outcome is unknown: {0}")]
    OutcomeUnknown(String),
    /// The filesystem operation failed before a trustworthy result existed.
    #[error("mutation ledger I/O failed: {0}")]
    Io(String),
}

impl MutationLedgerError {
    /// Stable protocol reason code.
    #[must_use]
    pub const fn reason_code(&self) -> &'static str {
        match self {
            Self::InvalidSubject(_) => "INVALID_MUTATION_SUBJECT",
            Self::ReplayConflict(_) => "AUTHORITY_REPLAY_CONFLICT",
            Self::OutcomeUnknown(_) => "MUTATION_OUTCOME_UNKNOWN",
            Self::Io(_) => "MUTATION_LEDGER_IO_FAILED",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case", deny_unknown_fields)]
enum LedgerEvent {
    Reserved {
        schema_version: u32,
        subject: MutationSubject,
    },
    Settled {
        schema_version: u32,
        subject: MutationSubject,
        outcome: MutationOutcome,
        result_digest: String,
        completed_at_unix_ms: u64,
    },
}

/// Append-only, one-file-per-Mutation replay ledger.
pub struct MutationLedger {
    root: PathBuf,
    owned_reservations: BTreeSet<String>,
    recovery: MutationRecoveryStatus,
}

impl MutationLedger {
    /// Open or create a replay ledger below an already selected private root.
    ///
    /// # Errors
    ///
    /// Returns `MUTATION_LEDGER_IO_FAILED` when the directory is unavailable.
    pub fn open(root: impl Into<PathBuf>) -> Result<Self, MutationLedgerError> {
        let root = root.into();
        fs::create_dir_all(&root).map_err(io_error)?;
        if !fs::symlink_metadata(&root)
            .map_err(io_error)?
            .file_type()
            .is_dir()
        {
            return Err(MutationLedgerError::Io(format!(
                "{} is not a directory",
                root.display()
            )));
        }
        let recovery = scan_recovery(&root)?;
        Ok(Self {
            root,
            owned_reservations: BTreeSet::new(),
            recovery,
        })
    }

    /// Read-only recovery facts reconstructed from the exact durable records.
    #[must_use]
    pub const fn recovery_status(&self) -> &MutationRecoveryStatus {
        &self.recovery
    }

    /// Refuse mutation when startup or an in-process write found ambiguity.
    pub fn require_writable(&self) -> Result<(), MutationLedgerError> {
        self.recovery.require_writable()
    }

    /// Reserve a Mutation ID exactly once.
    ///
    /// An identical terminal record is returned as an exact replay. An
    /// existing in-flight record is unknown, including after restart.
    pub fn reserve(
        &mut self,
        subject: &MutationSubject,
    ) -> Result<ReplayDisposition, MutationLedgerError> {
        self.require_writable()?;
        subject.validate()?;
        let path = self.record_path(subject);
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let persist = append_event(
                    &mut file,
                    &LedgerEvent::Reserved {
                        schema_version: SCHEMA_VERSION,
                        subject: subject.clone(),
                    },
                )
                .and_then(|()| sync_directory(&self.root));
                if let Err(error) = persist {
                    self.recovery.mark_corrupt();
                    return Err(outcome_unknown(
                        &path,
                        &format!("reservation durability is ambiguous: {error}"),
                    ));
                }
                self.owned_reservations.insert(subject.mutation_id.clone());
                Ok(ReplayDisposition::Fresh)
            }
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                let state = load_record(&path).inspect_err(|_| {
                    self.recovery.mark_corrupt();
                })?;
                require_same_subject(subject, &state.subject)?;
                match state.result {
                    Some(result) => Ok(ReplayDisposition::ExactReplay(Box::new(result))),
                    None => {
                        self.recovery.mark_indeterminate(
                            state.subject,
                            IndeterminateMutationState::InFlight,
                        );
                        Err(MutationLedgerError::OutcomeUnknown(format!(
                            "{} has no terminal settlement",
                            subject.mutation_id
                        )))
                    }
                }
            }
            Err(error) => Err(io_error(error)),
        }
    }

    /// Append a terminal settlement for a reservation created by this
    /// process, or return the identical durable terminal result.
    pub fn settle(
        &mut self,
        subject: &MutationSubject,
        outcome: MutationOutcome,
        result_digest: &str,
        completed_at_unix_ms: u64,
    ) -> Result<ReplayDisposition, MutationLedgerError> {
        self.require_writable()?;
        subject.validate()?;
        validate_digest(result_digest)?;
        if completed_at_unix_ms > MAX_SAFE_INTEGER {
            return Err(MutationLedgerError::InvalidSubject(
                "completion time exceeds the interoperable integer range".into(),
            ));
        }
        let path = self.record_path(subject);
        let (state, mut file) = load_record_for_append(&path).inspect_err(|_| {
            self.recovery.mark_corrupt();
        })?;
        require_same_subject(subject, &state.subject)?;
        let requested = MutationResult {
            subject: subject.clone(),
            outcome,
            result_digest: result_digest.to_owned(),
            completed_at_unix_ms,
        };
        if let Some(existing) = state.result {
            if existing == requested {
                return Ok(ReplayDisposition::ExactReplay(Box::new(existing)));
            }
            return Err(MutationLedgerError::ReplayConflict(format!(
                "{} already has a different terminal result",
                subject.mutation_id
            )));
        }
        if !self.owned_reservations.remove(&subject.mutation_id) {
            return Err(MutationLedgerError::OutcomeUnknown(format!(
                "{} was reserved by an earlier process",
                subject.mutation_id
            )));
        }
        if let Err(error) = append_event(
            &mut file,
            &LedgerEvent::Settled {
                schema_version: SCHEMA_VERSION,
                subject: subject.clone(),
                outcome,
                result_digest: result_digest.to_owned(),
                completed_at_unix_ms,
            },
        ) {
            self.recovery.mark_corrupt();
            return Err(outcome_unknown(
                &path,
                &format!("terminal settlement is not durably classified: {error}"),
            ));
        }
        if outcome == MutationOutcome::Unknown {
            self.recovery
                .mark_indeterminate(subject.clone(), IndeterminateMutationState::Unknown);
        }
        Ok(ReplayDisposition::Fresh)
    }

    fn record_path(&self, subject: &MutationSubject) -> PathBuf {
        self.root.join(format!("{}.jsonl", subject.mutation_id))
    }
}

fn append_event(file: &mut File, event: &LedgerEvent) -> Result<(), MutationLedgerError> {
    let encoded = serde_json::to_vec(event)
        .map_err(|error| MutationLedgerError::Io(format!("encode ledger event: {error}")))?;
    file.write_all(&encoded).map_err(io_error)?;
    file.write_all(b"\n").map_err(io_error)?;
    file.sync_all().map_err(io_error)
}

fn require_same_subject(
    requested: &MutationSubject,
    stored: &MutationSubject,
) -> Result<(), MutationLedgerError> {
    if requested == stored {
        return Ok(());
    }
    Err(MutationLedgerError::ReplayConflict(format!(
        "{} is already bound to another reservation, operation, or request",
        requested.mutation_id
    )))
}

fn validate_id(value: &str, prefix: &str) -> Result<(), MutationLedgerError> {
    let Some(hex) = value.strip_prefix(prefix) else {
        return Err(MutationLedgerError::InvalidSubject(format!(
            "identifier must start with {prefix}"
        )));
    };
    if !is_lower_hex(hex) {
        return Err(MutationLedgerError::InvalidSubject(
            "identifier must carry 64 lowercase hexadecimal characters".into(),
        ));
    }
    Ok(())
}

fn validate_digest(value: &str) -> Result<(), MutationLedgerError> {
    if is_lower_hex(value) {
        Ok(())
    } else {
        Err(MutationLedgerError::InvalidSubject(
            "digest must contain 64 lowercase hexadecimal characters".into(),
        ))
    }
}

fn validate_positive_generation(value: u64, name: &str) -> Result<(), MutationLedgerError> {
    if value == 0 || value > MAX_SAFE_INTEGER {
        return Err(MutationLedgerError::InvalidSubject(format!(
            "{name} must be a positive interoperable integer"
        )));
    }
    Ok(())
}

fn is_lower_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn sync_directory(path: &Path) -> Result<(), MutationLedgerError> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(io_error)
}

fn outcome_unknown(path: &Path, reason: &str) -> MutationLedgerError {
    MutationLedgerError::OutcomeUnknown(format!("{}: {reason}", path.display()))
}

fn io_error(error: io::Error) -> MutationLedgerError {
    MutationLedgerError::Io(error.to_string())
}
