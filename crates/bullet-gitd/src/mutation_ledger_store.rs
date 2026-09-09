//! Durable append/open for MutationLedger.

use super::*;

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
pub(super) enum LedgerEvent {
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
