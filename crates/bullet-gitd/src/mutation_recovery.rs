//! Bounded read-only recovery scan for the durable mutation ledger.

use super::{
    outcome_unknown, validate_digest, LedgerEvent, MutationLedgerError, MutationOutcome,
    MutationResult, MutationSubject, MAX_SAFE_INTEGER, SCHEMA_VERSION,
};
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};
use std::fmt;
use std::fs::{self, File};
use std::io::BufReader;
use std::path::{Path, PathBuf};

const MAX_LEDGER_RECORDS: usize = 4_096;
const MAX_LEDGER_RECORD_BYTES: u64 = 2 * (crate::protocol::MAX_FRAME_BYTES as u64 + 1);

/// Locally observable state of an indeterminate mutation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IndeterminateMutationState {
    /// A durable reservation has no terminal settlement.
    InFlight,
    /// A durable terminal settlement explicitly classified the outcome UNKNOWN.
    Unknown,
}

/// Exact subject available to read-only salvage tooling.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IndeterminateMutation {
    /// Exact durable authority subject.
    pub subject: MutationSubject,
    /// Locally observable recovery state.
    pub state: IndeterminateMutationState,
}

/// Bounded recovery status reconstructed when the ledger opens.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MutationRecoveryStatus {
    indeterminate: Vec<IndeterminateMutation>,
    corrupt_record_count: usize,
}

impl MutationRecoveryStatus {
    /// Whether all mutation must remain frozen pending authenticated recovery.
    #[must_use]
    pub fn is_frozen(&self) -> bool {
        !self.indeterminate.is_empty() || self.corrupt_record_count != 0
    }

    /// Exact locally validated subjects that salvage tooling may inspect.
    #[must_use]
    pub fn indeterminate(&self) -> &[IndeterminateMutation] {
        &self.indeterminate
    }

    /// Number of entries whose exact subject could not be trusted.
    #[must_use]
    pub const fn corrupt_record_count(&self) -> usize {
        self.corrupt_record_count
    }

    pub(super) fn require_writable(&self) -> Result<(), MutationLedgerError> {
        if self.is_frozen() {
            return Err(MutationLedgerError::OutcomeUnknown(format!(
                "ledger recovery is frozen with {} indeterminate subject(s) and {} corrupt record(s)",
                self.indeterminate.len(),
                self.corrupt_record_count
            )));
        }
        Ok(())
    }

    pub(super) fn mark_indeterminate(
        &mut self,
        subject: MutationSubject,
        state: IndeterminateMutationState,
    ) {
        self.indeterminate
            .push(IndeterminateMutation { subject, state });
    }

    pub(super) fn mark_corrupt(&mut self) {
        self.corrupt_record_count = self.corrupt_record_count.saturating_add(1);
    }
}

pub(super) fn scan_recovery(root: &Path) -> Result<MutationRecoveryStatus, MutationLedgerError> {
    let mut status = MutationRecoveryStatus::default();
    let mut paths = Vec::<PathBuf>::new();
    for entry in fs::read_dir(root).map_err(super::io_error)? {
        if paths.len() == MAX_LEDGER_RECORDS {
            status.mark_corrupt();
            break;
        }
        paths.push(entry.map_err(super::io_error)?.path());
    }
    paths.sort();
    for path in paths {
        let record = match load_record(&path) {
            Ok(record) => record,
            Err(_) => {
                status.mark_corrupt();
                continue;
            }
        };
        let expected_name = format!("{}.jsonl", record.subject.mutation_id);
        if path.file_name().and_then(|name| name.to_str()) != Some(expected_name.as_str()) {
            status.mark_corrupt();
            continue;
        }
        match record.result {
            None => status.mark_indeterminate(record.subject, IndeterminateMutationState::InFlight),
            Some(result) if result.outcome == MutationOutcome::Unknown => {
                status.mark_indeterminate(result.subject, IndeterminateMutationState::Unknown)
            }
            Some(_) => {}
        }
    }
    Ok(status)
}

pub(super) struct LoadedRecord {
    pub(super) subject: MutationSubject,
    pub(super) result: Option<MutationResult>,
}

pub(super) fn load_record(path: &Path) -> Result<LoadedRecord, MutationLedgerError> {
    load_record_with_access(path, false).map(|(record, _)| record)
}

pub(super) fn load_record_for_append(
    path: &Path,
) -> Result<(LoadedRecord, File), MutationLedgerError> {
    load_record_with_access(path, true)
}

fn load_record_with_access(
    path: &Path,
    writable: bool,
) -> Result<(LoadedRecord, File), MutationLedgerError> {
    let file = open_record(path, writable)?;
    let metadata = file
        .metadata()
        .map_err(|error| outcome_unknown(path, &error.to_string()))?;
    if !metadata.file_type().is_file() {
        return Err(outcome_unknown(path, "ledger record is not a regular file"));
    }
    if metadata.len() > MAX_LEDGER_RECORD_BYTES {
        return Err(outcome_unknown(
            path,
            "ledger record exceeds total byte bound",
        ));
    }
    let mut reader = BufReader::new(&file);
    let mut events = Vec::with_capacity(2);
    while let Some(line) = crate::protocol::read_frame(&mut reader)
        .map_err(|error| outcome_unknown(path, &error.to_string()))?
    {
        if line.is_empty() {
            return Err(outcome_unknown(path, "empty ledger frame"));
        }
        if events.len() == 2 {
            return Err(outcome_unknown(path, "too many ledger events"));
        }
        let value =
            decode_strict_json(&line).map_err(|error| outcome_unknown(path, &error.to_string()))?;
        let event = serde_json::from_value::<LedgerEvent>(value)
            .map_err(|error| outcome_unknown(path, &error.to_string()))?;
        events.push(event);
    }
    let Some(LedgerEvent::Reserved {
        schema_version,
        subject,
    }) = events.first()
    else {
        return Err(outcome_unknown(path, "missing initial reservation"));
    };
    if *schema_version != SCHEMA_VERSION {
        return Err(outcome_unknown(
            path,
            "unsupported or impossible event sequence",
        ));
    }
    subject
        .validate()
        .map_err(|error| outcome_unknown(path, &error.to_string()))?;
    let result = match events.get(1) {
        None => None,
        Some(LedgerEvent::Settled {
            schema_version,
            subject: settled_subject,
            outcome,
            result_digest,
            completed_at_unix_ms,
        }) => {
            if *schema_version != SCHEMA_VERSION
                || settled_subject != subject
                || *completed_at_unix_ms > MAX_SAFE_INTEGER
                || validate_digest(result_digest).is_err()
            {
                return Err(outcome_unknown(path, "invalid terminal settlement"));
            }
            Some(MutationResult {
                subject: subject.clone(),
                outcome: *outcome,
                result_digest: result_digest.clone(),
                completed_at_unix_ms: *completed_at_unix_ms,
            })
        }
        Some(LedgerEvent::Reserved { .. }) => {
            return Err(outcome_unknown(path, "duplicate reservation"));
        }
    };
    Ok((
        LoadedRecord {
            subject: subject.clone(),
            result,
        },
        file,
    ))
}

#[cfg(unix)]
fn open_record(path: &Path, writable: bool) -> Result<File, MutationLedgerError> {
    use rustix::fs::{open, Mode, OFlags};

    let access = if writable {
        OFlags::RDWR | OFlags::APPEND
    } else {
        OFlags::RDONLY
    };
    open(
        path,
        access | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map(File::from)
    .map_err(|error| outcome_unknown(path, &error.to_string()))
}

#[cfg(not(unix))]
fn open_record(path: &Path, _writable: bool) -> Result<File, MutationLedgerError> {
    Err(outcome_unknown(
        path,
        "persisted ledger recovery is unsupported on this platform",
    ))
}

fn decode_strict_json(input: &str) -> Result<Value, serde_json::Error> {
    let mut deserializer = serde_json::Deserializer::from_str(input);
    let value = StrictValueSeed.deserialize(&mut deserializer)?;
    deserializer.end()?;
    Ok(value)
}

struct StrictValueSeed;

impl<'de> DeserializeSeed<'de> for StrictValueSeed {
    type Value = Value;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictValueVisitor)
    }
}

struct StrictValueVisitor;

impl<'de> Visitor<'de> for StrictValueVisitor {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("JSON without duplicate object keys")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(Value::Bool(value))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(Value::Number(Number::from(value)))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("non-finite JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(Value::String(value))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(Value::Null)
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        StrictValueSeed.deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(1_024));
        while let Some(value) = sequence.next_element_seed(StrictValueSeed)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut values = Map::new();
        while let Some(key) = object.next_key::<String>()? {
            if values.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate JSON key: {key}")));
            }
            values.insert(key, object.next_value_seed(StrictValueSeed)?);
        }
        Ok(Value::Object(values))
    }
}
