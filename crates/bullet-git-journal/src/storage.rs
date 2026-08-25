//! Immutable batch-file storage and recovery for the durable journal.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use bullet_git_types::{frame, Digest};
use serde::{Deserialize, Serialize};

use crate::{durable::JournalError, JournalOp};

const SCHEMA_VERSION: u32 = 2;
const DOMAIN: &[u8] = b"bullet-git-journal-batch-v2";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct StoredBatch {
    pub(super) schema_version: u32,
    pub(super) start_seq: u64,
    pub(super) end_seq: u64,
    pub(super) previous_checksum: Option<Digest>,
    pub(super) ops: Vec<JournalOp>,
    pub(super) checksum: Digest,
}

impl StoredBatch {
    pub(super) fn new(
        start_seq: u64,
        end_seq: u64,
        previous_checksum: Option<Digest>,
        ops: Vec<JournalOp>,
    ) -> Self {
        let checksum = batch_checksum(previous_checksum.as_ref(), &ops);
        Self {
            schema_version: SCHEMA_VERSION,
            start_seq,
            end_seq,
            previous_checksum,
            ops,
            checksum,
        }
    }
}

pub(super) fn load_batches(
    directory: &Path,
) -> Result<(Vec<JournalOp>, Option<Digest>), JournalError> {
    let mut batches = Vec::new();
    for entry in fs::read_dir(directory).map_err(|error| io("read journal", error))? {
        let entry = entry.map_err(|error| io("read journal entry", error))?;
        let file_type = entry
            .file_type()
            .map_err(|error| io("inspect journal entry", error))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if file_type.is_file() {
            if let Some(range) = parse_batch_name(&name) {
                batches.push((range, entry.path()));
                continue;
            }
            if is_temp_name(&name) {
                continue;
            }
        }
        return Err(JournalError::Corrupt(format!(
            "unexpected journal entry {name:?}"
        )));
    }
    batches.sort_by_key(|(range, _)| *range);

    let mut ops = Vec::new();
    let mut previous = None;
    let mut expected = 1_u64;
    for ((file_start, file_end), path) in batches {
        let bytes = fs::read(&path).map_err(|error| io("read journal batch", error))?;
        let batch: StoredBatch = serde_json::from_slice(&bytes).map_err(|error| {
            JournalError::Corrupt(format!("{} is invalid JSON: {error}", path.display()))
        })?;
        validate_batch(&batch, file_start, file_end, expected, previous.as_ref())?;
        expected = batch
            .end_seq
            .checked_add(1)
            .ok_or_else(|| JournalError::Corrupt("sequence overflow".into()))?;
        previous = Some(batch.checksum);
        ops.extend(batch.ops);
    }
    Ok((ops, previous))
}

pub(super) fn publish_batch(directory: &Path, batch: &StoredBatch) -> Result<(), JournalError> {
    let mut bytes = serde_json::to_vec(batch)
        .map_err(|error| JournalError::Corrupt(format!("encode batch: {error}")))?;
    bytes.push(b'\n');
    let final_path = directory.join(batch_name(batch.start_seq, batch.end_seq));
    if final_path.exists() {
        return Err(JournalError::Corrupt(format!(
            "batch {} already exists",
            final_path.display()
        )));
    }
    let (staging, mut file) = create_staging_file(directory, batch)?;
    if let Err(error) = file.write_all(&bytes).and_then(|()| file.sync_all()) {
        drop(file);
        let _ = fs::remove_file(&staging);
        return Err(io("write journal batch", error));
    }
    drop(file);
    if let Err(error) = fs::hard_link(&staging, &final_path) {
        let _ = fs::remove_file(&staging);
        return if error.kind() == std::io::ErrorKind::AlreadyExists {
            Err(JournalError::Corrupt(format!(
                "batch {} already exists",
                final_path.display()
            )))
        } else {
            Err(io("publish journal batch", error))
        };
    }
    if sync_directory(directory).is_err() {
        return Err(JournalError::Poisoned);
    }
    if fs::remove_file(&staging).is_ok() {
        let _ = sync_directory(directory);
    }
    Ok(())
}

pub(super) fn prepare_directory(directory: &Path) -> Result<(), JournalError> {
    match fs::symlink_metadata(directory) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => Ok(()),
        Ok(_) => Err(JournalError::Corrupt(format!(
            "{} is not an ordinary directory",
            directory.display()
        ))),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(directory).map_err(|error| io("create journal", error))?;
            sync_directory(directory)?;
            if let Some(parent) = directory.parent() {
                sync_directory(parent)?;
            }
            Ok(())
        }
        Err(error) => Err(io("inspect journal", error)),
    }
}

fn validate_batch(
    batch: &StoredBatch,
    file_start: u64,
    file_end: u64,
    expected: u64,
    previous: Option<&Digest>,
) -> Result<(), JournalError> {
    if batch.schema_version != SCHEMA_VERSION {
        return Err(JournalError::Corrupt(format!(
            "unsupported schema {}",
            batch.schema_version
        )));
    }
    if batch.start_seq != file_start || batch.end_seq != file_end || batch.start_seq != expected {
        return Err(JournalError::Corrupt(format!(
            "sequence gap or filename mismatch at {file_start}-{file_end}, expected {expected}"
        )));
    }
    if batch.ops.is_empty() || batch.previous_checksum.as_ref() != previous {
        return Err(JournalError::Corrupt(
            "empty batch or checksum-chain mismatch".into(),
        ));
    }
    for (offset, op) in batch.ops.iter().enumerate() {
        let offset = u64::try_from(offset)
            .map_err(|_| JournalError::Corrupt("batch is too large".into()))?;
        let wanted = batch
            .start_seq
            .checked_add(offset)
            .ok_or_else(|| JournalError::Corrupt("sequence overflow".into()))?;
        let content_shape_valid = match op.kind {
            crate::JournalOpKind::Write => op.after.is_some(),
            crate::JournalOpKind::Delete => op.before.is_some() && op.after.is_none(),
        };
        if op.seq != wanted || op.path.is_empty() || op.path.contains('\0') || !content_shape_valid
        {
            return Err(JournalError::Corrupt(format!(
                "invalid operation at sequence {wanted}"
            )));
        }
    }
    if batch.ops.last().is_none_or(|op| op.seq != batch.end_seq) {
        return Err(JournalError::Corrupt("batch end sequence mismatch".into()));
    }
    let actual = batch_checksum(previous, &batch.ops);
    if actual != batch.checksum {
        return Err(JournalError::Corrupt(format!(
            "checksum mismatch at {}-{}",
            batch.start_seq, batch.end_seq
        )));
    }
    Ok(())
}

fn batch_checksum(previous: Option<&Digest>, ops: &[JournalOp]) -> Digest {
    let mut bytes = Vec::new();
    frame(&mut bytes, DOMAIN);
    match previous {
        Some(digest) => {
            frame(&mut bytes, b"previous");
            frame(&mut bytes, digest.as_bytes());
        }
        None => frame(&mut bytes, b"genesis"),
    }
    frame(&mut bytes, &(ops.len() as u64).to_le_bytes());
    for op in ops {
        frame(&mut bytes, &op.seq.to_le_bytes());
        frame(&mut bytes, op.kind.frame_tag());
        frame(&mut bytes, op.path.as_bytes());
        frame_optional_digest(&mut bytes, op.before.as_ref());
        frame_optional_digest(&mut bytes, op.after.as_ref());
    }
    Digest::of(&bytes)
}

fn frame_optional_digest(bytes: &mut Vec<u8>, digest: Option<&Digest>) {
    match digest {
        Some(digest) => {
            frame(bytes, b"present");
            frame(bytes, digest.as_bytes());
        }
        None => frame(bytes, b"absent"),
    }
}

fn create_staging_file(
    directory: &Path,
    batch: &StoredBatch,
) -> Result<(PathBuf, File), JournalError> {
    for attempt in 0_u16..128 {
        let name = format!(
            ".batch-{:020}-{:020}-{}-{}-{attempt}.tmp",
            batch.start_seq,
            batch.end_seq,
            std::process::id(),
            batch.checksum.to_hex()
        );
        let path = directory.join(name);
        match OpenOptions::new().create_new(true).write(true).open(&path) {
            Ok(file) => return Ok((path, file)),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io("create journal staging file", error)),
        }
    }
    Err(JournalError::Io(
        "could not allocate a unique journal staging file".into(),
    ))
}

fn batch_name(start: u64, end: u64) -> String {
    format!("{start:020}-{end:020}.json")
}

fn parse_batch_name(name: &str) -> Option<(u64, u64)> {
    let stem = name.strip_suffix(".json")?;
    let (start, end) = stem.split_once('-')?;
    if start.len() != 20
        || end.len() != 20
        || !start.bytes().all(|byte| byte.is_ascii_digit())
        || !end.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some((start.parse().ok()?, end.parse().ok()?))
}

fn is_temp_name(name: &str) -> bool {
    let stem = match name
        .strip_prefix(".batch-")
        .and_then(|name| name.strip_suffix(".tmp"))
    {
        Some(stem) => stem,
        None => return false,
    };
    let fields = stem.split('-').collect::<Vec<_>>();
    fields.len() == 5
        && fields[0].len() == 20
        && fields[1].len() == 20
        && fields[0].bytes().all(|byte| byte.is_ascii_digit())
        && fields[1].bytes().all(|byte| byte.is_ascii_digit())
        && !fields[2].is_empty()
        && fields[2].bytes().all(|byte| byte.is_ascii_digit())
        && fields[3].len() == 64
        && fields[3]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        && !fields[4].is_empty()
        && fields[4].bytes().all(|byte| byte.is_ascii_digit())
}

#[cfg(unix)]
fn sync_directory(directory: &Path) -> Result<(), JournalError> {
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|error| io("sync journal directory", error))
}

#[cfg(not(unix))]
fn sync_directory(_directory: &Path) -> Result<(), JournalError> {
    Ok(())
}

fn io(context: &str, error: std::io::Error) -> JournalError {
    JournalError::Io(format!("{context}: {error}"))
}
