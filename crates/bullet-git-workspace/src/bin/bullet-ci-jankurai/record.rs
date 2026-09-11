//! One-use private JSONL request/outcome record, durable before native spawn.
use super::{io, paths, Result};
use rustix::fs::{openat, Mode, OFlags};
use serde_json::{json, Value};
use std::fs::File;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) struct Record {
    pub(super) file: File,
    parent: File,
    name: String,
    sequence: u64,
}

impl Record {
    pub(super) fn new(path: &str) -> Result<Self> {
        let (parent, name, _) = paths::open_parent(path)?;
        let file = Self::create(&parent, &name)?;
        parent.sync_all().map_err(io)?;
        Ok(Self {
            file,
            parent,
            name,
            sequence: 0,
        })
    }

    fn create(parent: &File, name: &str) -> Result<File> {
        let flags =
            OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC;
        Ok(File::from(
            openat(parent, name, flags, Mode::from_raw_mode(0o600)).map_err(io)?,
        ))
    }

    pub(super) fn append(&mut self, event: &str, fields: Value) -> Result<()> {
        let mut row = json!({"schema": "bullet.local-auditor-tool.v1", "sequence": self.sequence,
            "time_ns": SystemTime::now().duration_since(UNIX_EPOCH).map_err(io)?.as_nanos().to_string(),
            "event": event, "evidence_class": "LOCAL_TOOL_DIAGNOSTIC"});
        row.as_object_mut()
            .ok_or("RECORD_OBJECT_REQUIRED")?
            .extend(fields.as_object().ok_or("RECORD_FIELDS_REQUIRED")?.clone());
        let mut bytes = serde_json::to_vec(&row).map_err(io)?;
        bytes.push(b'\n');
        self.file.write_all(&bytes).map_err(io)?;
        self.file.sync_all().map_err(io)?;
        self.sequence += 1;
        Ok(())
    }

    pub(super) fn stream(&self, suffix: &str) -> Result<File> {
        let stream = Self::create(&self.parent, &format!("{}{suffix}", self.name))?;
        self.parent.sync_all().map_err(io)?;
        Ok(stream)
    }
}
