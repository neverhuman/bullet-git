//! Refuse unqualified inherited descriptors; no unsafe pre-exec callback.
use super::{io, Result};
use rustix::fs::OFlags;
use std::collections::BTreeSet;
use std::fs::{self, File};
use std::io::Read;
use std::os::fd::RawFd;

pub(super) fn flags(text: &str) -> Result<u64> {
    let values: Vec<_> = text
        .lines()
        .filter_map(|line| line.strip_prefix("flags:"))
        .collect();
    if values.len() != 1 {
        return Err("DESCRIPTOR_FLAGS_AMBIGUOUS".into());
    }
    let value = values[0].trim();
    if value.is_empty() || !value.bytes().all(|byte| (b'0'..=b'7').contains(&byte)) {
        return Err("DESCRIPTOR_FLAGS_INVALID".into());
    }
    u64::from_str_radix(value, 8).map_err(|_| "DESCRIPTOR_FLAGS_INVALID".into())
}

pub(super) fn read_info(reader: impl Read) -> Result<String> {
    let mut text = String::new();
    reader.take(65_537).read_to_string(&mut text).map_err(io)?;
    if text.len() > 65_536 {
        return Err("DESCRIPTOR_INFO_LIMIT".into());
    }
    Ok(text)
}

// Called after record/stream/executable FD preparation, immediately before
// spawn. This binary installs no threads or asynchronous descriptor writers.
// A caller supplying a non-CLOEXEC descriptor gets a refusal, not silent leak.
pub(super) fn check(executable: RawFd) -> Result<()> {
    let entries = fs::read_dir("/proc/self/fdinfo").map_err(io)?;
    let mut seen = BTreeSet::new();
    let mut found_executable = false;
    for entry in entries {
        let entry = entry.map_err(io)?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "DESCRIPTOR_NAME_INVALID")?;
        if name.is_empty() || !name.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err("DESCRIPTOR_NAME_INVALID".into());
        }
        let fd: RawFd = name.parse().map_err(|_| "DESCRIPTOR_NAME_INVALID")?;
        if !seen.insert(fd) || seen.len() > 4096 {
            return Err("DESCRIPTOR_INVENTORY_INVALID".into());
        }
        let text = read_info(File::open(entry.path()).map_err(io)?)?;
        let cloexec = flags(&text)? & u64::from(OFlags::CLOEXEC.bits()) != 0;
        if fd == executable {
            if cloexec {
                return Err("EXECUTABLE_FD_NOT_INHERITABLE".into());
            }
            found_executable = true;
        } else if fd >= 3 && !cloexec {
            return Err(format!("INHERITED_DESCRIPTOR_REFUSED: {fd}"));
        }
    }
    if !found_executable {
        return Err("EXECUTABLE_FD_ABSENT".into());
    }
    Ok(())
}
