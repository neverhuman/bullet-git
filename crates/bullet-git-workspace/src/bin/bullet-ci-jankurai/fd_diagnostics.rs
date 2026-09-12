//! Test-only metadata observations, never descriptor admission or cleanup.
use serde_json::{json, Value};
use std::{fs, io::Read, os::unix::fs::MetadataExt};

const FD_LIMIT: usize = 4096;
const SUBJECT_LIMIT: usize = 32;
const ANCESTOR_LIMIT: usize = 8;

fn text(path: &str) -> Result<String, &'static str> {
    let file = fs::File::open(path).map_err(|_| "METADATA_OPEN_FAILED")?;
    let mut result = String::new();
    file.take(65_537)
        .read_to_string(&mut result)
        .map_err(|_| "METADATA_READ_FAILED")?;
    if result.len() > 65_536 {
        return Err("METADATA_SIZE_LIMIT");
    }
    Ok(result)
}

fn process(pid: u32) -> Result<(u32, u64), &'static str> {
    let stat = text(&format!("/proc/{pid}/stat"))?;
    // The parenthesized command name is neither emitted nor trusted as identity.
    let (_, fields) = stat.rsplit_once(')').ok_or("PROCESS_STAT_INVALID")?;
    let values: Vec<_> = fields.split_whitespace().collect();
    let parent = values.get(1).ok_or("PROCESS_STAT_INVALID")?;
    let start = values.get(19).ok_or("PROCESS_STAT_INVALID")?;
    Ok((
        parent.parse().map_err(|_| "PROCESS_STAT_INVALID")?,
        start.parse().map_err(|_| "PROCESS_STAT_INVALID")?,
    ))
}

fn descriptor(pid: u32, fd: u32) -> Result<Value, &'static str> {
    let path = format!("/proc/{pid}/fd/{fd}");
    // stat follows only the proc descriptor reference; never open/read its
    // target, readlink its name, or consume a socket/pipe/file's contents.
    let before = fs::metadata(&path).map_err(|_| "FD_STAT_FAILED")?;
    let info = text(&format!("/proc/{pid}/fdinfo/{fd}"))?;
    let mut fields = info.lines().filter_map(|line| line.strip_prefix("flags:"));
    let value = fields.next().ok_or("FD_FLAGS_INVALID")?.trim();
    if fields.next().is_some()
        || value.is_empty()
        || !value.bytes().all(|byte| (b'0'..=b'7').contains(&byte))
    {
        return Err("FD_FLAGS_INVALID");
    }
    let flags = u64::from_str_radix(value, 8).map_err(|_| "FD_FLAGS_INVALID")?;
    let after = fs::metadata(&path).map_err(|_| "FD_STAT_FAILED")?;
    if (before.dev(), before.ino(), before.mode()) != (after.dev(), after.ino(), after.mode()) {
        return Err("FD_IDENTITY_CHANGED");
    }
    Ok(json!({"fd":fd,"device":before.dev(),"inode":before.ino(),
        "mode":before.mode(),"uid":before.uid(),"gid":before.gid(),"flags":flags,
        "cloexec":flags & u64::from(rustix::fs::OFlags::CLOEXEC.bits()) != 0}))
}

fn inventory(pid: u32) -> Result<Vec<u32>, &'static str> {
    let entries = fs::read_dir(format!("/proc/{pid}/fd")).map_err(|_| "FD_LIST_FAILED")?;
    let mut result = Vec::new();
    for entry in entries.take(FD_LIMIT + 1) {
        if result.len() == FD_LIMIT {
            return Err("FD_LIST_LIMIT");
        }
        let entry = entry.map_err(|_| "FD_ENTRY_FAILED")?;
        result.push(
            entry
                .file_name()
                .to_str()
                .ok_or("FD_NAME_INVALID")?
                .parse()
                .map_err(|_| "FD_NAME_INVALID")?,
        );
    }
    result.sort_unstable();
    Ok(result)
}

fn capture_inner() -> Result<Value, &'static str> {
    let pid = std::process::id();
    let (mut parent, start) = process(pid)?;
    let mut subjects = Vec::new();
    let mut errors = Vec::new();
    for fd in inventory(pid)? {
        if fd < 3 {
            continue;
        }
        match descriptor(pid, fd) {
            Ok(value) if value["cloexec"] == false => {
                if subjects.len() == SUBJECT_LIMIT {
                    return Err("FD_SUBJECT_LIMIT");
                }
                subjects.push(value);
            }
            Ok(_) => {}
            Err(error) if errors.len() < SUBJECT_LIMIT => {
                errors.push(json!({"fd":fd,"error":error}))
            }
            Err(_) => return Err("FD_ERROR_LIMIT"),
        }
    }
    let mut ancestors = Vec::new();
    // Empty baseline needs no ancestor traversal. Each ancestor records the
    // same descriptor numbers; identity equality is observation, not ownership.
    while parent != 0 && !subjects.is_empty() && ancestors.len() < ANCESTOR_LIMIT {
        let ancestor_pid = parent;
        let (next, ancestor_start) = match process(ancestor_pid) {
            Ok(value) => value,
            Err(error) => {
                ancestors.push(json!({"pid":ancestor_pid,"error":error}));
                break;
            }
        };
        let mut matches = Vec::new();
        for subject in &subjects {
            let fd = subject["fd"].as_u64().ok_or("FD_SUBJECT_INVALID")? as u32;
            let value = match descriptor(ancestor_pid, fd) {
                Ok(value) => json!({"same_identity":value["device"] == subject["device"]
                    && value["inode"] == subject["inode"] && value["mode"] == subject["mode"],
                    "metadata":value}),
                Err(error) => json!({"fd":fd,"error":error}),
            };
            matches.push(value);
        }
        let stable = process(ancestor_pid) == Ok((next, ancestor_start));
        ancestors.push(json!({"pid":ancestor_pid,"start_ticks":ancestor_start,"parent":next,"stable":stable,"same_number_fds":matches}));
        if next == ancestor_pid {
            return Err("ANCESTOR_CYCLE");
        }
        parent = next;
    }
    Ok(
        json!({"schema":"bullet.ci.fixture-fd-diagnostic.v1","pid":pid,"start_ticks":start,
        "inheritable":subjects,"errors":errors,"ancestors":ancestors,
        "ancestor_walk_incomplete":parent != 0 && !subjects.is_empty(),"authority":"NONE"}),
    )
}

pub(super) fn capture() -> Value {
    capture_inner().unwrap_or_else(|error| json!({"diagnostic_error":error,"authority":"NONE"}))
}
