//! Bounded retained inventory. Validation errors never erase already read artifacts.
use super::super::{artifacts, io, paths, Result};
use super::common::{allowed, decimal, require, ARTIFACTS, PRODUCER};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::os::fd::AsRawFd;
use std::path::Path;

#[derive(Default)]
pub(super) struct Inventory {
    pub(super) data: BTreeMap<String, artifacts::Artifact>,
    pub(super) issues: Vec<String>,
    pub(super) omissions: Vec<String>,
}

impl Inventory {
    pub(super) fn scan(&mut self, run: &str) -> Result<()> {
        let allowed = allowed();
        let directories: BTreeSet<_> = allowed
            .iter()
            .flat_map(|path| Path::new(path).ancestors().skip(1))
            .map(|path| path.to_string_lossy().into_owned())
            .collect();
        let mut pending = vec![String::new()];
        let (mut entries, mut total) = (0usize, 0usize);
        while let Some(relative_directory) = pending.pop() {
            let directory = if relative_directory.is_empty() {
                run.to_owned()
            } else {
                format!("{run}/{relative_directory}")
            };
            // Enumerate the already opened directory rather than follow a raced symlink.
            let (descriptor, _, _) = paths::open_parent(&format!("{directory}/.inventory-lookup"))?;
            let iterator = std::fs::read_dir(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
                .map_err(io)?;
            let mut children = iterator
                .take(257 - entries)
                .collect::<std::io::Result<Vec<_>>>()
                .map_err(io)?;
            entries += children.len();
            require(entries <= 256, "INVENTORY_ENTRY_LIMIT")?;
            children.sort_by_key(std::fs::DirEntry::file_name);
            for child in children {
                let name = child
                    .file_name()
                    .into_string()
                    .map_err(|_| "NON_UTF8_ARTIFACT_PATH")?;
                let relative = if relative_directory.is_empty() {
                    name
                } else {
                    format!("{relative_directory}/{name}")
                };
                let path = format!("{run}/{relative}");
                let kind = child.file_type().map_err(io)?;
                if kind.is_dir() {
                    if directories.contains(&relative) {
                        pending.push(relative);
                    } else {
                        self.issues.push(format!("EXTRA_DIRECTORY:{relative}"));
                        self.omissions.push(format!("{relative}/"));
                    }
                    continue;
                }
                if !allowed.contains(&relative) {
                    self.issues.push(format!("EXTRA_ARTIFACT:{relative}"));
                }
                if PRODUCER.contains(&relative.as_str()) {
                    require(kind.is_file(), "PRODUCER_OUTPUT_NOT_REGULAR")?;
                    continue;
                }
                let artifact = match artifacts::read(&path) {
                    Ok(artifact) => artifact,
                    Err(error) => {
                        self.issues.push(error);
                        self.omissions.push(relative);
                        continue;
                    }
                };
                total += artifact.bytes.len();
                if total > 256 * 1024 * 1024 {
                    self.omissions.push(relative);
                    return Err("INVENTORY_BYTE_LIMIT".into());
                }
                require(
                    self.data.insert(relative, artifact).is_none(),
                    "DUPLICATE_INVENTORY_ARTIFACT",
                )?;
            }
        }
        Ok(())
    }

    pub(super) fn get(&self, path: &str) -> Result<&[u8]> {
        self.data
            .get(path)
            .map(|artifact| artifact.bytes.as_slice())
            .ok_or_else(|| format!("ARTIFACT_MISSING:{path}"))
    }
    pub(super) fn exit(&self, path: &str) -> Result<u8> {
        decimal(
            self.get(path)?
                .strip_suffix(b"\n")
                .ok_or("EXIT_NEWLINE_REQUIRED")?,
        )
    }
    pub(super) fn argv(&self, name: &str, expected: &[String]) -> Result<()> {
        let bytes: Vec<u8> = expected
            .iter()
            .flat_map(|arg| arg.bytes().chain([0]))
            .collect();
        require(
            self.get(&format!("{name}.argv"))? == bytes,
            format!("STAGE_ARGV_MISMATCH:{name}"),
        )?;
        self.get(&format!("{name}.stdout"))?;
        self.get(&format!("{name}.stderr"))?;
        Ok(())
    }
    pub(super) fn snapshot(&self, phase: &str) -> Result<()> {
        let present: BTreeSet<&str> = ARTIFACTS
            .into_iter()
            .filter(|path| self.data.contains_key(&format!("{phase}/{path}")))
            .collect();
        let absence = self
            .data
            .get(&format!("{phase}.absent"))
            .map(|a| a.bytes.as_slice())
            .unwrap_or_default();
        let text = std::str::from_utf8(absence).map_err(io)?;
        let lines: Vec<&str> = text.lines().collect();
        let absent: BTreeSet<&str> = lines.iter().copied().collect();
        require(
            lines.len() == absent.len()
                && present.is_disjoint(&absent)
                && present.union(&absent).copied().collect::<BTreeSet<_>>()
                    == ARTIFACTS.into_iter().collect(),
            format!("SNAPSHOT_INCOMPLETE:{phase}"),
        )
    }
    pub(super) fn subjects(&self) -> Vec<Value> {
        self.data
            .iter()
            .map(|(path, artifact)| {
                let mut item = artifact.subject.clone();
                item["path"] = path.clone().into();
                item
            })
            .collect()
    }
    pub(super) fn recheck(&self) -> Result<()> {
        for artifact in self.data.values() {
            artifact.recheck()?;
        }
        Ok(())
    }
}
