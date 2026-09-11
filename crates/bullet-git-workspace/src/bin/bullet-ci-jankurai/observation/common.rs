//! Exact subjects beneath the existing unsigned local audit observation contract.
use super::super::Result;
use serde_json::Value;
use std::collections::BTreeSet;

pub(super) const SCHEMA: &str = "bullet.local-audit-observation.v1";
pub(super) const CLASS: &str = "LOCAL_AUDIT_DIAGNOSTIC";
pub(super) const REPORTS: [&str; 3] = ["repo-score.json", "repo-score.md", "repair-queue.jsonl"];
pub(super) const PRODUCER: [&str; 5] = [
    "observation.argv",
    "observation.stdout",
    "observation.stderr",
    "observation.exit",
    "observation.json",
];
pub(super) const PHASES: [&str; 4] = ["before", "ratchet", "audit", "final"];
pub(super) const ARTIFACTS: [&str; 13] = [
    ".ci-artifacts/observations/audit.json",
    "target/jankurai/audit-state.json",
    "target/jankurai/update/state.json",
    "target/jankurai/accepted-baseline.json",
    "target/jankurai/repo-score.json",
    "target/jankurai/repo-score.md",
    "target/jankurai/repair-queue.jsonl",
    ".jankurai/repo-score.json",
    ".jankurai/repo-score.md",
    ".jankurai/repair-queue.jsonl",
    ".jankurai/repo-score-current.json",
    ".jankurai/repo-score-current.md",
    ".jankurai/score-history.jsonl",
];

pub(super) fn allowed() -> BTreeSet<String> {
    let mut result: BTreeSet<String> = [
        "invocation.json",
        "previous-observation.json",
        "audit.started",
        "result.txt",
        "retention.stderr",
        "staging.stderr",
        "ratchet.json",
        "ratchet.md",
    ]
    .into_iter()
    .chain(PRODUCER)
    .map(str::to_owned)
    .collect();
    for stage in ["bootstrap", "doctor", "lane", "audit", "ratchet"] {
        for suffix in ["stdout", "stderr", "exit"] {
            result.insert(format!("{stage}.{suffix}"));
        }
    }
    for stage in ["bootstrap", "doctor", "lane"] {
        result.insert(format!("{stage}.argv"));
    }
    for stage in ["doctor", "audit", "ratchet"] {
        result.insert(format!("{stage}.tool.jsonl"));
    }
    for suffix in ["stdout", "stderr"] {
        result.insert(format!("doctor.tool.jsonl.{suffix}"));
    }
    for stage in ["audit", "ratchet"] {
        for suffix in ["argv", "stdout", "stderr", "exit"] {
            result.insert(format!("{stage}.validation.{suffix}"));
        }
    }
    for phase in PHASES {
        result.insert(format!("{phase}.absent"));
        for artifact in ARTIFACTS {
            result.insert(format!("{phase}/{artifact}"));
        }
    }
    result
}

pub(super) fn require(condition: bool, reason: impl Into<String>) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(reason.into())
    }
}
pub(super) fn field<'a>(row: &'a Value, key: &str) -> Result<&'a Value> {
    row.as_object()
        .and_then(|row| row.get(key))
        .ok_or_else(|| format!("OBSERVATION_FIELD_MISSING:{key}"))
}
pub(super) fn decimal(bytes: &[u8]) -> Result<u8> {
    require(
        !bytes.is_empty()
            && bytes.len() <= 3
            && bytes.iter().all(u8::is_ascii_digit)
            && (bytes.len() == 1 || bytes[0] != b'0'),
        "EXIT_RECORD_INVALID",
    )?;
    std::str::from_utf8(bytes)
        .map_err(|e| e.to_string())?
        .parse()
        .map_err(|_| "EXIT_RECORD_RANGE".into())
}
