//! Local unsigned diagnostics only; no source-admission or release authority.
#[cfg(test)]
mod advanced_tests;
mod bootstrap;
mod bootstrap_inputs;
#[cfg(test)]
mod bootstrap_tests;
mod cli;
mod common;
#[cfg(test)]
mod fixtures;
mod inventory;
#[cfg(test)]
mod tests;
mod tool_record;
mod validate;

use super::{artifacts, io, paths, report::Repository, report_policy, Result};
use common::*;
use inventory::Inventory;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

pub(super) fn entry(command: &str, args: &[String]) -> Result<u8> {
    cli::entry(command, args)
}

fn invocation(root: &str, run: &str, parent: Option<u32>) -> Result<Value> {
    paths::absolute_parts(root)?;
    paths::absolute_parts(run)?;
    let path = Path::new(run);
    let name = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or("AUDIT_RUN_PATH_INVALID")?;
    let suffix = name.strip_prefix("run.").ok_or("AUDIT_RUN_PATH_INVALID")?;
    require(
        path.parent() == Some(Path::new(&format!("{root}/target/jankurai/audit-runs")))
            && suffix.len() == 8
            && suffix.bytes().all(|b| b.is_ascii_alphanumeric()),
        "AUDIT_RUN_PATH_INVALID",
    )?;
    let filename = format!("{run}/invocation.json");
    let (directory, _, _) = paths::open_parent(&filename)?;
    let metadata = directory.metadata().map_err(io)?;
    let uid = rustix::process::getuid().as_raw();
    require(
        metadata.mode() & 0o7777 == 0o700 && metadata.uid() == uid,
        "AUDIT_RUN_OWNER_INVALID",
    )?;
    let input = artifacts::read(&filename)?;
    let value = report_policy::decode(&input.bytes)?;
    let pid = field(&value, "parent_pid")?
        .as_u64()
        .filter(|pid| *pid > 0 && *pid <= u64::from(u32::MAX))
        .ok_or("AUDIT_RUN_PARENT_MISMATCH")?;
    require(
        parent.is_none_or(|parent| u64::from(parent) == pid),
        "AUDIT_RUN_PARENT_MISMATCH",
    )?;
    require(
        value
            == json!({"schema":"bullet.audit-invocation.v1","id":name,"repository":root,"origin":"dispatcher","parent_pid":pid})
            && input.subject["identity"]["mode"]
                .as_u64()
                .is_some_and(|mode| mode & 0o7777 == 0o600)
            && input.subject["identity"]["uid"].as_u64() == Some(u64::from(uid)),
        "AUDIT_INVOCATION_INVALID",
    )?;
    Ok(value)
}

pub(super) fn collect(
    root: &str,
    run: &str,
    status: u8,
    parent: Option<u32>,
    runtime: &str,
) -> Result<Value> {
    let invocation = invocation(root, run, parent)?;
    let mut inventory = Inventory::default();
    let (mut commit, mut tree, mut clean, mut policy_subject, mut git_subject) =
        (None, None, false, None, None);
    let mut tools = BTreeMap::new();
    let validation = (|| -> Result<()> {
        inventory.scan(run)?;
        bootstrap::collect(&mut inventory, root, run)?;
        let repository = Repository::new(root, runtime)?;
        git_subject = Some(repository.tool_subject());
        let (head, policy) = repository.policy()?;
        commit = Some(head.clone());
        policy_subject = Some(policy.subject.clone());
        let tree_bytes = repository.git(&["rev-parse", "--verify", &format!("{head}^{{tree}}")])?;
        tree = Some(
            std::str::from_utf8(&tree_bytes)
                .map_err(io)?
                .trim()
                .to_owned(),
        );
        clean = repository
            .git(&["status", "--porcelain", "--untracked-files=normal"])?
            .is_empty();
        let build_inputs = bootstrap::validate(&inventory, root, run)?;
        validate::validate(&inventory, root, run, status, &policy.bytes, &mut tools)?;
        inventory.recheck()?;
        policy.recheck()?;
        for input in build_inputs {
            input.recheck()?;
        }
        require(repository.head()? == head, "COMMIT_CHANGED")?;
        Ok(())
    })();
    if let Err(error) = validation {
        inventory.issues.push(error);
    }
    Ok(
        json!({"schema_version":SCHEMA,"repository":"bullet-git","commit_oid":commit,"tree_oid":tree,
        "clean":clean,"invocation":invocation,"run_path":run,"signed":false,"evidence_class":CLASS,
        "artifact_hashes":inventory.subjects(),"tools":tools,"git_tool":git_subject,"policy_subject":policy_subject,
        "bootstrap_artifact_root":format!("{root}/target/jankurai/bootstrap/{}",run.rsplit('/').next().unwrap_or_default()),
        "primary_status":status,"integrity_issues":inventory.issues,"omitted_artifacts":inventory.omissions,
        "outcome":if status == 0 && inventory.issues.is_empty() {"PASS"} else {"FAIL"},
        "producer_outputs_excluded":PRODUCER,
        "bootstrap_intermediates_excluded":"target/ except the exact emitted target/debug/bullet-ci-jankurai; cache contents are not accepted proof inputs",
        "limitations":"Unsigned local point-in-time diagnostics; no continuous source/runtime custody, installed distribution or aggregate event acceptance"}),
    )
}

pub(super) fn capture(root: &str, run: &str, status: u8, parent: u32, runtime: &str) -> Result<u8> {
    let report = collect(root, run, status, Some(parent), runtime)?;
    let mut bytes = serde_json::to_vec_pretty(&report).map_err(io)?;
    bytes.push(b'\n');
    // Preserve the original observation before attempting the canonical staging.
    artifacts::publish(&format!("{run}/observation.json"), &bytes)?;
    for path in [
        format!("{root}/.ci-artifacts"),
        format!("{root}/.ci-artifacts/observations"),
    ] {
        match std::fs::create_dir(&path) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(error) => return Err(io(error)),
        }
        paths::open_parent(&format!("{path}/.directory-lookup"))?;
    }
    artifacts::publish(
        &format!("{root}/.ci-artifacts/observations/audit.json"),
        &bytes,
    )?;
    println!(
        "audit-observation: {} (unsigned local diagnostic)",
        field(&report, "outcome")?
            .as_str()
            .ok_or("OUTCOME_INVALID")?
    );
    Ok(
        if report["integrity_issues"]
            .as_array()
            .ok_or("ISSUES_INVALID")?
            .is_empty()
        {
            0
        } else {
            75
        },
    )
}

pub(super) fn check(root: &str, commit: &str, runtime: &str) -> Result<()> {
    let raw = artifacts::read(&format!("{root}/.ci-artifacts/observations/audit.json"))?;
    let saved = report_policy::decode(&raw.bytes)?;
    let run = field(&saved, "run_path")?
        .as_str()
        .ok_or("RUN_PATH_INVALID")?;
    let original = artifacts::read(&format!("{run}/observation.json"))?;
    require(
        original.bytes == raw.bytes,
        "PUBLISHED_OBSERVATION_MISMATCH",
    )?;
    let status = field(&saved, "primary_status")?
        .as_u64()
        .and_then(|v| u8::try_from(v).ok())
        .ok_or("PRIMARY_STATUS_INVALID")?;
    let current = collect(root, run, status, None, runtime)?;
    require(saved == current, "OBSERVATION_OR_ARTIFACT_DRIFT")?;
    raw.recheck()?;
    original.recheck()?;
    require(
        field(&saved, "commit_oid")? == commit
            && field(&saved, "clean")?.as_bool() == Some(true)
            && field(&saved, "outcome")? == "PASS",
        "LOCAL_AUDIT_NOT_PASSING",
    )?;
    println!("audit-observation: exact local diagnostic artifacts passed");
    Ok(())
}
