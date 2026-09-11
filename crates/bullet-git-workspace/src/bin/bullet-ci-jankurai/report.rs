//! Local diagnostic report validation using existing hardened Git commands.
#[cfg(test)]
#[path = "report_tests.rs"]
mod tests;

use super::{artifacts, io, paths, report_policy, Result};
use bullet_git_workspace::{FileProtocol, GitBounds, PinnedGit, SafeGit};
use serde_json::{json, Value};
use std::ffi::OsString;
use std::path::Path;
use std::time::Duration;

pub(super) struct Repository {
    root: String,
    git: SafeGit,
}

impl Repository {
    pub(super) fn new(root: &str, runtime: &str) -> Result<Self> {
        paths::absolute_parts(root)?;
        paths::absolute_parts(runtime)?;
        if Path::new(runtime).starts_with(root) {
            return Err("RUNTIME_MUST_BE_OUTSIDE_SOURCE".into());
        }
        // Lookup includes root ancestors and refuses .git files/worktrees.
        let _config = artifacts::read(&format!("{root}/.git/config"))?;
        artifacts::new_directory(runtime)?;
        let pin = PinnedGit::process_default()
            .map_err(io)?
            .clone()
            .with_bounds(GitBounds {
                deadline: Duration::from_secs(30),
                max_stdout_bytes: artifacts::MAX_FILE as usize,
                max_stderr_bytes: 65536,
            });
        let git = SafeGit::with_binary(Path::new(runtime), pin).map_err(io)?;
        Ok(Self {
            root: root.into(),
            git,
        })
    }

    pub(super) fn git(&self, args: &[&str]) -> Result<Vec<u8>> {
        self.git
            .run(
                Some(Path::new(&self.root)),
                FileProtocol::Never,
                args,
                &[("GIT_OPTIONAL_LOCKS", OsString::from("0"))],
            )
            .map(|output| output.stdout)
            .map_err(io)
    }

    pub(super) fn tool_subject(&self) -> Value {
        let pin = self.git.binary();
        json!({"path": pin.path(), "blake3": pin.digest().to_hex(),
            "pin_source": format!("{:?}", pin.source()), "diagnostic_only": true,
            "limitations": "Existing SafeGit pin; helpers/runtime libraries not pinned here; no distribution or continuous custody acceptance"})
    }

    pub(super) fn policy(&self) -> Result<(String, artifacts::Artifact)> {
        let head = self.head()?;
        let policy = artifacts::read(&format!("{}/agent/audit-policy.toml", self.root))?;
        if self.git(&["show", &format!("{head}:agent/audit-policy.toml")])? != policy.bytes {
            return Err("UNCOMMITTED_POLICY".into());
        }
        Ok((head, policy))
    }

    pub(super) fn head(&self) -> Result<String> {
        let bytes = self.git(&["rev-parse", "--verify", "HEAD"])?;
        let value = std::str::from_utf8(&bytes).map_err(io)?.trim();
        if ![40, 64].contains(&value.len())
            || !value
                .bytes()
                .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        {
            return Err("INVALID_COMMIT_ID".into());
        }
        Ok(value.into())
    }
}

pub(super) fn entry(args: &[String]) -> Result<()> {
    let mut options = std::collections::BTreeMap::new();
    if args.len() % 2 != 0 {
        return Err("REPORT_OPTION_VALUE_REQUIRED".into());
    }
    for pair in args.chunks_exact(2) {
        if !["--root", "--runtime", "--report", "--baseline"].contains(&pair[0].as_str())
            || options.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("UNSUPPORTED_OR_DUPLICATE_REPORT_OPTION".into());
        }
        paths::absolute_parts(&pair[1])?;
    }
    let root = *options.get("--root").ok_or("REPORT_ROOT_REQUIRED")?;
    let runtime = *options.get("--runtime").ok_or("REPORT_RUNTIME_REQUIRED")?;
    let report_path = *options.get("--report").ok_or("REPORT_PATH_REQUIRED")?;
    let repository = Repository::new(root, runtime)?;
    let (head, policy) = repository.policy()?;
    let report = artifacts::read(report_path)?;
    let baseline = options
        .get("--baseline")
        .map(|path| artifacts::read(path))
        .transpose()?;
    let parsed = report_policy::decode(&report.bytes)?;
    let parsed_baseline = baseline
        .as_ref()
        .map(|value| report_policy::decode(&value.bytes))
        .transpose()?;
    report_policy::validate(&parsed, &policy.bytes, parsed_baseline.as_ref())?;
    report.recheck()?;
    policy.recheck()?;
    if let Some(baseline) = &baseline {
        baseline.recheck()?;
    }
    if repository.head()? != head {
        return Err("COMMIT_CHANGED".into());
    }
    println!(
        "{}",
        json!({"message": "native report matches committed policy", "commit_oid": head,
        "evidence_class": "LOCAL_AUDIT_DIAGNOSTIC", "git": repository.tool_subject(),
        "policy_subject": policy.subject, "report_subject": report.subject,
        "baseline_subject": baseline.map(|value| value.subject), "signed": false})
    );
    Ok(())
}
