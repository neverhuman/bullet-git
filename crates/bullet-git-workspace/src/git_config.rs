//! Fail-closed inspection of repository-local Git configuration.

use std::{fs, path::Path, process::Command};

use crate::{io_err, CapabilityError};

/// Inspect a repository-local Git config through the fuzz harness's isolated
/// `git config --file` subprocess.
///
/// # Errors
///
/// `HOSTILE_GIT_CONFIG` when the config is malformed, non-regular, unreadable,
/// or contains a forbidden key.
#[cfg(feature = "fuzzing")]
pub fn validate_repo_config(repo: &Path) -> Result<(), CapabilityError> {
    let mut command = Command::new("git");
    command.env_clear();
    if let Some(path) = std::env::var_os("PATH") {
        command.env("PATH", path);
    }
    command
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("LC_ALL", "C");
    validate(repo, command)
}

pub(crate) fn validate(repo: &Path, mut command: Command) -> Result<(), CapabilityError> {
    let config = local_config_path(repo)?;
    let Some(config) = config else {
        return Ok(());
    };
    command.args(["config", "--file"]).arg(&config).args([
        "--no-includes",
        "--null",
        "--name-only",
        "--list",
    ]);
    let output = command
        .output()
        .map_err(|error| io_err("inspect local git config", &error))?;
    if !output.status.success() {
        return Err(CapabilityError::HostileGitConfig(format!(
            "cannot parse {}: {}",
            config.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    for raw in output.stdout.split(|byte| *byte == 0) {
        if raw.is_empty() {
            continue;
        }
        let key = std::str::from_utf8(raw).map_err(|_| {
            CapabilityError::HostileGitConfig(format!(
                "{} contains a non-UTF-8 key",
                config.display()
            ))
        })?;
        if forbidden(key) {
            return Err(CapabilityError::HostileGitConfig(format!(
                "{} contains forbidden key {key}",
                config.display()
            )));
        }
    }
    Ok(())
}

fn local_config_path(repo: &Path) -> Result<Option<std::path::PathBuf>, CapabilityError> {
    let dot_git = repo.join(".git");
    let config = match fs::symlink_metadata(&dot_git) {
        Ok(metadata) if metadata.is_dir() => dot_git.join("config"),
        Ok(_) => {
            return Err(CapabilityError::HostileGitConfig(format!(
                "{} is not an ordinary .git directory",
                dot_git.display()
            )));
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => repo.join("config"),
        Err(error) => return Err(io_err("inspect .git", &error)),
    };
    let metadata = match fs::symlink_metadata(&config) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_err("inspect local git config", &error)),
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(CapabilityError::HostileGitConfig(format!(
            "{} is not a regular file",
            config.display()
        )));
    }
    Ok(Some(config))
}

fn forbidden(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.starts_with("filter.")
        || key.starts_with("include.")
        || key.starts_with("includeif.")
        || key.starts_with("alias.")
        || key.starts_with("pager.")
        || key.starts_with("url.")
            && (key.ends_with(".insteadof") || key.ends_with(".pushinsteadof"))
        || key.starts_with("remote.")
            && (key.ends_with(".uploadpack") || key.ends_with(".receivepack"))
        || key.starts_with("diff.") && (key.ends_with(".command") || key.ends_with(".textconv"))
        || key.starts_with("merge.") && key.ends_with(".driver")
        || key.starts_with("submodule.") && key.ends_with(".update")
        || matches!(
            key.as_str(),
            "core.askpass"
                | "core.attributesfile"
                | "core.editor"
                | "core.excludesfile"
                | "core.fsmonitor"
                | "core.hookspath"
                | "core.gitproxy"
                | "core.pager"
                | "core.sparsecheckout"
                | "core.sparsecheckoutcone"
                | "core.sshcommand"
                | "core.worktree"
                | "credential.helper"
                | "gpg.program"
                | "gpg.ssh.program"
                | "index.sparse"
                | "interactive.difffilter"
                | "sequence.editor"
        )
}

#[cfg(test)]
mod tests {
    use super::forbidden;

    #[test]
    fn command_and_truth_redirecting_key_classes_are_denied() {
        for key in [
            "filter.evil.clean",
            "filter.evil.process",
            "include.path",
            "includeIf.gitdir:/.path",
            "alias.status",
            "pager.diff",
            "url.file:///outside.insteadOf",
            "remote.origin.uploadPack",
            "diff.evil.textconv",
            "diff.evil.command",
            "merge.evil.driver",
            "submodule.evil.update",
            "core.fsmonitor",
            "core.hooksPath",
            "core.excludesFile",
            "credential.helper",
            "gpg.program",
            "interactive.diffFilter",
            "sequence.editor",
        ] {
            assert!(forbidden(key), "dangerous key was allowed: {key}");
        }
    }

    #[test]
    fn ordinary_generated_clone_and_mirror_keys_are_allowed() {
        for key in [
            "core.repositoryFormatVersion",
            "core.fileMode",
            "core.bare",
            "core.logAllRefUpdates",
            "core.ignoreCase",
            "remote.origin.url",
            "remote.origin.fetch",
            "remote.origin.mirror",
            "extensions.objectFormat",
        ] {
            assert!(!forbidden(key), "ordinary key was refused: {key}");
        }
    }
}
