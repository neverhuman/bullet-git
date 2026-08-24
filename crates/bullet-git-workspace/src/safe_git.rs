//! Hardened git command builder (spec §20.3 hostile-git controls).

use crate::{git_config, io_err, CapabilityError};
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// File transport policy for one git invocation.
///
/// Local clones from the source repository need the file transport; every
/// other invocation runs with the transport denied.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileProtocol {
    /// `protocol.file.allow=never`.
    Never,
    /// `protocol.file.allow=user` — scoped to exactly the clone call.
    User,
}

/// Structural HEAD state. Never derived by comparing a branch name to "HEAD".
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HeadState {
    /// HEAD is detached (expected before private-branch creation).
    Detached,
    /// HEAD points at the named branch (without the `refs/heads/` prefix).
    Branch(String),
}

/// Successful git output.
#[derive(Debug)]
pub struct GitOutput {
    /// Raw stdout bytes.
    pub stdout: Vec<u8>,
}

impl GitOutput {
    /// Stdout as trimmed UTF-8 text.
    #[must_use]
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).trim().to_string()
    }
}

/// Builds git commands with a fully isolated environment.
///
/// The child environment is cleared (which strips every inherited `GIT_*`
/// variable) and rebuilt with: per-workspace `HOME`/`XDG_CONFIG_HOME`/
/// `XDG_CACHE_HOME`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`,
/// `GIT_TERMINAL_PROMPT=0`, `GIT_ASKPASS=<deny script>`, and
/// `GIT_SSH_COMMAND=false`. Every invocation also passes
/// `-c core.hooksPath=<empty dir> -c credential.helper=
/// -c protocol.file.allow=<never|user> -c include.path=/dev/null`. Before any
/// repository-scoped call, the exact local config is read without includes and
/// rejected if it contains a command-bearing or truth-redirecting key.
#[derive(Debug)]
pub struct SafeGit {
    home_dir: PathBuf,
    xdg_config_dir: PathBuf,
    xdg_cache_dir: PathBuf,
    hooks_dir: PathBuf,
    askpass: PathBuf,
}

impl SafeGit {
    /// Prepare the isolation directories and deny script under `runtime_dir`.
    ///
    /// # Errors
    ///
    /// Returns `IO_FAILED` when the runtime directories cannot be created.
    pub fn new(runtime_dir: &Path) -> Result<Self, CapabilityError> {
        let home_dir = runtime_dir.join("home");
        let xdg_config_dir = runtime_dir.join("xdg-config");
        let xdg_cache_dir = runtime_dir.join("xdg-cache");
        let hooks_dir = runtime_dir.join("hooks-empty");
        for dir in [&home_dir, &xdg_config_dir, &xdg_cache_dir, &hooks_dir] {
            fs::create_dir_all(dir).map_err(|err| io_err("create runtime dir", &err))?;
        }
        let askpass = runtime_dir.join("askpass-deny.sh");
        fs::write(&askpass, "#!/bin/sh\nexit 1\n")
            .map_err(|err| io_err("write askpass deny script", &err))?;
        fs::set_permissions(&askpass, fs::Permissions::from_mode(0o700))
            .map_err(|err| io_err("chmod askpass deny script", &err))?;
        Ok(Self {
            home_dir,
            xdg_config_dir,
            xdg_cache_dir,
            hooks_dir,
            askpass,
        })
    }

    /// Build a hardened git command after validating repository-local config.
    ///
    /// # Errors
    ///
    /// Returns `HOSTILE_GIT_CONFIG` when local configuration can execute code,
    /// include another config source, or redirect repository truth.
    pub fn command(
        &self,
        repo: Option<&Path>,
        file_protocol: FileProtocol,
    ) -> Result<Command, CapabilityError> {
        if let Some(repo) = repo {
            git_config::validate(repo, self.base_command(None, FileProtocol::Never))?;
        }
        Ok(self.base_command(repo, file_protocol))
    }

    fn base_command(&self, repo: Option<&Path>, file_protocol: FileProtocol) -> Command {
        let mut cmd = Command::new("git");
        cmd.env_clear();
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        cmd.env("HOME", &self.home_dir)
            .env("XDG_CONFIG_HOME", &self.xdg_config_dir)
            .env("XDG_CACHE_HOME", &self.xdg_cache_dir)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_ASKPASS", &self.askpass)
            .env("GIT_SSH_COMMAND", "false")
            .env("LC_ALL", "C");
        let allow = match file_protocol {
            FileProtocol::Never => "never",
            FileProtocol::User => "user",
        };
        cmd.arg("--no-pager")
            .arg("-c")
            .arg(format!("core.hooksPath={}", self.hooks_dir.display()))
            .arg("-c")
            .arg("credential.helper=")
            .arg("-c")
            .arg(format!("protocol.file.allow={allow}"))
            .arg("-c")
            .arg("include.path=/dev/null")
            .arg("-c")
            .arg("core.fsmonitor=false")
            .arg("-c")
            .arg("core.attributesFile=/dev/null")
            .arg("-c")
            .arg("core.excludesFile=/dev/null")
            .arg("-c")
            .arg("commit.gpgSign=false")
            .arg("-c")
            .arg("tag.gpgSign=false");
        if let Some(repo) = repo {
            cmd.arg("-C").arg(repo);
        }
        cmd
    }

    /// Run a git command that must succeed.
    ///
    /// # Errors
    ///
    /// Returns `GIT_FAILED` on a nonzero exit, `IO_FAILED` when spawning fails.
    pub fn run(
        &self,
        repo: Option<&Path>,
        file_protocol: FileProtocol,
        args: &[&str],
        extra_env: &[(&str, OsString)],
    ) -> Result<GitOutput, CapabilityError> {
        let mut cmd = self.command(repo, file_protocol)?;
        for (key, value) in extra_env {
            cmd.env(key, value);
        }
        cmd.args(args);
        let out = cmd.output().map_err(|err| io_err("spawn git", &err))?;
        if !out.status.success() {
            let verb = args.first().copied().unwrap_or("git");
            let stderr = String::from_utf8_lossy(&out.stderr);
            return Err(CapabilityError::Git(format!(
                "git {verb} exited {:?}: {}",
                out.status.code(),
                stderr.trim()
            )));
        }
        Ok(GitOutput { stdout: out.stdout })
    }

    /// Run a git probe where failure is a legitimate answer.
    ///
    /// # Errors
    ///
    /// Returns `IO_FAILED` only when the process cannot be spawned.
    pub fn probe(&self, repo: Option<&Path>, args: &[&str]) -> Result<bool, CapabilityError> {
        let mut cmd = self.command(repo, FileProtocol::Never)?;
        cmd.args(args);
        let out = cmd
            .output()
            .map_err(|err| io_err("spawn git probe", &err))?;
        Ok(out.status.success())
    }

    /// Structural HEAD state via `symbolic-ref -q HEAD` exit status.
    ///
    /// # Errors
    ///
    /// Returns `GIT_FAILED` when git reports anything other than a branch
    /// (exit 0) or a detached HEAD (exit 1).
    pub fn head_state(&self, repo: &Path) -> Result<HeadState, CapabilityError> {
        let mut cmd = self.command(Some(repo), FileProtocol::Never)?;
        cmd.args(["symbolic-ref", "-q", "HEAD"]);
        let out = cmd
            .output()
            .map_err(|err| io_err("spawn git symbolic-ref", &err))?;
        match out.status.code() {
            Some(0) => {
                let full = String::from_utf8_lossy(&out.stdout).trim().to_string();
                let name = full.strip_prefix("refs/heads/").unwrap_or(&full);
                Ok(HeadState::Branch(name.to_string()))
            }
            Some(1) => Ok(HeadState::Detached),
            code => Err(CapabilityError::Git(format!(
                "git symbolic-ref exited {code:?}"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsStr;

    #[test]
    fn command_environment_is_isolated() {
        let dir = tempfile::tempdir().expect("tempdir");
        let git = SafeGit::new(dir.path()).expect("safe git");
        let cmd = git
            .command(None, FileProtocol::Never)
            .expect("safe command");
        let envs: Vec<(&OsStr, Option<&OsStr>)> = cmd.get_envs().collect();
        let get = |key: &str| {
            envs.iter()
                .find(|(k, _)| *k == OsStr::new(key))
                .and_then(|(_, v)| *v)
        };
        assert_eq!(get("GIT_CONFIG_NOSYSTEM"), Some(OsStr::new("1")));
        assert_eq!(get("GIT_CONFIG_GLOBAL"), Some(OsStr::new("/dev/null")));
        assert_eq!(get("GIT_TERMINAL_PROMPT"), Some(OsStr::new("0")));
        assert!(get("HOME").is_some());
        assert!(get("GIT_ASKPASS").is_some());
        // env_clear means inherited GIT_* variables never reach the child.
        assert!(cmd.get_envs().all(|(k, _)| k != OsStr::new("GIT_DIR")));
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"credential.helper=".to_string()));
        assert!(args.contains(&"protocol.file.allow=never".to_string()));
        assert!(args.contains(&"include.path=/dev/null".to_string()));
        assert!(args.contains(&"core.fsmonitor=false".to_string()));
        assert!(args.contains(&"commit.gpgSign=false".to_string()));
        assert!(args.iter().any(|a| a.starts_with("core.hooksPath=")));
    }

    #[test]
    fn clone_call_scopes_file_protocol_to_user() {
        let dir = tempfile::tempdir().expect("tempdir");
        let git = SafeGit::new(dir.path()).expect("safe git");
        let cmd = git
            .command(None, FileProtocol::User)
            .expect("safe clone command");
        let args: Vec<String> = cmd
            .get_args()
            .map(|a| a.to_string_lossy().into_owned())
            .collect();
        assert!(args.contains(&"protocol.file.allow=user".to_string()));
    }

    #[test]
    fn askpass_script_denies() {
        let dir = tempfile::tempdir().expect("tempdir");
        let git = SafeGit::new(dir.path()).expect("safe git");
        let status = Command::new(dir.path().join("askpass-deny.sh"))
            .status()
            .expect("run deny script");
        assert!(!status.success());
        drop(git);
    }
}
