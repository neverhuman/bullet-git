//! Native outcome and bounded version capture, without process-tree claims.
#[path = "descriptors.rs"]
pub(super) mod descriptors;
use super::{io, record::Record, Environment, Profile, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use rustix::fs::{fcntl_getfl, fcntl_setfl, OFlags};
use serde_json::json;
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

const VERSION_BYTES: usize = 65_536;
const VERSION_TIMEOUT: Duration = Duration::from_secs(15);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);

struct ChildGuard {
    child: Child,
    observed: bool,
}
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.observed {
            return;
        }
        let _ = self.child.kill();
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        while Instant::now() < deadline {
            if matches!(self.child.try_wait(), Ok(Some(_))) {
                return;
            }
            thread::sleep(Duration::from_millis(2));
        }
        eprintln!("jankurai-tool: CHILD_TERMINATION_UNKNOWN");
    }
}

fn environment(mut environment: Environment) -> Result<(Environment, Vec<String>)> {
    let mut keys = Vec::new();
    for key in environment.keys() {
        let key = key.to_str().ok_or("ENVIRONMENT_KEY_NON_UTF8")?;
        if key.starts_with("LD_") || ["GLIBC_TUNABLES", "GCONV_PATH", "LOCPATH"].contains(&key) {
            return Err("DYNAMIC_LOADER_ENVIRONMENT_REFUSED".into());
        }
        keys.push(key.to_owned());
    }
    environment.insert("JANKURAI_NO_UPDATE_CHECK".into(), "1".into());
    if !keys.iter().any(|key| key == "JANKURAI_NO_UPDATE_CHECK") {
        keys.push("JANKURAI_NO_UPDATE_CHECK".into());
        keys.sort();
    }
    Ok((environment, keys))
}

pub(super) fn run(
    executable: &File,
    argv: &[String],
    record: &mut Record,
    native: &mut Option<i32>,
    profile: Profile<'_>,
    environment: Environment,
) -> Result<i32> {
    run_inner(
        executable,
        argv,
        record,
        native,
        profile,
        environment,
        (argv == ["--version"]).then_some(VERSION_TIMEOUT),
    )
}

fn run_inner(
    executable: &File,
    argv: &[String],
    record: &mut Record,
    native: &mut Option<i32>,
    profile: Profile<'_>,
    environment_input: Environment,
    capture_timeout: Option<Duration>,
) -> Result<i32> {
    let (environment, keys) = environment(environment_input)?;
    let version = capture_timeout.is_some();
    let streams = if let Some(timeout) = capture_timeout {
        Some((
            record.stream(".stdout")?,
            record.stream(".stderr")?,
            timeout,
        ))
    } else {
        None
    };
    let inherit = rustix::io::dup(executable).map_err(io)?;
    let executable_path = format!("/proc/self/fd/{}", inherit.as_raw_fd());
    let mut command = Command::new(&executable_path);
    command
        .arg0("jankurai")
        .args(argv)
        .env_clear()
        .envs(environment);
    if version {
        command.stdout(Stdio::piped()).stderr(Stdio::piped());
    }
    let native_argv = [vec!["jankurai".to_owned()], argv.to_vec()].concat();
    record.append("launch_intent", json!({"argv": native_argv,
        "executable": executable_path, "inherited_environment_keys": keys,
        "update_check": "disabled_by_JANKURAI_NO_UPDATE_CHECK_1",
        "inherited_fds": if version { vec![0] } else { vec![0, 1, 2] },
        "passed_executable_fd": inherit.as_raw_fd(), "streams": if version { "retained" } else { "caller_owned" },
        "limitations": "No source/runtime closure, process-tree supervision, network containment or release authority; unqualified inheritable FDs refuse"}))?;
    descriptors::check(inherit.as_raw_fd())?;
    let mut guard = ChildGuard {
        child: command.spawn().map_err(io)?,
        observed: false,
    };
    drop(inherit);
    record.append("started", json!({"pid": guard.child.id()}))?;
    if let Some((stdout_file, stderr_file, timeout)) = streams {
        let stdout = guard
            .child
            .stdout
            .take()
            .ok_or("VERSION_STDOUT_UNAVAILABLE")?;
        let stderr = guard
            .child
            .stderr
            .take()
            .ok_or("VERSION_STDERR_UNAVAILABLE")?;
        fcntl_setfl(
            &stdout,
            fcntl_getfl(&stdout).map_err(io)? | OFlags::NONBLOCK,
        )
        .map_err(io)?;
        fcntl_setfl(
            &stderr,
            fcntl_getfl(&stderr).map_err(io)? | OFlags::NONBLOCK,
        )
        .map_err(io)?;
        let mut stdout = Capture::new(stdout, stdout_file);
        let mut stderr = Capture::new(stderr, stderr_file);
        let deadline = Instant::now() + timeout;
        loop {
            observe(&mut guard, record, native)?;
            stdout.pump()?;
            stderr.pump()?;
            if native.is_some() && stdout.eof && stderr.eof {
                break;
            }
            if Instant::now() >= deadline {
                return Err("VERSION_TIMEOUT".into());
            }
            thread::sleep(Duration::from_millis(2));
        }
        record.append(
            "version_output",
            json!({"stdout_base64": STANDARD.encode(&stdout.bytes),
            "stderr_base64": STANDARD.encode(&stderr.bytes)}),
        )?;
        std::io::stdout().write_all(&stdout.bytes).map_err(io)?;
        std::io::stderr().write_all(&stderr.bytes).map_err(io)?;
        let end = stdout
            .bytes
            .iter()
            .rposition(|byte| !b"\r\n".contains(byte))
            .map_or(0, |i| i + 1);
        if *native == Some(0)
            && (stdout.bytes[..end] != *profile.version || !stderr.bytes.is_empty())
        {
            return Err("VERSION_OUTPUT_MISMATCH".into());
        }
    } else {
        let status = guard.child.wait().map_err(io)?;
        guard.observed = true;
        terminated(status, record, native)?;
    }
    native.ok_or_else(|| "NATIVE_OUTCOME_UNKNOWN".into())
}

fn observe(guard: &mut ChildGuard, record: &mut Record, native: &mut Option<i32>) -> Result<()> {
    if !guard.observed {
        if let Some(status) = guard.child.try_wait().map_err(io)? {
            guard.observed = true;
            terminated(status, record, native)?;
        }
    }
    Ok(())
}

fn terminated(
    status: std::process::ExitStatus,
    record: &mut Record,
    native: &mut Option<i32>,
) -> Result<()> {
    let raw = status
        .code()
        .or_else(|| status.signal().map(|signal| -signal))
        .ok_or("NATIVE_OUTCOME_UNKNOWN")?;
    let exit = if raw < 0 { 128 - raw } else { raw };
    *native = Some(exit);
    record.append(
        "terminated",
        json!({"native_returncode": raw, "exit_status": exit}),
    )
}

struct Capture<R> {
    pipe: R,
    file: File,
    bytes: Vec<u8>,
    eof: bool,
}
impl<R: Read> Capture<R> {
    fn new(pipe: R, file: File) -> Self {
        Self {
            pipe,
            file,
            bytes: Vec::new(),
            eof: false,
        }
    }
    fn pump(&mut self) -> Result<()> {
        if self.eof {
            return Ok(());
        }
        let remaining = VERSION_BYTES + 1 - self.bytes.len();
        let mut buffer = [0_u8; 8192];
        let take = remaining.min(buffer.len());
        match self.pipe.read(&mut buffer[..take]) {
            Ok(0) => self.eof = true,
            Ok(count) => {
                self.file.write_all(&buffer[..count]).map_err(io)?;
                self.file.sync_all().map_err(io)?;
                self.bytes.extend_from_slice(&buffer[..count]);
                if self.bytes.len() > VERSION_BYTES {
                    return Err("VERSION_OUTPUT_LIMIT".into());
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(error) => return Err(io(error)),
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "execution_tests.rs"]
mod tests;
