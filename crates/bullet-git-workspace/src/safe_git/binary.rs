//! Digest-pinned Git binary with wall-clock deadlines and output bounds.
//!
//! [`PinnedGit`] is the only way this crate reaches a Git executable. The
//! file is opened once (`O_RDONLY|O_CLOEXEC|O_NOFOLLOW`), checked and hashed
//! from that descriptor (regular, executable, digest equal), and its verified
//! bytes are staged into a sealed anonymous memfd that lives as long as the
//! pin. Every invocation executes `/proc/self/fd/<memfd>`, so a later swap
//! or in-place rewrite of the on-disk file never changes what runs. `PATH`
//! never selects the executable. Each spawn runs under a wall-clock deadline
//! and per-stream byte caps.
//!
//! Residuals (documented, not hidden): the deadline kills the direct child
//! only, because the workspace has no process-group signal primitive without
//! a new dependency (`rustix` is compiled with `fs` only); descendants lose
//! their pipes when the child dies and are never waited for. Git helpers
//! under its compiled-in exec path are not covered by the pin.

#[path = "binary_pin.rs"]
mod pin;

use crate::{io_err, CapabilityError, GitBinaryError};
use bullet_git_types::Digest;
use std::io::{ErrorKind, Read};
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver};
use std::sync::{Arc, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

/// Absolute locations probed, in order, when no default binary was installed.
pub const SYSTEM_GIT_CANDIDATES: [&str; 3] = ["/usr/bin/git", "/usr/local/bin/git", "/bin/git"];

/// Wall-clock and output bounds for one Git invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GitBounds {
    /// Wall-clock limit from spawn to exit; the child is killed on expiry.
    pub deadline: Duration,
    /// Stdout bytes admitted; one byte more is a typed refusal.
    pub max_stdout_bytes: usize,
    /// Stderr bytes admitted; one byte more is a typed refusal.
    pub max_stderr_bytes: usize,
}

impl GitBounds {
    /// Production defaults. Stdout admits four times the 32 MiB proposal
    /// aggregate so `git diff` over a maximal stage (every content line gains
    /// a prefix) still fits; stderr is diagnostics only.
    pub const DEFAULT: Self = Self {
        deadline: Duration::from_secs(600),
        max_stdout_bytes: 128 * 1_048_576,
        max_stderr_bytes: 4 * 1_048_576,
    };
}

/// Who vouched for the pinned digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PinSource {
    /// The caller supplied the expected digest ([`PinnedGit::new`]).
    Operator,
    /// The digest was computed from the file itself
    /// ([`PinnedGit::self_pinned`]): process-stable, not authenticated.
    /// Production configuration must refuse this source.
    SelfPinned,
}

/// An absolute, digest-verified Git executable staged in a sealed memfd,
/// plus its execution bounds.
#[derive(Clone, Debug)]
pub struct PinnedGit {
    path: PathBuf,
    digest: Digest,
    source: PinSource,
    bounds: GitBounds,
    staged: Arc<OwnedFd>,
}

impl PartialEq for PinnedGit {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
            && self.digest == other.digest
            && self.source == other.source
            && self.bounds == other.bounds
    }
}

impl Eq for PinnedGit {}

static DEFAULT_BINARY: OnceLock<PinnedGit> = OnceLock::new();

impl CapabilityError {
    /// The [`GitBinaryError`] reason code, when this is a Git binary refusal.
    #[must_use]
    pub const fn git_binary_code(&self) -> Option<&'static str> {
        match self {
            Self::GitBinary(error) => Some(error.reason_code()),
            _ => None,
        }
    }
}

/// A command bound to the staged executable plus the descriptor it runs.
pub(crate) struct PreparedCommand {
    pub(crate) command: Command,
    inherit: OwnedFd,
}

/// Exit status plus both bounded streams of one invocation.
#[derive(Debug)]
pub(crate) struct BoundedOutput {
    pub(crate) status: ExitStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
}

fn proc_path(fd: &OwnedFd) -> String {
    format!("/proc/self/fd/{}", std::os::fd::AsRawFd::as_raw_fd(fd))
}

fn staging(path: &Path, reason: impl ToString) -> GitBinaryError {
    GitBinaryError::Staging {
        path: path.display().to_string(),
        reason: reason.to_string(),
    }
}

/// Open once without following symlinks, verify from the descriptor, and
/// stage the verified bytes into a sealed memfd.
#[cfg(target_os = "linux")]
fn stage(path: &Path) -> Result<(Digest, OwnedFd), GitBinaryError> {
    use rustix::fs::{fcntl_add_seals, memfd_create, open, MemfdFlags, Mode, OFlags, SealFlags};
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let shown = path.display().to_string();
    if !path.is_absolute() {
        return Err(GitBinaryError::PathNotAbsolute(shown));
    }
    let unreadable = |reason: &dyn ToString| GitBinaryError::Unreadable {
        path: shown.clone(),
        reason: reason.to_string(),
    };
    let flags = OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW;
    let source = match open(path, flags, Mode::empty()) {
        Ok(fd) => File::from(fd),
        Err(rustix::io::Errno::LOOP) => return Err(GitBinaryError::Symlink(shown)),
        Err(errno) => return Err(unreadable(&errno)),
    };
    let metadata = source.metadata().map_err(|err| unreadable(&err))?;
    if !metadata.is_file() {
        return Err(GitBinaryError::NotRegular(shown));
    }
    if (metadata.permissions().mode() & 0o111) == 0 {
        return Err(GitBinaryError::NotExecutable(shown));
    }
    let mut bytes = Vec::new();
    (&source)
        .read_to_end(&mut bytes)
        .map_err(|err| unreadable(&err))?;
    let digest = Digest::of(&bytes);

    let base = MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING;
    let memfd = match memfd_create("bullet-git-pinned", base | MemfdFlags::EXEC) {
        Err(rustix::io::Errno::INVAL) => memfd_create("bullet-git-pinned", base),
        other => other,
    }
    .map_err(|errno| staging(path, errno))?;
    let mut staged = File::from(memfd);
    staged.write_all(&bytes).map_err(|err| staging(path, err))?;
    let seals = SealFlags::WRITE | SealFlags::SHRINK | SealFlags::GROW | SealFlags::SEAL;
    fcntl_add_seals(&staged, seals).map_err(|errno| staging(path, errno))?;
    Ok((digest, OwnedFd::from(staged)))
}

#[cfg(not(target_os = "linux"))]
fn stage(path: &Path) -> Result<(Digest, OwnedFd), GitBinaryError> {
    Err(staging(path, "memfd staging requires linux"))
}

/// A plain `dup` (no `CLOEXEC`) so the executed descriptor survives `exec`.
#[cfg(target_os = "linux")]
fn inheritable(staged: &OwnedFd, path: &Path) -> Result<OwnedFd, CapabilityError> {
    Ok(rustix::io::dup(staged).map_err(|errno| staging(path, errno))?)
}

#[cfg(not(target_os = "linux"))]
fn inheritable(_staged: &OwnedFd, path: &Path) -> Result<OwnedFd, CapabilityError> {
    Err(staging(path, "memfd execution requires linux").into())
}

fn discover_system() -> Result<PinnedGit, GitBinaryError> {
    let mut reasons = Vec::new();
    for candidate in SYSTEM_GIT_CANDIDATES {
        match PinnedGit::self_pinned(Path::new(candidate)) {
            Ok(pinned) => return Ok(pinned),
            Err(err) => reasons.push(format!("{candidate}: {}", err.reason_code())),
        }
    }
    Err(GitBinaryError::NotFound(reasons.join("; ")))
}

fn reap(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn tripped(stdout: &StreamReader, stderr: &StreamReader) -> Option<&'static str> {
    if stdout.exceeded() {
        Some("stdout")
    } else if stderr.exceeded() {
        Some("stderr")
    } else {
        None
    }
}

/// Background reader that stops at `cap + 1` bytes and flags the excess;
/// dropping its end of the pipe then fails the writer with `EPIPE`.
struct StreamReader {
    receiver: Receiver<Vec<u8>>,
    exceeded: Arc<AtomicBool>,
}

impl StreamReader {
    fn spawn<R: Read + Send + 'static>(
        source: Option<R>,
        cap: usize,
    ) -> Result<Self, CapabilityError> {
        let mut source =
            source.ok_or_else(|| CapabilityError::Io("git stream was not piped".into()))?;
        let (sender, receiver) = mpsc::channel();
        let exceeded = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&exceeded);
        thread::Builder::new()
            .name("bullet-git-stream".into())
            .spawn(move || {
                let mut bytes = Vec::new();
                let mut chunk = vec![0_u8; 65_536];
                loop {
                    match source.read(&mut chunk) {
                        Ok(0) => break,
                        Ok(count) => {
                            if bytes.len().saturating_add(count) > cap {
                                flag.store(true, Ordering::SeqCst);
                                break;
                            }
                            bytes.extend_from_slice(&chunk[..count]);
                        }
                        Err(err) if err.kind() == ErrorKind::Interrupted => {}
                        Err(_) => break,
                    }
                }
                drop(source);
                let _ = sender.send(bytes);
            })
            .map_err(|err| io_err("spawn git stream reader", &err))?;
        Ok(Self { receiver, exceeded })
    }

    fn exceeded(&self) -> bool {
        self.exceeded.load(Ordering::SeqCst)
    }

    /// Bytes read once the stream closed, or `None` when it stayed open past
    /// `wait` (a descendant still holds the pipe) or the reader died.
    fn finish(&self, wait: Duration) -> Option<Vec<u8>> {
        self.receiver.recv_timeout(wait).ok()
    }
}
