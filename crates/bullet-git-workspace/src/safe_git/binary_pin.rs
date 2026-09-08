//! PinnedGit discovery, staging, and bounded spawn.

use super::*;

impl PinnedGit {
    /// Pin `path` to `expected`, verifying and staging the file once now.
    ///
    /// # Errors
    ///
    /// Typed [`GitBinaryError`] when the path is relative, missing, a
    /// symlink, not a regular file, not executable, hashes differently, or
    /// cannot be staged.
    pub fn new(path: &Path, expected: Digest) -> Result<Self, GitBinaryError> {
        let (digest, staged) = stage(path)?;
        if digest != expected {
            return Err(GitBinaryError::DigestMismatch {
                path: path.display().to_string(),
                expected: expected.to_hex(),
                actual: digest.to_hex(),
            });
        }
        Ok(Self::assemble(path, digest, staged, PinSource::Operator))
    }

    /// Pin `path` to whatever it currently hashes to (trust on first use).
    /// The result reports [`PinSource::SelfPinned`]; production callers use
    /// [`PinnedGit::new`] with an operator-supplied digest.
    ///
    /// # Errors
    ///
    /// Same structural and staging refusals as [`PinnedGit::new`].
    pub fn self_pinned(path: &Path) -> Result<Self, GitBinaryError> {
        let (digest, staged) = stage(path)?;
        Ok(Self::assemble(path, digest, staged, PinSource::SelfPinned))
    }

    fn assemble(path: &Path, digest: Digest, staged: OwnedFd, source: PinSource) -> Self {
        Self {
            path: path.to_path_buf(),
            digest,
            source,
            bounds: GitBounds::DEFAULT,
            staged: Arc::new(staged),
        }
    }

    /// Replace the execution bounds.
    #[must_use]
    pub fn with_bounds(mut self, bounds: GitBounds) -> Self {
        self.bounds = bounds;
        self
    }

    /// Absolute path the bytes were verified from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Verified digest of the staged bytes.
    #[must_use]
    pub fn digest(&self) -> Digest {
        self.digest
    }

    /// Who vouched for the digest.
    #[must_use]
    pub fn source(&self) -> PinSource {
        self.source
    }

    /// Execution bounds.
    #[must_use]
    pub fn bounds(&self) -> GitBounds {
        self.bounds
    }

    /// Install this pin as the process-wide default used by `SafeGit::new`.
    /// Installing an equal pin again is a no-op.
    ///
    /// # Errors
    ///
    /// `GIT_BINARY_ALREADY_PINNED` when a different default exists.
    pub fn install_default(self) -> Result<(), GitBinaryError> {
        let Err(rejected) = DEFAULT_BINARY.set(self) else {
            return Ok(());
        };
        match DEFAULT_BINARY.get() {
            Some(current) if *current == rejected => Ok(()),
            current => Err(GitBinaryError::AlreadyPinned(
                current.map_or_else(String::new, |pin| pin.path.display().to_string()),
            )),
        }
    }

    /// The process-wide default: an installed pin, else the first admissible
    /// [`SYSTEM_GIT_CANDIDATES`] entry self-pinned once for the process.
    ///
    /// # Errors
    ///
    /// `GIT_BINARY_NOT_FOUND` when no candidate passes the structural checks.
    pub fn process_default() -> Result<&'static Self, GitBinaryError> {
        if let Some(current) = DEFAULT_BINARY.get() {
            return Ok(current);
        }
        let _ = DEFAULT_BINARY.set(discover_system()?);
        DEFAULT_BINARY
            .get()
            .ok_or_else(|| GitBinaryError::NotFound("default pin vanished".into()))
    }

    /// A command that executes the staged bytes through `/proc/self/fd`.
    /// The returned descriptor is a non-`CLOEXEC` duplicate that must stay
    /// open until the spawn so interpreter scripts can reopen their source;
    /// [`PinnedGit::execute`] closes it right after spawning.
    ///
    /// # Errors
    ///
    /// `GIT_BINARY_STAGING_FAILED` when the descriptor cannot be duplicated.
    pub(crate) fn command(&self) -> Result<PreparedCommand, CapabilityError> {
        let inherit = inheritable(&self.staged, &self.path)?;
        let mut command = Command::new(proc_path(&inherit));
        std::os::unix::process::CommandExt::arg0(&mut command, &self.path);
        Ok(PreparedCommand { command, inherit })
    }

    /// Run `prepared` under the deadline and output bounds.
    ///
    /// # Errors
    ///
    /// `IO_FAILED` when the child cannot be spawned or waited for;
    /// `GIT_DEADLINE_EXCEEDED` or `GIT_OUTPUT_BOUND_EXCEEDED` when a bound
    /// trips, after the child was killed.
    pub(crate) fn execute(
        &self,
        prepared: PreparedCommand,
        verb: &str,
    ) -> Result<BoundedOutput, CapabilityError> {
        let PreparedCommand {
            mut command,
            inherit,
        } = prepared;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let started = Instant::now();
        let mut child = command
            .spawn()
            .map_err(|err| io_err(&format!("spawn git {verb}"), &err))?;
        drop(inherit);
        let stdout = StreamReader::spawn(child.stdout.take(), self.bounds.max_stdout_bytes)?;
        let stderr = StreamReader::spawn(child.stderr.take(), self.bounds.max_stderr_bytes)?;
        loop {
            if let Some(stream) = tripped(&stdout, &stderr) {
                reap(&mut child);
                return Err(self.output_error(verb, stream).into());
            }
            match child.try_wait() {
                Ok(Some(status)) => return self.collect(verb, status, started, &stdout, &stderr),
                Ok(None) => {}
                Err(err) => {
                    reap(&mut child);
                    return Err(io_err(&format!("wait git {verb}"), &err));
                }
            }
            if started.elapsed() >= self.bounds.deadline {
                reap(&mut child);
                return Err(self.deadline_error(verb).into());
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn collect(
        &self,
        verb: &str,
        status: ExitStatus,
        started: Instant,
        stdout: &StreamReader,
        stderr: &StreamReader,
    ) -> Result<BoundedOutput, CapabilityError> {
        let remaining = || self.bounds.deadline.saturating_sub(started.elapsed());
        let (Some(stdout_bytes), Some(stderr_bytes)) =
            (stdout.finish(remaining()), stderr.finish(remaining()))
        else {
            return Err(self.deadline_error(verb).into());
        };
        if let Some(stream) = tripped(stdout, stderr) {
            return Err(self.output_error(verb, stream).into());
        }
        Ok(BoundedOutput {
            status,
            stdout: stdout_bytes,
            stderr: stderr_bytes,
        })
    }

    fn output_error(&self, verb: &str, stream: &'static str) -> GitBinaryError {
        let limit = match stream {
            "stdout" => self.bounds.max_stdout_bytes,
            _ => self.bounds.max_stderr_bytes,
        };
        GitBinaryError::OutputBoundExceeded {
            verb: verb.to_owned(),
            stream,
            limit,
        }
    }

    fn deadline_error(&self, verb: &str) -> GitBinaryError {
        GitBinaryError::DeadlineExceeded {
            verb: verb.to_owned(),
            limit_ms: self.bounds.deadline.as_millis(),
        }
    }
}
