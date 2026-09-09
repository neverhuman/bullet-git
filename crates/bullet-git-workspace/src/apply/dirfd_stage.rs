//! StagedRoot descriptor-relative mutation.

use super::*;

impl StagedRoot {
    /// Open `root` as a directory without following a final-component symlink.
    pub(crate) fn open(root: &Path) -> Result<Self, DirfdError> {
        let fd = open(
            root,
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|errno| classify(errno, &root.display().to_string(), "open staged root"))?;
        Ok(Self { fd })
    }

    /// Read the regular file at `path`; `Ok(None)` when nothing exists there.
    pub(crate) fn read(&self, path: &str) -> Result<Option<Vec<u8>>, DirfdError> {
        validate_path(path)?;
        let flags = OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let fd = match open_beneath(self.fd.as_fd(), path, flags, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::NOENT) => return Ok(None),
            Err(errno) => return Err(self.diagnose(errno, path, "open prior bytes")),
        };
        require_regular(&fd, path, "inspect prior bytes")?;
        let mut bytes = Vec::new();
        File::from(fd)
            .read_to_end(&mut bytes)
            .map_err(|error| io(path, "read prior bytes", &error))?;
        Ok(Some(bytes))
    }

    /// Create or truncate the regular file at `path`, write `bytes`, fsync.
    pub(crate) fn write(&self, path: &str, bytes: &[u8]) -> Result<(), DirfdError> {
        let components = validate_path(path)?;
        let Some((leaf, directories)) = components.split_last() else {
            return Err(DirfdError::InvalidPath {
                path: path.to_owned(),
                reason: "empty path",
            });
        };
        let parent = self.ensure_directories(path, directories)?;
        let parent = parent.as_ref().map_or(self.fd.as_fd(), AsFd::as_fd);
        let flags =
            OFlags::WRONLY | OFlags::CREATE | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
        let fd = open_beneath(parent, leaf, flags, Mode::from_raw_mode(0o666))
            .map_err(|errno| self.diagnose(errno, path, "open patch target"))?;
        require_regular(&fd, path, "inspect patch target")?;
        ftruncate(&fd, 0).map_err(|errno| classify(errno, path, "truncate patch target"))?;
        let mut file = File::from(fd);
        file.write_all(bytes)
            .map_err(|error| io(path, "write patch target", &error))?;
        file.sync_all()
            .map_err(|error| io(path, "fsync patch target", &error))
    }

    /// Unlink the regular file at `path`; symlinks and non-files are refused.
    pub(crate) fn unlink(&self, path: &str) -> Result<(), DirfdError> {
        let components = validate_path(path)?;
        let Some((leaf, directories)) = components.split_last() else {
            return Err(DirfdError::InvalidPath {
                path: path.to_owned(),
                reason: "empty path",
            });
        };
        let parent = self.open_parent(path, directories)?;
        let parent = parent.as_ref().map_or(self.fd.as_fd(), AsFd::as_fd);
        let stat = match statat(parent, *leaf, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(Errno::NOENT) => {
                return Err(DirfdError::Absent {
                    path: path.to_owned(),
                })
            }
            Err(errno) => return Err(self.diagnose(errno, path, "inspect delete target")),
        };
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::RegularFile => {}
            FileType::Symlink => {
                return Err(DirfdError::Symlink {
                    path: path.to_owned(),
                })
            }
            _ => {
                return Err(DirfdError::NotRegularFile {
                    path: path.to_owned(),
                })
            }
        }
        unlinkat(parent, *leaf, AtFlags::empty())
            .map_err(|errno| self.diagnose(errno, path, "unlink delete target"))
    }

    /// Restore prior states in reverse order; every failure is aggregated.
    ///
    /// `Some(bytes)` rewrites the file; `None` removes it, and an already
    /// absent file counts as restored.
    pub(crate) fn restore<'a>(
        &self,
        entries: impl Iterator<Item = (&'a str, Option<&'a [u8]>)>,
    ) -> Result<(), DirfdError> {
        let mut failures = Vec::new();
        for (path, prior) in entries {
            let outcome = match prior {
                Some(bytes) => self.write(path, bytes),
                None => match self.unlink(path) {
                    Err(DirfdError::Absent { .. }) => Ok(()),
                    other => other,
                },
            };
            if let Err(error) = outcome {
                failures.push(RestoreFailure {
                    path: path.to_owned(),
                    reason_code: error.reason_code(),
                    message: error.to_string(),
                });
            }
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(DirfdError::Restore { failures })
        }
    }

    /// Open the directory holding the leaf without creating anything.
    fn open_parent(&self, path: &str, directories: &[&str]) -> Result<Option<OwnedFd>, DirfdError> {
        if directories.is_empty() {
            return Ok(None);
        }
        open_directory(self.fd.as_fd(), &directories.join("/"))
            .map(Some)
            .map_err(|errno| self.diagnose(errno, path, "open delete directory"))
    }

    /// Turn a kernel refusal into the exact typed reason. `openat2` reports a
    /// forbidden symlink component as `ELOOP` or, when `O_DIRECTORY` or a later
    /// component is involved, as `ENOTDIR`; a no-follow walk over the components
    /// tells the two apart. The walk is diagnostic only: safety came from the
    /// refused open itself.
    fn diagnose(&self, errno: Errno, path: &str, context: &'static str) -> DirfdError {
        if matches!(errno, Errno::NOTDIR | Errno::LOOP) {
            if let Some(found) = self.locate_offender(path) {
                return found;
            }
        }
        classify(errno, path, context)
    }

    fn locate_offender(&self, path: &str) -> Option<DirfdError> {
        let components = validate_path(path).ok()?;
        let last = components.len().checked_sub(1)?;
        let mut current: Option<OwnedFd> = None;
        for (index, component) in components.iter().enumerate() {
            let parent = current.as_ref().map_or(self.fd.as_fd(), AsFd::as_fd);
            let stat = statat(parent, *component, AtFlags::SYMLINK_NOFOLLOW).ok()?;
            match FileType::from_raw_mode(stat.st_mode) {
                FileType::Symlink => {
                    return Some(DirfdError::Symlink {
                        path: path.to_owned(),
                    })
                }
                FileType::Directory => {}
                _ if index < last => {
                    return Some(DirfdError::NotDirectory {
                        path: path.to_owned(),
                    })
                }
                _ => return None,
            }
            current = Some(open_directory(parent, component).ok()?);
        }
        None
    }

    /// Walk (and create when absent) each directory component one level at
    /// a time so no `mkdir` ever crosses a symlink.
    fn ensure_directories(
        &self,
        path: &str,
        directories: &[&str],
    ) -> Result<Option<OwnedFd>, DirfdError> {
        let mut current: Option<OwnedFd> = None;
        for component in directories {
            let parent = current.as_ref().map_or(self.fd.as_fd(), AsFd::as_fd);
            let next = match open_directory(parent, component) {
                Ok(fd) => fd,
                Err(Errno::NOENT) => {
                    match mkdirat(parent, *component, Mode::from_raw_mode(0o777)) {
                        Ok(()) | Err(Errno::EXIST) => {}
                        Err(errno) => {
                            return Err(self.diagnose(errno, path, "create patch directory"))
                        }
                    }
                    open_directory(parent, component).map_err(|errno| {
                        self.diagnose(errno, path, "open created patch directory")
                    })?
                }
                Err(errno) => return Err(self.diagnose(errno, path, "open patch directory")),
            };
            current = Some(next);
        }
        Ok(current)
    }
}
