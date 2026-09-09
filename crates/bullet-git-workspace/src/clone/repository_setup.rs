use crate::reflink::{copy_tree_prefers_reflink, CopyMode};
use crate::safe_git::{FileProtocol, HeadState, SafeGit};
use crate::{io_err, CapabilityError};
use bullet_git_types::{GitOid, GitOidAlgorithm};
use std::fs::{self, File};
use std::path::Path;

pub(super) fn prepare_private_directory(path: &Path) -> Result<(), CapabilityError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => require_ordinary_runtime_directory(path, &metadata)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => match fs::create_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata = fs::symlink_metadata(path)
                    .map_err(|error| io_err("reinspect runtime directory", &error))?;
                require_ordinary_runtime_directory(path, &metadata)?;
            }
            Err(error) => return Err(io_err("create runtime directory", &error)),
        },
        Err(error) => return Err(io_err("inspect runtime directory", &error)),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| io_err("secure runtime directory", &error))?;
    }
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_err("sync runtime directory", &error))?;
    if let Some(parent) = path.parent() {
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| io_err("sync runtime parent", &error))?;
    }
    Ok(())
}

fn require_ordinary_runtime_directory(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), CapabilityError> {
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(CapabilityError::Io(format!(
            "runtime path is not an ordinary directory: {}",
            path.display()
        )))
    }
}

/// Build a remote-free repository and independently materialize its objects.
pub(super) fn clone_from_mirror(
    git: &SafeGit,
    mirror: &Path,
    dest: &Path,
    algorithm: GitOidAlgorithm,
) -> Result<CopyMode, CapabilityError> {
    let destination = dest.to_string_lossy().into_owned();
    let object_format = format!("--object-format={}", algorithm.as_str());
    git.run(
        None,
        FileProtocol::Never,
        &["init", "--quiet", &object_format, &destination],
        &[],
    )?;
    let git_dir = dest.join(".git");
    let objects = git_dir.join("objects");
    require_empty_initial_object_directory(&objects)?;
    let staged_objects = git_dir.join("bullet-objects-stage");
    let mode = copy_tree_prefers_reflink(&mirror.join("objects"), &staged_objects)?;
    if fs::symlink_metadata(staged_objects.join("info").join("alternates")).is_ok() {
        fs::remove_dir_all(&staged_objects)
            .map_err(|error| io_err("remove alternate-backed object stage", &error))?;
        return Err(CapabilityError::Git(
            "mirror object store depends on forbidden alternates".into(),
        ));
    }
    remove_empty_initial_object_directory(&objects)?;
    fs::rename(&staged_objects, &objects)
        .map_err(|error| io_err("install private object store", &error))?;
    File::open(&git_dir)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_err("sync private git directory", &error))?;
    Ok(mode)
}

fn require_empty_initial_object_directory(objects: &Path) -> Result<(), CapabilityError> {
    let metadata = fs::symlink_metadata(objects)
        .map_err(|error| io_err("inspect initial object directory", &error))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(CapabilityError::Io(
            "initial Git object path is not an ordinary directory".into(),
        ));
    }
    for entry in fs::read_dir(objects).map_err(|error| io_err("read initial objects", &error))? {
        let entry = entry.map_err(|error| io_err("read initial object entry", &error))?;
        let name = entry.file_name();
        if name != "info" && name != "pack" {
            return Err(CapabilityError::Io(format!(
                "unexpected initial Git object entry: {}",
                entry.path().display()
            )));
        }
        let metadata = entry
            .file_type()
            .map_err(|error| io_err("inspect initial object entry", &error))?;
        if !metadata.is_dir()
            || fs::read_dir(entry.path())
                .map_err(|error| io_err("read initial object subdirectory", &error))?
                .next()
                .is_some()
        {
            return Err(CapabilityError::Io(format!(
                "initial Git object entry is not an empty directory: {}",
                entry.path().display()
            )));
        }
    }
    Ok(())
}

fn remove_empty_initial_object_directory(objects: &Path) -> Result<(), CapabilityError> {
    for name in ["info", "pack"] {
        let path = objects.join(name);
        match fs::remove_dir(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(io_err("remove initial object subdirectory", &error)),
        }
    }
    fs::remove_dir(objects).map_err(|error| io_err("remove initial object directory", &error))
}

/// Detached checkout of the exact base, then creation of the private branch.
///
/// Detached HEAD between the two steps is the expected state and is detected
/// structurally via `symbolic-ref`, never by comparing a branch name to
/// the string "HEAD".
pub(super) fn checkout_private_branch(
    git: &SafeGit,
    repo_dir: &Path,
    base: &GitOid,
    branch: &str,
) -> Result<(), CapabilityError> {
    git.run(
        Some(repo_dir),
        FileProtocol::Never,
        &["checkout", "--detach", base.hex()],
        &[],
    )?;
    match git.head_state(repo_dir)? {
        HeadState::Detached => {}
        HeadState::Branch(name) => {
            return Err(CapabilityError::Git(format!(
                "expected detached base checkout, found branch {name}"
            )));
        }
    }
    git.run(
        Some(repo_dir),
        FileProtocol::Never,
        &["checkout", "-b", branch],
        &[],
    )?;
    Ok(())
}

/// Fail closed unless `repo` is a plain repository rooted exactly at `repo`.
///
/// A `.git` file (the on-disk shape of a worktree) is `WORKTREE_FORBIDDEN`; a
/// toplevel other than `repo` (upward discovery) is `WRONG_REPOSITORY`.
///
/// # Errors
///
/// Returns `WORKTREE_FORBIDDEN`, `WRONG_REPOSITORY`, or `IO_FAILED`.
pub fn guard_repository(git: &SafeGit, repo: &Path) -> Result<(), CapabilityError> {
    let dot_git = repo.join(".git");
    let meta = fs::symlink_metadata(&dot_git)
        .map_err(|_| CapabilityError::WrongRepository(format!("{} has no .git", repo.display())))?;
    if !meta.is_dir() {
        return Err(CapabilityError::WorktreeForbidden(
            repo.display().to_string(),
        ));
    }
    let toplevel = git
        .run(
            Some(repo),
            FileProtocol::Never,
            &["rev-parse", "--show-toplevel"],
            &[],
        )?
        .text();
    let expected = fs::canonicalize(repo).map_err(|err| io_err("canonicalize repo", &err))?;
    let actual =
        fs::canonicalize(&toplevel).map_err(|err| io_err("canonicalize toplevel", &err))?;
    if expected != actual {
        return Err(CapabilityError::WrongRepository(format!(
            "toplevel {} != expected {}",
            actual.display(),
            expected.display()
        )));
    }
    Ok(())
}

/// Refuse when sequencer state is present (spec: checkpoint/prepare time).
///
/// # Errors
///
/// Returns `SEQUENCER_ACTIVE` naming the state file.
pub fn sequencer_check(repo: &Path) -> Result<(), CapabilityError> {
    for name in ["CHERRY_PICK_HEAD", "MERGE_HEAD", "REBASE_HEAD"] {
        if repo.join(".git").join(name).exists() {
            return Err(CapabilityError::SequencerActive(name.to_string()));
        }
    }
    Ok(())
}
