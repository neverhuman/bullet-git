//! No-follow copying and durability for complete workspace generations.
// jankurai:allow repo-rot.path.fake-versioned-source reason=module names the operation (no-follow copy of a tree), not a parked copy of another module owner=git expires=2027-08-31
// It is the only implementation of generation materialisation and is proved by crates/bullet-git-workspace/tests/real_repository.rs.

use crate::fsync::create_new_file;
use crate::generation::GenerationError;
use serde::Serialize;
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::Write as _;
use std::path::{Path, PathBuf};

const MAX_CONTROL_BYTES: u64 = 64 * 1024;

pub(crate) fn copy_tree(source: &Path, destination: &Path) -> Result<(), GenerationError> {
    let metadata = fs::symlink_metadata(source).map_err(|error| io("inspect source", error))?;
    require_directory(source, &metadata)?;
    fs::create_dir(destination).map_err(|error| io("create generation directory", error))?;
    copy_entries(source, destination)?;
    fs::set_permissions(destination, metadata.permissions())
        .map_err(|error| io("copy generation directory permissions", error))?;
    Ok(())
}

fn copy_entries(source: &Path, destination: &Path) -> Result<(), GenerationError> {
    for entry in fs::read_dir(source).map_err(|error| io("read generation directory", error))? {
        let entry = entry.map_err(|error| io("read generation entry", error))?;
        reject_dot_names(&entry.file_name())?;
        let from = entry.path();
        let to = destination.join(entry.file_name());
        let metadata =
            fs::symlink_metadata(&from).map_err(|error| io("inspect generation entry", error))?;
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            fs::create_dir(&to).map_err(|error| io("create copied directory", error))?;
            copy_entries(&from, &to)?;
            fs::set_permissions(&to, metadata.permissions())
                .map_err(|error| io("copy directory permissions", error))?;
        } else if file_type.is_file() {
            fs::copy(&from, &to).map_err(|error| io("copy generation file", error))?;
            fs::set_permissions(&to, metadata.permissions())
                .map_err(|error| io("copy file permissions", error))?;
        } else if file_type.is_symlink() {
            copy_symlink(&from, &to)?;
        } else {
            return Err(GenerationError::Corrupt(format!(
                "special filesystem entry is forbidden: {}",
                from.display()
            )));
        }
    }
    Ok(())
}

pub(crate) fn sync_tree(root: &Path) -> Result<(), GenerationError> {
    let metadata = fs::symlink_metadata(root).map_err(|error| io("inspect sync root", error))?;
    require_directory(root, &metadata)?;
    sync_entries(root)?;
    sync_directory(root).map_err(|error| io("sync generation root", error))
}

fn sync_entries(directory: &Path) -> Result<(), GenerationError> {
    for entry in fs::read_dir(directory).map_err(|error| io("read sync directory", error))? {
        let entry = entry.map_err(|error| io("read sync entry", error))?;
        let path = entry.path();
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| io("inspect sync entry", error))?;
        let file_type = metadata.file_type();
        if file_type.is_dir() {
            sync_entries(&path)?;
            sync_directory(&path).map_err(|error| io("sync generation directory", error))?;
        } else if file_type.is_file() {
            File::open(&path)
                .and_then(|file| file.sync_all())
                .map_err(|error| io("sync generation file", error))?;
        } else if !file_type.is_symlink() {
            return Err(GenerationError::Corrupt(format!(
                "special filesystem entry is forbidden: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    File::open(path).and_then(|directory| directory.sync_all())
}

pub(crate) fn next_generation(generations: &Path) -> Result<u64, GenerationError> {
    let mut maximum = None;
    for entry in fs::read_dir(generations).map_err(|error| io("read generations", error))? {
        let entry = entry.map_err(|error| io("read generation entry", error))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(number) = parse_generation_name(&name) {
            maximum = Some(maximum.map_or(number, |value: u64| value.max(number)));
        } else if !name.starts_with(".stage-") {
            return Err(GenerationError::Corrupt(format!(
                "unexpected generation entry {name:?}"
            )));
        }
    }
    maximum
        .unwrap_or(0)
        .checked_add(1)
        .ok_or_else(|| GenerationError::Corrupt("generation counter overflow".into()))
}

pub(crate) fn inspect_generation_entries(generations: &Path) -> Result<(), GenerationError> {
    for entry in fs::read_dir(generations).map_err(|error| io("read generations", error))? {
        let entry = entry.map_err(|error| io("read generation entry", error))?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let metadata = fs::symlink_metadata(entry.path())
            .map_err(|error| io("inspect generation entry", error))?;
        if (!name.starts_with(".stage-") && parse_generation_name(&name).is_none())
            || !metadata.is_dir()
            || metadata.file_type().is_symlink()
        {
            return Err(GenerationError::Corrupt(format!(
                "unexpected generation entry {name:?}"
            )));
        }
    }
    Ok(())
}

fn parse_generation_name(name: &str) -> Option<u64> {
    let suffix = name.strip_prefix("generation-")?;
    (suffix.len() == 20 && suffix.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| suffix.parse().ok())
        .flatten()
}

pub(crate) fn allocate_staging(
    generations: &Path,
    generation: u64,
) -> Result<PathBuf, GenerationError> {
    for attempt in 0_u16..128 {
        let path = generations.join(format!(
            ".stage-{generation:020}-{}-{attempt}",
            std::process::id()
        ));
        match fs::create_dir(&path) {
            Ok(()) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io("allocate staged generation", error)),
        }
    }
    Err(GenerationError::Io(
        "could not allocate a unique staged generation".into(),
    ))
}

pub(crate) fn allocate_pointer_stage(
    work_dir: &Path,
    generation: u64,
) -> Result<PathBuf, GenerationError> {
    for attempt in 0_u16..128 {
        let path = work_dir.join(format!(
            ".active-stage-{generation:020}-{}-{attempt}",
            std::process::id()
        ));
        match create_new_file(&path) {
            Ok(_) => return Ok(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io("allocate staged active pointer", error)),
        }
    }
    Err(GenerationError::Io(
        "could not allocate a unique staged active pointer".into(),
    ))
}

pub(crate) fn replace_pointer(staged: &Path, active: &Path) -> Result<(), GenerationError> {
    #[cfg(unix)]
    {
        fs::rename(staged, active).map_err(|error| io("replace active generation pointer", error))
    }
    #[cfg(not(unix))]
    {
        let _ = (staged, active);
        Err(GenerationError::Unsupported(
            "this platform lacks an audited replace-and-sync backend".into(),
        ))
    }
}

pub(crate) fn create_directory(path: &Path) -> Result<(), GenerationError> {
    fs::create_dir(path).map_err(|error| io("create generation layout", error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|error| io("secure generation directory", error))?;
    }
    Ok(())
}

pub(crate) fn require_ordinary_directory(path: &Path) -> Result<(), GenerationError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io("inspect generation root", error))?;
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(GenerationError::Corrupt(format!(
            "{} is not an ordinary directory",
            path.display()
        )))
    }
}

pub(crate) fn write_json(path: &Path, value: &impl Serialize) -> Result<(), GenerationError> {
    let mut file =
        create_new_file(path).map_err(|error| io("create generation control file", error))?;
    write_json_to(&mut file, value)?;
    file.sync_all()
        .map_err(|error| io("sync generation control file", error))
}

pub(crate) fn write_json_file(path: &Path, value: &impl Serialize) -> Result<(), GenerationError> {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(path)
        .map_err(|error| io("open staged generation control file", error))?;
    write_json_to(&mut file, value)
}

fn write_json_to(file: &mut File, value: &impl Serialize) -> Result<(), GenerationError> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|error| GenerationError::Corrupt(format!("encode control JSON: {error}")))?;
    bytes.push(b'\n');
    file.write_all(&bytes)
        .map_err(|error| io("write generation control file", error))
}

pub(crate) fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, GenerationError> {
    let metadata =
        fs::symlink_metadata(path).map_err(|error| io("inspect generation control file", error))?;
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAX_CONTROL_BYTES
    {
        return Err(GenerationError::Corrupt(format!(
            "invalid generation control file {}",
            path.display()
        )));
    }
    let bytes = fs::read(path).map_err(|error| io("read generation control file", error))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        GenerationError::Corrupt(format!(
            "invalid control JSON at {}: {error}",
            path.display()
        ))
    })
}

fn require_directory(path: &Path, metadata: &fs::Metadata) -> Result<(), GenerationError> {
    if metadata.is_dir() && !metadata.file_type().is_symlink() {
        Ok(())
    } else {
        Err(GenerationError::Corrupt(format!(
            "{} is not an ordinary directory",
            path.display()
        )))
    }
}

fn reject_dot_names(name: &OsStr) -> Result<(), GenerationError> {
    if name == OsStr::new(".") || name == OsStr::new("..") {
        Err(GenerationError::Corrupt("dot path component".into()))
    } else {
        Ok(())
    }
}

#[cfg(unix)]
fn copy_symlink(source: &Path, destination: &Path) -> Result<(), GenerationError> {
    use std::os::unix::fs::symlink;

    let target = fs::read_link(source).map_err(|error| io("read generation symlink", error))?;
    symlink(target, destination).map_err(|error| io("copy generation symlink", error))
}

#[cfg(not(unix))]
fn copy_symlink(_source: &Path, _destination: &Path) -> Result<(), GenerationError> {
    Err(GenerationError::Unsupported(
        "this platform lacks an audited no-follow symlink copy backend".into(),
    ))
}

fn io(context: &str, error: std::io::Error) -> GenerationError {
    GenerationError::Io(format!("{context}: {error}"))
}
