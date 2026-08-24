//! Filesystem containment, copying, hashing, and private seal persistence.

use crate::fsync::create_new_file;
use crate::preservation::PreservationError;
use crate::tree_copy::{copy_tree, sync_directory, sync_tree};
use bullet_git_types::Digest;
use std::fs::{self, File};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};

const SEAL_FILE: &str = "preservation-seal-v1.key";
const HASH_DOMAIN: &[u8] = b"bullet-git-preservation-artifact-v1";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DestinationIdentity {
    pub(crate) canonical: PathBuf,
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

pub(crate) fn open_private_seal(runtime: &Path) -> Result<[u8; 32], PreservationError> {
    let path = runtime.join(SEAL_FILE);
    match create_new_file(&path) {
        Ok(mut file) => {
            let mut key = [0_u8; 32];
            fill_random(&mut key)?;
            file.write_all(&key)
                .and_then(|()| file.sync_all())
                .map_err(|error| io("write private preservation seal", error))?;
            sync_directory(runtime)
                .map_err(|error| io("sync preservation seal directory", error))?;
            validate_seal_file(&path)?;
            Ok(key)
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => read_seal(&path),
        Err(error) => Err(io("create private preservation seal", error)),
    }
}

fn read_seal(path: &Path) -> Result<[u8; 32], PreservationError> {
    validate_seal_file(path)?;
    let bytes = fs::read(path).map_err(|error| io("read private preservation seal", error))?;
    bytes
        .try_into()
        .map_err(|_| PreservationError::Corrupt("preservation seal length changed".into()))
}

fn validate_seal_file(path: &Path) -> Result<(), PreservationError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|error| io("inspect private preservation seal", error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() != 32 {
        return Err(PreservationError::Corrupt(
            "preservation seal is not one ordinary 32-byte file".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        if metadata.mode() & 0o077 != 0 || metadata.nlink() != 1 {
            return Err(PreservationError::Corrupt(
                "preservation seal permissions or link count changed".into(),
            ));
        }
    }
    #[cfg(not(unix))]
    return Err(PreservationError::Unsupported(
        "this platform lacks an audited private-seal backend".into(),
    ));
    Ok(())
}

#[cfg(unix)]
fn fill_random(bytes: &mut [u8]) -> Result<(), PreservationError> {
    File::open("/dev/urandom")
        .and_then(|mut random| random.read_exact(bytes))
        .map_err(|error| io("read operating-system randomness", error))
}

#[cfg(not(unix))]
fn fill_random(_bytes: &mut [u8]) -> Result<(), PreservationError> {
    Err(PreservationError::Unsupported(
        "this platform lacks an audited random-seal backend".into(),
    ))
}

pub(crate) fn create_external_destination(
    requested: &Path,
    forbidden: &[&Path],
) -> Result<DestinationIdentity, PreservationError> {
    if !requested.is_absolute() || requested.file_name().is_none() {
        return Err(PreservationError::InvalidDestination(
            "destination must be an absolute new directory".into(),
        ));
    }
    let parent = requested
        .parent()
        .ok_or_else(|| PreservationError::InvalidDestination("destination has no parent".into()))?;
    let canonical_parent = fs::canonicalize(parent)
        .map_err(|error| invalid_destination("canonicalize destination parent", error))?;
    if parent != canonical_parent {
        return Err(PreservationError::InvalidDestination(
            "destination parent contains a symlink or non-canonical component".into(),
        ));
    }
    for target in forbidden {
        let canonical = fs::canonicalize(target)
            .map_err(|error| invalid_destination("canonicalize cleanup target", error))?;
        if paths_overlap(requested, &canonical) {
            return Err(PreservationError::InvalidDestination(format!(
                "destination overlaps cleanup-owned path {}",
                canonical.display()
            )));
        }
    }
    match fs::symlink_metadata(requested) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => {
            return Err(PreservationError::InvalidDestination(
                "destination already exists".into(),
            ));
        }
        Err(error) => return Err(invalid_destination("inspect destination", error)),
    }
    fs::create_dir(requested).map_err(|error| invalid_destination("create destination", error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(requested, fs::Permissions::from_mode(0o700))
            .map_err(|error| io("secure destination", error))?;
    }
    sync_directory(parent).map_err(|error| io("sync destination parent", error))?;
    destination_identity(requested)
}

pub(crate) fn destination_identity(path: &Path) -> Result<DestinationIdentity, PreservationError> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        PreservationError::ReceiptRefused(format!("destination missing: {error}"))
    })?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(PreservationError::ReceiptRefused(
            "destination is no longer an ordinary directory".into(),
        ));
    }
    let canonical = fs::canonicalize(path).map_err(|error| {
        PreservationError::ReceiptRefused(format!("canonicalize destination: {error}"))
    })?;
    if canonical != path {
        return Err(PreservationError::ReceiptRefused(
            "destination path identity changed".into(),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        Ok(DestinationIdentity {
            canonical,
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    Err(PreservationError::Unsupported(
        "this platform lacks audited destination identity".into(),
    ))
}

pub(crate) fn copy_artifact_tree(
    source: &Path,
    destination: &Path,
) -> Result<(), PreservationError> {
    copy_tree(source, destination).map_err(|error| PreservationError::Io(error.to_string()))
}

pub(crate) fn copy_artifact_file(
    source: &Path,
    destination: &Path,
) -> Result<(), PreservationError> {
    let metadata =
        fs::symlink_metadata(source).map_err(|error| io("inspect artifact file", error))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(PreservationError::Corrupt(format!(
            "artifact source is not an ordinary file: {}",
            source.display()
        )));
    }
    let mut from = File::open(source).map_err(|error| io("open artifact source", error))?;
    let mut to = create_new_file(destination).map_err(|error| io("create artifact file", error))?;
    std::io::copy(&mut from, &mut to).map_err(|error| io("copy artifact file", error))?;
    to.sync_all()
        .map_err(|error| io("sync artifact file", error))
}

pub(crate) fn sync_artifact(root: &Path) -> Result<(), PreservationError> {
    sync_tree(root).map_err(|error| PreservationError::Io(error.to_string()))?;
    let parent = root
        .parent()
        .ok_or_else(|| PreservationError::Corrupt("artifact has no parent".into()))?;
    sync_directory(parent).map_err(|error| io("sync artifact parent", error))
}

pub(crate) fn hash_artifact(root: &Path) -> Result<Digest, PreservationError> {
    let mut hasher = blake3::Hasher::new();
    hash_field(&mut hasher, HASH_DOMAIN);
    hash_entries(root, root, &mut hasher)?;
    Digest::from_hex(hasher.finalize().to_hex().as_str())
        .map_err(|error| PreservationError::Corrupt(error.to_string()))
}

fn hash_entries(
    root: &Path,
    directory: &Path,
    hasher: &mut blake3::Hasher,
) -> Result<(), PreservationError> {
    let mut entries = fs::read_dir(directory)
        .map_err(|error| io("read artifact directory", error))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| io("read artifact entry", error))?;
    entries.sort_by_key(std::fs::DirEntry::file_name);
    for entry in entries {
        let path = entry.path();
        let relative = path
            .strip_prefix(root)
            .map_err(|error| PreservationError::Corrupt(error.to_string()))?;
        let relative = relative
            .to_str()
            .ok_or_else(|| PreservationError::Unsupported("non-UTF-8 artifact path".into()))?;
        let metadata =
            fs::symlink_metadata(&path).map_err(|error| io("inspect artifact", error))?;
        hash_field(hasher, relative.as_bytes());
        if metadata.file_type().is_dir() {
            hash_field(hasher, b"directory");
            hash_mode(hasher, &metadata);
            hash_entries(root, &path, hasher)?;
        } else if metadata.file_type().is_file() {
            hash_field(hasher, b"file");
            hash_mode(hasher, &metadata);
            hash_field(hasher, &metadata.len().to_le_bytes());
            let mut file = File::open(&path).map_err(|error| io("open artifact", error))?;
            let mut buffer = [0_u8; 64 * 1024];
            loop {
                let read = file
                    .read(&mut buffer)
                    .map_err(|error| io("hash artifact", error))?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
        } else if metadata.file_type().is_symlink() {
            hash_field(hasher, b"symlink");
            let target =
                fs::read_link(&path).map_err(|error| io("read artifact symlink", error))?;
            let target = target
                .to_str()
                .ok_or_else(|| PreservationError::Unsupported("non-UTF-8 symlink target".into()))?;
            hash_field(hasher, target.as_bytes());
        } else {
            return Err(PreservationError::Corrupt(format!(
                "special artifact entry: {}",
                path.display()
            )));
        }
    }
    Ok(())
}

fn hash_field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

#[cfg(unix)]
fn hash_mode(hasher: &mut blake3::Hasher, metadata: &fs::Metadata) {
    use std::os::unix::fs::MetadataExt as _;
    hash_field(hasher, &(metadata.mode() & 0o7777).to_le_bytes());
}

#[cfg(not(unix))]
fn hash_mode(_hasher: &mut blake3::Hasher, _metadata: &fs::Metadata) {}

fn paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn invalid_destination(context: &str, error: std::io::Error) -> PreservationError {
    PreservationError::InvalidDestination(format!("{context}: {error}"))
}

fn io(context: &str, error: std::io::Error) -> PreservationError {
    PreservationError::Io(format!("{context}: {error}"))
}
