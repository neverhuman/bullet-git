//! Small filesystem durability helpers shared only inside the workspace crate.

use std::fs::{File, Metadata, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::cas::CasError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Boundary {
    Allocate,
    Write,
    FileSync,
    Publish,
    DirectorySync,
}

pub(crate) trait Faults {
    fn trips(&mut self, _boundary: Boundary) -> bool {
        false
    }

    fn check(&mut self, boundary: Boundary) -> Result<(), CasError> {
        if self.trips(boundary) {
            Err(injected(boundary))
        } else {
            Ok(())
        }
    }
}

pub(crate) struct NoFault;
impl Faults for NoFault {}

pub(crate) fn injected(boundary: Boundary) -> CasError {
    CasError::Io(format!("injected {boundary:?} failure"))
}

pub(crate) fn validate_storage_root(root: &Path) -> Result<PathBuf, String> {
    if !root.is_absolute() {
        return Err("root must be an absolute server-selected path".into());
    }
    let metadata =
        std::fs::symlink_metadata(root).map_err(|error| format!("{}: {error}", root.display()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(format!("{} is not an ordinary directory", root.display()));
    }
    let canonical =
        std::fs::canonicalize(root).map_err(|error| format!("{}: {error}", root.display()))?;
    if canonical != root {
        return Err(format!(
            "{} contains a symlink or non-canonical component",
            root.display()
        ));
    }
    validate_storage_ancestry(&canonical, &metadata)?;
    Ok(canonical)
}

/// Validate the server-owned containment chain for a dedicated CAS root.
///
/// On Unix the root owner is the server-selected trust anchor. Ancestors must
/// be owned by that UID or UID 0. Writable ancestors are accepted only with the
/// sticky bit, which permits conventional trusted roots such as `/tmp` without
/// permitting another user to replace the server-owned child. The root itself
/// is never accepted writable by group or other. Deployment remains responsible
/// for selecting the root and constraining ACLs and mount namespaces.
#[cfg(unix)]
fn validate_storage_ancestry(root: &Path, root_metadata: &Metadata) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt as _;

    let root_owner = root_metadata.uid();
    for (depth, component) in root.ancestors().enumerate() {
        let metadata = std::fs::symlink_metadata(component)
            .map_err(|error| format!("cannot inspect {}: {error}", component.display()))?;
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(format!(
                "{} is not an ordinary ancestor directory",
                component.display()
            ));
        }
        if !unix_component_is_trusted(root_owner, metadata.uid(), metadata.mode(), depth == 0) {
            return Err(format!(
                "{} has an untrusted owner or writable mode",
                component.display()
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn unix_component_is_trusted(root_owner: u32, owner: u32, mode: u32, is_root: bool) -> bool {
    let trusted_owner = owner == root_owner || owner == 0;
    let externally_writable = mode & 0o022 != 0;
    let protected_ancestor = !externally_writable || (!is_root && mode & 0o1000 != 0);
    trusted_owner && protected_ancestor
}

#[cfg(not(unix))]
fn validate_storage_ancestry(_root: &Path, _root_metadata: &Metadata) -> Result<(), String> {
    Err("this platform lacks an audited CAS root-containment backend".into())
}

pub(crate) fn sync_directory(path: &Path) -> Result<(), std::io::Error> {
    File::open(path).and_then(|directory| directory.sync_all())
}

pub(crate) fn create_new_file(path: &Path) -> Result<File, std::io::Error> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options.open(path)
}

pub(crate) fn write_new_durable_file(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut file = create_new_file(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    let parent = path.parent().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "durable file has no parent directory",
        )
    })?;
    sync_directory(parent)
}

pub(crate) fn make_read_only(file: &File) -> Result<(), std::io::Error> {
    let mut permissions = file.metadata()?.permissions();
    permissions.set_readonly(true);
    file.set_permissions(permissions)
}

#[cfg(test)]
pub(crate) fn private_tempdir() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private CAS root");
    }
    root
}

#[cfg(all(test, unix))]
mod tests {
    use super::unix_component_is_trusted;

    #[test]
    fn owner_and_sticky_policy_is_explicit() {
        let server = 1_000;
        assert!(unix_component_is_trusted(server, server, 0o700, true));
        assert!(unix_component_is_trusted(server, 0, 0o755, false));
        assert!(unix_component_is_trusted(server, 0, 0o1777, false));
        assert!(!unix_component_is_trusted(server, server, 0o1777, true));
        assert!(!unix_component_is_trusted(server, 0, 0o777, false));
        assert!(!unix_component_is_trusted(server, 2_000, 0o755, false));
        assert!(!unix_component_is_trusted(server, 2_000, 0o1777, false));
    }
}
