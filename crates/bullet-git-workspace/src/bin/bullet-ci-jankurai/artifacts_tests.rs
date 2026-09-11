use super::*;
use std::fs;
use std::os::unix::fs::{symlink, PermissionsExt};

fn fixture() -> (tempfile::TempDir, String) {
    let directory = tempfile::tempdir().unwrap();
    let path = directory
        .path()
        .join("artifact")
        .to_str()
        .unwrap()
        .to_owned();
    fs::write(&path, b"original bytes").unwrap();
    (directory, path)
}

#[test]
fn exact_artifact_bytes_and_hash_survive_readback() {
    let (_directory, path) = fixture();
    let artifact = read(&path).unwrap();
    assert_eq!(artifact.bytes, b"original bytes");
    assert_eq!(
        artifact.subject["sha256"],
        hex::encode(Sha256::digest(b"original bytes"))
    );
    artifact.recheck().unwrap();
}

#[test]
fn rejects_leaf_and_ancestor_symlinks() {
    let (directory, path) = fixture();
    let leaf = directory.path().join("leaf");
    symlink(&path, &leaf).unwrap();
    assert!(read(leaf.to_str().unwrap()).is_err());
    let alias = directory.path().join("alias");
    symlink(directory.path(), &alias).unwrap();
    assert!(read(alias.join("artifact").to_str().unwrap()).is_err());
}

#[test]
fn fifo_and_sparse_oversize_refuse_before_read() {
    let (directory, path) = fixture();
    let fifo = directory.path().join("fifo");
    rustix::fs::mkfifoat(rustix::fs::CWD, &fifo, Mode::from_raw_mode(0o600)).unwrap();
    assert!(matches!(read(fifo.to_str().unwrap()), Err(e) if e == "ARTIFACT_KIND_OR_LIMIT"));
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(MAX_FILE + 1)
        .unwrap();
    assert!(matches!(read(&path), Err(e) if e == "ARTIFACT_KIND_OR_LIMIT"));
}

#[test]
fn changed_and_restored_open_input_is_not_accepted() {
    let (_directory, path) = fixture();
    // An old initial timestamp makes actual replacement writes observable even
    // when two writes share a filesystem clock tick. This is not a write monitor.
    File::options()
        .write(true)
        .open(&path)
        .unwrap()
        .set_modified(std::time::SystemTime::UNIX_EPOCH)
        .unwrap();
    let initial = fs::metadata(&path).unwrap().modified().unwrap();
    let result = read_with(&path, |_| {
        fs::write(&path, b"replacement").map_err(io)?;
        fs::write(&path, b"original bytes").map_err(io)?;
        assert_ne!(fs::metadata(&path).unwrap().modified().unwrap(), initial);
        Ok(())
    });
    assert!(matches!(result, Err(e) if e == "ARTIFACT_CHANGED_DURING_READ"));
    assert_eq!(fs::read(path).unwrap(), b"original bytes");
}

#[test]
fn replaced_lookup_is_refused_after_descriptor_read() {
    let (directory, path) = fixture();
    let result = read_with(&path, |_| {
        fs::rename(&path, directory.path().join("old")).map_err(io)?;
        fs::write(&path, b"original bytes").map_err(io)
    });
    assert!(result.is_err());
}

#[test]
fn later_same_bytes_replacement_invalidates_subject() {
    let (directory, path) = fixture();
    let artifact = read(&path).unwrap();
    fs::rename(&path, directory.path().join("old")).unwrap();
    fs::write(&path, b"original bytes").unwrap();
    assert!(artifact.recheck().is_err());
}

#[test]
fn exclusive_publication_preserves_original_on_collision() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("report");
    let path = path.to_str().unwrap();
    publish(path, b"retained").unwrap();
    assert!(publish(path, b"overwrite").is_err());
    assert_eq!(fs::read(path).unwrap(), b"retained");
    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn exclusive_runtime_refuses_existing_and_symlink_destinations() {
    let directory = tempfile::tempdir().unwrap();
    let runtime = directory.path().join("runtime");
    new_directory(runtime.to_str().unwrap()).unwrap();
    assert_eq!(
        fs::metadata(&runtime).unwrap().permissions().mode() & 0o777,
        0o700
    );
    fs::write(runtime.join("sentinel"), b"retained").unwrap();
    assert!(new_directory(runtime.to_str().unwrap()).is_err());
    assert_eq!(fs::read(runtime.join("sentinel")).unwrap(), b"retained");
    let alias = directory.path().join("alias");
    symlink(&runtime, &alias).unwrap();
    assert!(new_directory(alias.to_str().unwrap()).is_err());
}
