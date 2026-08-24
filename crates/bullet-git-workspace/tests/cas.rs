//! Immutable CAS durability, corruption, and root-containment behavior.

use bullet_git_types::Digest;
use bullet_git_workspace::{cas_digest, ImmutableCas, PutDisposition, MAX_CAS_OBJECT_BYTES};
use std::sync::Arc;

#[test]
fn publication_and_exact_adoption_are_verified() {
    let root = private_tempdir();
    let cas = ImmutableCas::open(root.path()).expect("open");
    let bytes = b"immutable payload";
    let first = cas.put(bytes).expect("publish");
    assert_eq!(first.disposition, PutDisposition::Published);
    assert_eq!(first.digest, cas_digest(bytes));
    assert!(
        std::fs::metadata(root.path().join(first.digest.to_hex()))
            .expect("object metadata")
            .permissions()
            .readonly(),
        "authoritative object must not remain writable"
    );
    assert_ne!(
        first.digest,
        Digest::of(bytes),
        "CAS hash is domain separated"
    );

    let second = cas.put(bytes).expect("adopt");
    assert_eq!(second.digest, first.digest);
    assert_eq!(second.disposition, PutDisposition::Existing);
    assert_eq!(cas.get(&first.digest).expect("read"), Some(bytes.to_vec()));

    drop(cas);
    let reopened = ImmutableCas::open(root.path()).expect("reopen");
    assert_eq!(
        reopened.get(&first.digest).expect("read"),
        Some(bytes.to_vec())
    );
}

#[test]
fn concurrent_publication_creates_one_exact_object() {
    let root = private_tempdir();
    let cas = Arc::new(ImmutableCas::open(root.path()).expect("open"));
    let mut workers = Vec::new();
    for _ in 0..8 {
        let cas = Arc::clone(&cas);
        workers.push(std::thread::spawn(move || {
            cas.put(b"same bytes").expect("put")
        }));
    }
    let receipts = workers
        .into_iter()
        .map(|worker| worker.join().expect("worker"))
        .collect::<Vec<_>>();
    assert_eq!(
        receipts
            .iter()
            .filter(|receipt| receipt.disposition == PutDisposition::Published)
            .count(),
        1
    );
    assert!(receipts
        .windows(2)
        .all(|pair| pair[0].digest == pair[1].digest));
    let authoritative = std::fs::read_dir(root.path())
        .expect("read root")
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().len() == 64)
        .count();
    assert_eq!(authoritative, 1);
}

#[test]
fn oversize_is_refused_before_allocation() {
    let root = private_tempdir();
    let cas = ImmutableCas::open(root.path()).expect("open");
    let error = cas
        .put(&vec![0; MAX_CAS_OBJECT_BYTES + 1])
        .expect_err("oversize");
    assert_eq!(error.reason_code(), "CAS_OBJECT_TOO_LARGE");
    assert_eq!(
        std::fs::read_dir(root.path()).expect("read root").count(),
        0
    );
}

#[test]
fn existing_and_read_bytes_are_rehashed() {
    let root = private_tempdir();
    let cas = ImmutableCas::open(root.path()).expect("open");
    let receipt = cas.put(b"original").expect("publish");
    let object = root.path().join(receipt.digest.to_hex());
    make_owner_writable(&object);
    std::fs::write(&object, b"tampered").expect("tamper");
    make_read_only(&object);
    assert_eq!(
        cas.get(&receipt.digest)
            .expect_err("read corruption")
            .reason_code(),
        "CAS_CORRUPT"
    );
    assert_eq!(
        cas.put(b"original")
            .expect_err("adoption verifies bytes")
            .reason_code(),
        "CAS_CORRUPT"
    );
    assert_eq!(
        ImmutableCas::open(root.path())
            .expect_err("reopen corruption")
            .reason_code(),
        "CAS_CORRUPT"
    );
}

#[test]
fn unknown_or_nonregular_entries_fail_closed() {
    let unknown = private_tempdir();
    std::fs::write(unknown.path().join("unknown"), b"x").expect("unknown entry");
    assert_eq!(
        ImmutableCas::open(unknown.path())
            .expect_err("unknown refused")
            .reason_code(),
        "CAS_CORRUPT"
    );

    let directory = private_tempdir();
    let name = cas_digest(b"object").to_hex();
    std::fs::create_dir(directory.path().join(name)).expect("object-shaped directory");
    assert_eq!(
        ImmutableCas::open(directory.path())
            .expect_err("non-file refused")
            .reason_code(),
        "CAS_CORRUPT"
    );
}

#[test]
fn root_must_be_existing_absolute_and_canonical() {
    let relative = ImmutableCas::open("relative-cas").expect_err("relative refused");
    assert_eq!(relative.reason_code(), "CAS_ROOT_INVALID");
    let root = private_tempdir();
    let missing = root.path().join("missing");
    assert_eq!(
        ImmutableCas::open(&missing)
            .expect_err("missing refused")
            .reason_code(),
        "CAS_ROOT_INVALID"
    );
}

#[cfg(unix)]
#[test]
fn group_or_other_writable_root_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let root = tempfile::tempdir().expect("tempdir");
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o777))
        .expect("make unsafe root");
    assert_eq!(
        ImmutableCas::open(root.path())
            .expect_err("unsafe root refused")
            .reason_code(),
        "CAS_ROOT_INVALID"
    );
}

#[cfg(unix)]
#[test]
fn writable_nonsticky_ancestor_is_refused() {
    use std::os::unix::fs::PermissionsExt as _;

    let parent = private_tempdir();
    let ancestor = parent.path().join("shared");
    let root = ancestor.join("cas");
    std::fs::create_dir_all(&root).expect("CAS root");
    std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o777))
        .expect("make ancestor unsafe");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("make root private");

    assert_eq!(
        ImmutableCas::open(&root)
            .expect_err("non-sticky writable ancestor refused")
            .reason_code(),
        "CAS_ROOT_INVALID"
    );
}

#[cfg(unix)]
#[test]
fn trusted_sticky_ancestor_is_accepted() {
    use std::os::unix::fs::PermissionsExt as _;

    let parent = private_tempdir();
    let ancestor = parent.path().join("sticky");
    let root = ancestor.join("cas");
    std::fs::create_dir_all(&root).expect("CAS root");
    std::fs::set_permissions(&ancestor, std::fs::Permissions::from_mode(0o1777))
        .expect("make ancestor sticky");
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
        .expect("make root private");

    ImmutableCas::open(&root).expect("trusted sticky ancestor accepted");
}

#[cfg(unix)]
#[test]
fn symlinked_root_or_ancestor_is_refused() {
    let parent = private_tempdir();
    let actual = parent.path().join("actual");
    let root = actual.join("cas");
    std::fs::create_dir_all(&root).expect("actual root");

    let direct = parent.path().join("direct-link");
    std::os::unix::fs::symlink(&root, &direct).expect("direct symlink");
    assert_eq!(
        ImmutableCas::open(&direct)
            .expect_err("symlink root refused")
            .reason_code(),
        "CAS_ROOT_INVALID"
    );

    let ancestor = parent.path().join("ancestor-link");
    std::os::unix::fs::symlink(&actual, &ancestor).expect("ancestor symlink");
    assert_eq!(
        ImmutableCas::open(ancestor.join("cas"))
            .expect_err("symlink ancestor refused")
            .reason_code(),
        "CAS_ROOT_INVALID"
    );
}

#[cfg(unix)]
fn make_owner_writable(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt as _;

    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .expect("restore owner write for corruption fixture");
}

fn make_read_only(path: &std::path::Path) {
    let mut permissions = std::fs::metadata(path)
        .expect("object metadata")
        .permissions();
    permissions.set_readonly(true);
    std::fs::set_permissions(path, permissions).expect("restore object read-only state");
}

fn private_tempdir() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("private CAS root");
    }
    root
}

#[cfg(not(unix))]
fn make_owner_writable(path: &std::path::Path) {
    let mut permissions = std::fs::metadata(path)
        .expect("object metadata")
        .permissions();
    permissions.set_readonly(false);
    std::fs::set_permissions(path, permissions)
        .expect("restore owner write for corruption fixture");
}
