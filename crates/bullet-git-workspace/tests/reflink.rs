//! Byte-identical fallback proof for the reflink clone path.

use bullet_git_workspace::{copy_tree_byte_identical, copy_tree_prefers_reflink, CopyMode};
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn fallback_copy_is_byte_identical() {
    let root = private_tempdir();
    let source = root.path().join("source");
    write_fixture_tree(&source);
    let dest = root.path().join("fallback");
    copy_tree_byte_identical(&source, &dest).expect("fallback");
    assert_trees_equal(&source, &dest);
}

#[test]
fn prefers_reflink_or_fallback_and_stays_byte_identical() {
    let root = private_tempdir();
    let source = root.path().join("source");
    write_fixture_tree(&source);
    let dest = root.path().join("copy");
    let mode = copy_tree_prefers_reflink(&source, &dest).expect("copy");
    assert!(
        matches!(mode, CopyMode::Reflink | CopyMode::Fallback),
        "{mode:?}"
    );
    assert_trees_equal(&source, &dest);
}

#[test]
fn existing_destination_is_refused() {
    let root = private_tempdir();
    let source = root.path().join("source");
    write_fixture_tree(&source);
    let dest = root.path().join("dest");
    fs::create_dir(&dest).expect("dest");
    assert_eq!(
        copy_tree_prefers_reflink(&source, &dest)
            .expect_err("exists")
            .reason_code(),
        "IO_FAILED"
    );
}

#[test]
fn ambient_cp_is_never_part_of_the_copy_authority() {
    const CHILD_FLAG: &str = "BULLET_REFLINK_HOSTILE_CP_CHILD";
    if std::env::var_os(CHILD_FLAG).is_some() {
        let source = std::env::var_os("BULLET_REFLINK_SOURCE").expect("source");
        let destination = std::env::var_os("BULLET_REFLINK_DESTINATION").expect("destination");
        copy_tree_prefers_reflink(Path::new(&source), Path::new(&destination)).expect("copy");
        return;
    }

    let root = private_tempdir();
    let source = root.path().join("source");
    write_fixture_tree(&source);
    let destination = root.path().join("copy");
    let hostile_bin = root.path().join("hostile-bin");
    fs::create_dir(&hostile_bin).expect("hostile bin");
    let marker = root.path().join("ambient-cp-ran");
    let cp = hostile_bin.join("cp");
    fs::write(
        &cp,
        format!("#!/bin/sh\ntouch '{}'\nexit 0\n", marker.display()),
    )
    .expect("cp");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&cp, fs::Permissions::from_mode(0o700)).expect("chmod cp");
    }

    let output = Command::new(std::env::current_exe().expect("test binary"))
        .args(["--exact", "ambient_cp_is_never_part_of_the_copy_authority"])
        .env(CHILD_FLAG, "1")
        .env("BULLET_REFLINK_SOURCE", &source)
        .env("BULLET_REFLINK_DESTINATION", &destination)
        .env("PATH", &hostile_bin)
        .output()
        .expect("child test");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!marker.exists(), "ambient cp must not execute");
    assert_trees_equal(&source, &destination);
}

fn write_fixture_tree(root: &Path) {
    fs::create_dir_all(root.join("nested")).expect("dirs");
    fs::write(root.join("alpha.txt"), b"alpha-bytes").expect("alpha");
    fs::write(root.join("nested/beta.txt"), b"beta-bytes").expect("beta");
}

fn assert_trees_equal(left: &Path, right: &Path) {
    let mut left_files = collect_files(left);
    let mut right_files = collect_files(right);
    left_files.sort();
    right_files.sort();
    assert_eq!(left_files, right_files, "relative paths");
    for rel in left_files {
        let left_bytes = fs::read(left.join(&rel)).expect("left");
        let right_bytes = fs::read(right.join(&rel)).expect("right");
        assert_eq!(left_bytes, right_bytes, "{}", rel.display());
    }
}

fn collect_files(root: &Path) -> Vec<std::path::PathBuf> {
    let mut files = Vec::new();
    collect_files_into(root, root, &mut files);
    files
}

fn collect_files_into(root: &Path, dir: &Path, files: &mut Vec<std::path::PathBuf>) {
    for entry in fs::read_dir(dir).expect("read") {
        let entry = entry.expect("entry");
        let path = entry.path();
        if path.is_dir() {
            collect_files_into(root, &path, files);
        } else {
            files.push(path.strip_prefix(root).expect("prefix").to_path_buf());
        }
    }
}

fn private_tempdir() -> tempfile::TempDir {
    let root = tempfile::tempdir().expect("tempdir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("private");
    }
    root
}
