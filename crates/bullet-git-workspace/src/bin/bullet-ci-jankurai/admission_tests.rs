//! Actual file identity, immutable-copy and hostile lookup regressions.
use super::*;
use crate::tool::{admission, execution, record::Record};
use rustix::fs::{fcntl_add_seals, mkfifoat, Mode, SealFlags, CWD};
use std::fs::File;
use std::io::Write;
use std::os::unix::fs::{symlink, FileExt};
use std::time::{Duration, SystemTime};

#[test]
fn hash_mismatch_never_starts() {
    let fixture = Fixture::new("hash-mismatch");
    let mut bytes = fs::read(&fixture.candidate).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    fs::write(&fixture.candidate, bytes).unwrap();
    assert_eq!(fixture.invoke(), 75);
    fixture.no_start();
    assert!(fixture.rows().last().unwrap()["reason"]
        .as_str()
        .unwrap()
        .contains("CANDIDATE_SHA256_MISMATCH"));
}

#[test]
fn wrong_elf_architecture_refused_after_matching_hash() {
    let mut fixture = Fixture::new("elf-profile");
    let mut bytes = fs::read(&fixture.candidate).unwrap();
    bytes[18..20].copy_from_slice(b"\xb7\0");
    fs::write(&fixture.candidate, bytes).unwrap();
    fixture.refresh();
    assert_eq!(fixture.invoke(), 75);
    fixture.no_start();
    assert!(fixture.rows().last().unwrap()["reason"]
        .as_str()
        .unwrap()
        .contains("CANDIDATE_ELF_PROFILE_MISMATCH"));
}

#[test]
fn fifo_without_writer_refused_without_blocking() {
    let fixture = Fixture::new("fifo");
    fs::remove_file(&fixture.candidate).unwrap();
    mkfifoat(CWD, fixture.candidate.as_str(), Mode::from_raw_mode(0o600)).unwrap();
    let start = std::time::Instant::now();
    assert_eq!(fixture.invoke(), 75);
    assert!(start.elapsed() < Duration::from_secs(1));
    fixture.no_start();
}

#[test]
fn symlink_leaf_refused() {
    let fixture = Fixture::new("symlink-leaf");
    fs::remove_file(&fixture.candidate).unwrap();
    symlink("/usr/bin/true", &fixture.candidate).unwrap();
    assert_eq!(fixture.invoke(), 75);
    fixture.no_start();
}

#[test]
fn symlink_ancestor_refused() {
    let fixture = Fixture::new("symlink-parent");
    let alias = fixture.root.join("alias");
    symlink(&fixture.root, &alias).unwrap();
    let mut request = fixture.request();
    request.candidate = alias.join("candidate").to_str().unwrap().into();
    assert_eq!(
        invoke(&request, fixture.profile(), fixture.environment()),
        75
    );
    fixture.no_start();
}

#[test]
fn directory_and_nonexecutable_refused() {
    let fixture = Fixture::new("kind-mode");
    fs::set_permissions(&fixture.candidate, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(fixture.invoke(), 75);
    fixture.no_start();
    fs::remove_file(&fixture.candidate).unwrap();
    fs::create_dir(&fixture.candidate).unwrap();
    let mut request = fixture.request();
    request.record = fixture
        .root
        .join("directory.jsonl")
        .to_str()
        .unwrap()
        .into();
    assert_eq!(
        invoke(&request, fixture.profile(), fixture.environment()),
        75
    );
}

#[test]
fn changed_and_restored_source_during_actual_copy_refused() {
    let fixture = Fixture::new("changed-restored");
    File::open(&fixture.candidate)
        .unwrap()
        .set_modified(SystemTime::UNIX_EPOCH + Duration::from_secs(1))
        .unwrap();
    let original = fs::read(&fixture.candidate).unwrap();
    let mut changed = false;
    let mut record = Record::new(&fixture.record).unwrap();
    let result = admission::admit_observed(
        &fixture.candidate,
        &mut record,
        fixture.profile(),
        |_, _| {
            if !changed {
                changed = true;
                fs::write(&fixture.candidate, b"changed").unwrap();
                fs::write(&fixture.candidate, &original).unwrap();
            }
            Ok(())
        },
    );
    assert!(changed);
    assert_eq!(fs::read(&fixture.candidate).unwrap(), original);
    assert_eq!(result.unwrap_err(), "CANDIDATE_CHANGED_DURING_READ");
    fixture.no_start();
}

#[test]
fn replaced_lookup_after_copy_refused() {
    let fixture = Fixture::new("lookup-replaced");
    let mut record = Record::new(&fixture.record).unwrap();
    let original = fs::read(&fixture.candidate).unwrap();
    let mut changed = false;
    let result = admission::admit_observed(
        &fixture.candidate,
        &mut record,
        fixture.profile(),
        |_, _| {
            if !changed {
                changed = true;
                fs::rename(&fixture.candidate, fixture.root.join("original")).unwrap();
                fs::write(&fixture.candidate, &original).unwrap();
                fs::set_permissions(&fixture.candidate, fs::Permissions::from_mode(0o755)).unwrap();
            }
            Ok(())
        },
    );
    // Rename changes ctime on the opened inode on Linux; either exact check
    // catches the actual drift. Never an unrelated early admission failure.
    let reason = result.unwrap_err();
    assert!(changed);
    assert!(
        ["CANDIDATE_LOOKUP_CHANGED", "CANDIDATE_CHANGED_DURING_READ"].contains(&reason.as_str())
    );
    fixture.no_start();
}

#[test]
fn corrupted_memfd_copy_refused() {
    let fixture = Fixture::new("corrupt-copy");
    let mut record = Record::new(&fixture.record).unwrap();
    let mut corrupted = false;
    let result = admission::admit_observed(
        &fixture.candidate,
        &mut record,
        fixture.profile(),
        |_, sealed| {
            if !corrupted {
                corrupted = true;
                let last = sealed.metadata().unwrap().len() - 1;
                let mut byte = [0_u8];
                sealed.read_exact_at(&mut byte, last).unwrap();
                byte[0] ^= 1;
                sealed.write_all_at(&byte, last).unwrap();
            }
            Ok(())
        },
    );
    assert!(corrupted);
    assert_eq!(result.unwrap_err(), "SEALED_ARTIFACT_DIGEST_MISMATCH");
    fixture.no_start();
}

#[test]
fn replacement_after_admission_executes_sealed_bytes() {
    let fixture = Fixture::new("post-admission");
    let mut record = Record::new(&fixture.record).unwrap();
    let executable = admission::admit(&fixture.candidate, &mut record, fixture.profile()).unwrap();
    fs::rename(&fixture.candidate, fixture.root.join("original-true")).unwrap();
    fs::copy("/usr/bin/false", &fixture.candidate).unwrap();
    let mut native = None;
    assert_eq!(
        execution::run(
            &executable,
            &audit(),
            &mut record,
            &mut native,
            fixture.profile(),
            fixture.environment()
        )
        .unwrap(),
        0
    );
    assert_eq!(native, Some(0));
    assert_eq!(
        fs::read(&fixture.candidate).unwrap(),
        fs::read("/usr/bin/false").unwrap()
    );
}

#[test]
fn seals_refuse_write_resize_and_removal() {
    let fixture = Fixture::new("seals");
    let mut record = Record::new(&fixture.record).unwrap();
    let mut executable =
        admission::admit(&fixture.candidate, &mut record, fixture.profile()).unwrap();
    assert_eq!(
        executable.write(b"X").unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert_eq!(
        executable.set_len(1).unwrap_err().kind(),
        std::io::ErrorKind::PermissionDenied
    );
    assert!(fcntl_add_seals(&executable, SealFlags::empty()).is_err());
    let mut native = None;
    assert_eq!(
        execution::run(
            &executable,
            &audit(),
            &mut record,
            &mut native,
            fixture.profile(),
            fixture.environment()
        )
        .unwrap(),
        0
    );
}
