use std::fs;

use bullet_git_journal::{DurableJournal, JournalMutation};
use bullet_git_types::Digest;

fn object(bytes: &[u8]) -> Digest {
    Digest::of(bytes)
}

fn batch_files(directory: &std::path::Path) -> Vec<std::path::PathBuf> {
    let mut files = fs::read_dir(directory)
        .expect("read journal")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    files.sort();
    files
}

#[test]
fn batch_is_one_immutable_file_and_recovers_exactly() {
    let temp = tempfile::tempdir().expect("tempdir");
    let directory = temp.path().join("journal");
    let mut journal = DurableJournal::open(&directory).expect("open");
    journal
        .record_batch(&[
            JournalMutation::write("src/a.rs", None, object(b"one")),
            JournalMutation::delete("src/b.rs", object(b"before")),
        ])
        .expect("record batch");
    let expected_ops = journal.ops().to_vec();
    let expected_checkpoint = journal.checkpoint();
    assert_eq!(batch_files(&directory).len(), 1);
    drop(journal);

    let recovered = DurableJournal::open(&directory).expect("recover");
    assert_eq!(recovered.ops(), expected_ops);
    assert_eq!(recovered.checkpoint(), expected_checkpoint);
}

#[test]
fn corruption_and_sequence_gaps_fail_closed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let directory = temp.path().join("corrupt");
    let mut journal = DurableJournal::open(&directory).expect("open");
    journal
        .record_batch(&[JournalMutation::write("src/a.rs", None, object(b"one"))])
        .expect("first");
    journal
        .record_batch(&[JournalMutation::write("src/b.rs", None, object(b"two"))])
        .expect("second");
    let files = batch_files(&directory);
    fs::remove_file(&files[0]).expect("create gap");
    let error = DurableJournal::open(&directory).expect_err("gap refused");
    assert_eq!(error.reason_code(), "CORRUPT_JOURNAL");

    let directory = temp.path().join("checksum");
    let mut journal = DurableJournal::open(&directory).expect("open");
    journal
        .record_batch(&[JournalMutation::write("src/a.rs", None, object(b"one"))])
        .expect("record");
    let file = batch_files(&directory).pop().expect("batch");
    let original = fs::read_to_string(&file).expect("read batch");
    fs::write(&file, original.replace("src/a.rs", "src/z.rs")).expect("tamper");
    let error = DurableJournal::open(&directory).expect_err("checksum refused");
    assert_eq!(error.reason_code(), "CORRUPT_JOURNAL");
}

#[test]
fn unknown_batch_fields_fail_closed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let directory = temp.path().join("unknown-field");
    let mut journal = DurableJournal::open(&directory).expect("open");
    journal
        .record_batch(&[JournalMutation::write("src/a.rs", None, object(b"one"))])
        .expect("record");
    let file = batch_files(&directory).pop().expect("batch");
    let original = fs::read_to_string(&file).expect("read batch");
    fs::write(&file, original.replacen('{', "{\"unknown\":true,", 1)).expect("add unknown field");
    let error = DurableJournal::open(&directory).expect_err("unknown field refused");
    assert_eq!(error.reason_code(), "CORRUPT_JOURNAL");

    let directory = temp.path().join("unknown-op-field");
    let mut journal = DurableJournal::open(&directory).expect("open");
    journal
        .record_batch(&[JournalMutation::write("src/a.rs", None, object(b"one"))])
        .expect("record");
    let file = batch_files(&directory).pop().expect("batch");
    let original = fs::read_to_string(&file).expect("read batch");
    fs::write(
        &file,
        original.replacen("\"seq\":1", "\"unknown\":true,\"seq\":1", 1),
    )
    .expect("add nested unknown field");
    let error = DurableJournal::open(&directory).expect_err("nested unknown field refused");
    assert_eq!(error.reason_code(), "CORRUPT_JOURNAL");
}

#[test]
fn temp_orphans_are_ignored_but_unknown_entries_are_refused() {
    let temp = tempfile::tempdir().expect("tempdir");
    let directory = temp.path().join("journal");
    fs::create_dir_all(&directory).expect("journal dir");
    let orphan = format!(".batch-{:020}-{:020}-42-{}-0.tmp", 1, 1, "0".repeat(64));
    fs::write(directory.join(orphan), b"partial").expect("orphan");
    let mut journal = DurableJournal::open(&directory).expect("orphan ignored");
    journal
        .record_batch(&[JournalMutation::write("src/a.rs", None, object(b"one"))])
        .expect("append after orphan");
    drop(journal);
    fs::write(directory.join("unexpected"), b"data").expect("unknown entry");
    let error = DurableJournal::open(&directory).expect_err("unknown refused");
    assert_eq!(error.reason_code(), "CORRUPT_JOURNAL");
}

#[cfg(unix)]
#[test]
fn symlinked_journal_directory_is_refused() {
    let temp = tempfile::tempdir().expect("tempdir");
    let target = temp.path().join("target");
    fs::create_dir_all(&target).expect("target");
    let linked = temp.path().join("linked");
    std::os::unix::fs::symlink(&target, &linked).expect("symlink");
    let error = DurableJournal::open(&linked).expect_err("symlink refused");
    assert_eq!(error.reason_code(), "CORRUPT_JOURNAL");
}
