use crate::fsync::private_tempdir;
use crate::generation::{
    GenerationBootstrap, GenerationBoundary, GenerationFaults, GenerationStore,
};
use bullet_git_journal::DurableJournal;
use bullet_git_types::{GitOid, GitOidAlgorithm};
use std::fs;

const ATTEMPT: &str = "attempt_generation_test";
const NONCE: &str = "abababababababababababababababababababababababababababababababab";

struct Trip(GenerationBoundary);

impl GenerationFaults for Trip {
    fn trips(&mut self, boundary: GenerationBoundary) -> bool {
        boundary == self.0
    }
}

fn tree(digit: u8) -> GitOid {
    GitOid::from_hex(GitOidAlgorithm::Sha1, format!("{digit:040x}")).expect("oid")
}

fn store() -> (tempfile::TempDir, GenerationStore) {
    let root = private_tempdir();
    let work = root.path().join("work");
    fs::create_dir(&work).expect("work");
    let bootstrap = GenerationBootstrap::prepare(&work).expect("bootstrap");
    fs::create_dir(bootstrap.repo_dir()).expect("repo");
    fs::write(bootstrap.repo_dir().join("value"), b"prior").expect("prior file");
    let journal = DurableJournal::open(bootstrap.journal_dir()).expect("journal");
    let checkpoint = journal.checkpoint().bind_git_tree(tree(1));
    let store = bootstrap
        .finish(ATTEMPT, NONCE, checkpoint)
        .expect("finish");
    (root, store)
}

#[test]
fn every_pre_switch_failure_reopens_the_prior_generation() {
    for boundary in [
        GenerationBoundary::GenerationFileSync,
        GenerationBoundary::GenerationRename,
        GenerationBoundary::GenerationDirectorySync,
        GenerationBoundary::PointerWrite,
        GenerationBoundary::PointerFileSync,
        GenerationBoundary::PointerRename,
    ] {
        let (_root, mut store) = store();
        let stage = store.stage().expect("stage");
        fs::write(stage.repo_dir().join("value"), b"next").expect("next file");
        let journal = DurableJournal::open(stage.journal_dir()).expect("stage journal");
        let checkpoint = journal.checkpoint().bind_git_tree(tree(2));
        let error = store
            .publish_with(stage, checkpoint, &mut Trip(boundary))
            .expect_err("injected failure");
        assert_eq!(error.reason_code(), "GENERATION_IO_FAILED");
        let reopened = GenerationStore::open(store.work_dir(), ATTEMPT, NONCE).expect("reopen");
        assert_eq!(reopened.generation(), 0, "boundary {boundary:?}");
        assert_eq!(
            fs::read(reopened.repo_dir().join("value")).expect("prior value"),
            b"prior"
        );
    }
}

#[test]
fn post_switch_directory_sync_failure_reopens_the_complete_next_generation() {
    let (_root, mut store) = store();
    let stage = store.stage().expect("stage");
    fs::write(stage.repo_dir().join("value"), b"next").expect("next file");
    let journal = DurableJournal::open(stage.journal_dir()).expect("stage journal");
    let checkpoint = journal.checkpoint().bind_git_tree(tree(2));
    let error = store
        .publish_with(
            stage,
            checkpoint.clone(),
            &mut Trip(GenerationBoundary::PointerDirectorySync),
        )
        .expect_err("outcome unknown");
    assert_eq!(error.reason_code(), "GENERATION_OUTCOME_UNKNOWN");

    let reopened = GenerationStore::open(store.work_dir(), ATTEMPT, NONCE).expect("reopen");
    assert_eq!(reopened.generation(), 1);
    assert_eq!(reopened.checkpoint(), &checkpoint);
    assert_eq!(
        fs::read(reopened.repo_dir().join("value")).expect("next value"),
        b"next"
    );
}

#[test]
fn reopen_rejects_corruption_anywhere_in_the_active_lineage() {
    let (_root, mut store) = store();
    let stage = store.stage().expect("stage");
    let journal = DurableJournal::open(stage.journal_dir()).expect("stage journal");
    let checkpoint = journal.checkpoint().bind_git_tree(tree(2));
    store.publish(stage, checkpoint).expect("publish");
    fs::write(
        store
            .work_dir()
            .join("generations/generation-00000000000000000000/manifest.json"),
        b"{}\n",
    )
    .expect("corrupt prior manifest");

    let error = GenerationStore::open(store.work_dir(), ATTEMPT, NONCE)
        .expect_err("corrupt lineage refused");
    assert_eq!(error.reason_code(), "GENERATION_CORRUPT");
}
