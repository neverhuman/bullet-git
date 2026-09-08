//! ImmutableCas unit proofs.

use super::*;
use std::sync::{Arc, Barrier};

struct FailAt(Boundary);

impl Faults for FailAt {
    fn trips(&mut self, boundary: Boundary) -> bool {
        self.0 == boundary
    }
}

#[test]
fn prepublication_failures_reopen_as_absent() {
    for boundary in [
        Boundary::Allocate,
        Boundary::Write,
        Boundary::FileSync,
        Boundary::Publish,
    ] {
        let root = private_tempdir();
        let cas = ImmutableCas::open(root.path()).expect("open");
        let bytes = b"boundary payload";
        let digest = cas_digest(bytes);
        let error = cas
            .put_inner(bytes, &mut FailAt(boundary))
            .expect_err("injected failure");
        assert_eq!(error.reason_code(), "CAS_IO_FAILED");
        drop(cas);

        let reopened = ImmutableCas::open(root.path()).expect("reopen");
        assert_eq!(reopened.get(&digest).expect("read"), None, "{boundary:?}");
    }
}

#[test]
fn directory_sync_failure_is_unknown_until_exact_reopen() {
    let root = private_tempdir();
    let cas = ImmutableCas::open(root.path()).expect("open");
    let bytes = b"published payload";
    let digest = cas_digest(bytes);
    let error = cas
        .put_inner(bytes, &mut FailAt(Boundary::DirectorySync))
        .expect_err("directory sync failure");
    assert_eq!(error.reason_code(), "CAS_OUTCOME_UNKNOWN");
    assert_eq!(
        cas.put(bytes).expect_err("poisoned").reason_code(),
        "CAS_OUTCOME_UNKNOWN"
    );
    drop(cas);

    let reopened = ImmutableCas::open(root.path()).expect("reopen exact object");
    assert_eq!(reopened.get(&digest).expect("read"), Some(bytes.to_vec()));
}

#[test]
fn unknown_is_visible_before_a_waiter_can_mutate() {
    let root = private_tempdir();
    let cas = Arc::new(ImmutableCas::open(root.path()).expect("open"));
    let entered = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let worker = Arc::clone(&cas);
    let worker_entered = Arc::clone(&entered);
    let worker_release = Arc::clone(&release);
    let first = std::thread::spawn(move || {
        worker.put_inner(
            b"published first",
            &mut PauseAtSync(worker_entered, worker_release),
        )
    });
    entered.wait();
    let waiter = Arc::clone(&cas);
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let second = std::thread::spawn(move || {
        ready_tx.send(()).expect("signal ready");
        waiter.put(b"must remain absent")
    });
    ready_rx.recv().expect("waiter ready");
    release.wait();
    for outcome in [first.join().expect("first"), second.join().expect("second")] {
        assert_eq!(
            outcome.expect_err("refused").reason_code(),
            "CAS_OUTCOME_UNKNOWN"
        );
    }
    drop(cas);

    let reopened = ImmutableCas::open(root.path()).expect("reopen");
    assert_eq!(
        reopened.get(&cas_digest(b"published first")).expect("read"),
        Some(b"published first".to_vec())
    );
    assert_eq!(
        reopened
            .get(&cas_digest(b"must remain absent"))
            .expect("read"),
        None
    );
}

struct PauseAtSync(Arc<Barrier>, Arc<Barrier>);

impl Faults for PauseAtSync {
    fn trips(&mut self, boundary: Boundary) -> bool {
        if boundary != Boundary::DirectorySync {
            return false;
        }
        self.0.wait();
        self.1.wait();
        true
    }
}
