//! Digest-pinned Git binary: pin refusals, staged-bytes immutability,
//! deadlines, output bounds, and clone/apply under an operator pin.

mod support;

use bullet_git_types::Digest;
use bullet_git_workspace::{
    AgentRepository, FileProtocol, PatchHunk, PinSource, PinnedGit, SafeGit, SYSTEM_GIT_CANDIDATES,
};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};
use support::{clone_workspace, good_auth, init_source, real_repo, ATTEMPT};

/// The system git this test process pins: an explicit absolute path chosen
/// here, with its digest computed at setup (never by the crate).
const SYSTEM_GIT: &str = "/usr/bin/git";

fn system_git() -> (PathBuf, Digest) {
    let path = PathBuf::from(SYSTEM_GIT);
    let bytes = fs::read(&path).expect("read the system git binary");
    (path, Digest::of(&bytes))
}

/// Install the caller-discovered operator pin once per process (idempotent).
fn pin_system_git() -> (PathBuf, Digest) {
    let (path, digest) = system_git();
    let pinned = PinnedGit::new(&path, digest).expect("pin the system git");
    pinned.install_default().expect("install the system pin");
    (path, digest)
}

fn write_executable(path: &Path, body: &str) -> Digest {
    fs::write(path, body).expect("write fake git");
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).expect("chmod fake git");
    Digest::of(body.as_bytes())
}

fn pin_script(path: &Path, body: &str) -> PinnedGit {
    let digest = write_executable(path, body);
    PinnedGit::new(path, digest).expect("pin fake git")
}

/// A `SafeGit` over a fake git script with tight bounds.
fn fake_git(dir: &Path, body: &str, deadline: Duration, stdout: usize, stderr: usize) -> SafeGit {
    let pinned = pin_script(&dir.join("fake-git"), body);
    let mut bounds = pinned.bounds();
    bounds.deadline = deadline;
    bounds.max_stdout_bytes = stdout;
    bounds.max_stderr_bytes = stderr;
    SafeGit::with_binary(&dir.join("runtime"), pinned.with_bounds(bounds)).expect("safe git")
}

fn run_text(git: &SafeGit, verb: &str) -> String {
    git.run(None, FileProtocol::Never, &[verb], &[])
        .expect("fake git runs")
        .text()
}

const LOOSE: Duration = Duration::from_secs(30);
const KIB: usize = 1024;

#[test]
fn explicit_system_pin_is_verified_from_caller_supplied_path_and_digest() {
    let (path, digest) = pin_system_git();
    let pinned = PinnedGit::new(&path, digest).expect("pin verifies");
    assert_eq!(pinned.path(), path.as_path());
    assert_eq!(pinned.digest(), digest);
    assert_eq!(pinned.source(), PinSource::Operator);
    let installed = PinnedGit::process_default().expect("default installed");
    assert_eq!(installed.path(), path.as_path());
    assert_eq!(installed.digest(), digest);
    assert_eq!(installed.source(), PinSource::Operator);
}

#[test]
fn wrong_digest_is_refused() {
    let (path, digest) = system_git();
    let wrong = Digest::of(b"not the git binary");
    assert_ne!(wrong, digest);
    let err = PinnedGit::new(&path, wrong).expect_err("wrong digest refused");
    assert_eq!(err.reason_code(), "GIT_BINARY_DIGEST_MISMATCH");
    assert!(err.to_string().contains(&digest.to_hex()), "{err}");
    assert!(err.to_string().contains(&wrong.to_hex()), "{err}");
    let capability = bullet_git_workspace::CapabilityError::from(err);
    assert_eq!(capability.reason_code(), "GIT_BINARY_DIGEST_MISMATCH");
    assert_eq!(
        capability.git_binary_code(),
        Some("GIT_BINARY_DIGEST_MISMATCH")
    );
}

#[test]
fn symlink_is_refused_even_with_the_right_digest() {
    let (path, digest) = system_git();
    let tmp = tempfile::tempdir().expect("tempdir");
    let link = tmp.path().join("git");
    std::os::unix::fs::symlink(&path, &link).expect("symlink");
    let err = PinnedGit::new(&link, digest).expect_err("symlink refused");
    assert_eq!(err.reason_code(), "GIT_BINARY_SYMLINK");
}

#[test]
fn non_executable_copy_is_refused_even_with_the_right_digest() {
    let (path, digest) = system_git();
    let tmp = tempfile::tempdir().expect("tempdir");
    let copy = tmp.path().join("git");
    fs::copy(&path, &copy).expect("copy git");
    fs::set_permissions(&copy, fs::Permissions::from_mode(0o644)).expect("chmod");
    let err = PinnedGit::new(&copy, digest).expect_err("non-executable refused");
    assert_eq!(err.reason_code(), "GIT_BINARY_NOT_EXECUTABLE");
    // Restoring the execute bit makes the very same bytes admissible.
    fs::set_permissions(&copy, fs::Permissions::from_mode(0o755)).expect("chmod");
    PinnedGit::new(&copy, digest).expect("executable copy pins");
}

#[test]
fn relative_missing_and_directory_paths_are_refused() {
    let (_, digest) = system_git();
    let tmp = tempfile::tempdir().expect("tempdir");
    let err = PinnedGit::new(Path::new("git"), digest).expect_err("relative refused");
    assert_eq!(err.reason_code(), "GIT_BINARY_PATH_NOT_ABSOLUTE");
    let err = PinnedGit::new(&tmp.path().join("absent"), digest).expect_err("missing");
    assert_eq!(err.reason_code(), "GIT_BINARY_UNREADABLE");
    let err = PinnedGit::new(tmp.path(), digest).expect_err("directory refused");
    assert_eq!(err.reason_code(), "GIT_BINARY_NOT_REGULAR");
}

#[test]
fn a_different_default_pin_is_refused_once_one_is_installed() {
    pin_system_git();
    let tmp = tempfile::tempdir().expect("tempdir");
    let other = pin_script(&tmp.path().join("other-git"), "#!/bin/sh\nexit 0\n");
    let err = other.install_default().expect_err("second default refused");
    assert_eq!(err.reason_code(), "GIT_BINARY_ALREADY_PINNED");
    assert_eq!(
        PinnedGit::process_default().expect("default").path(),
        Path::new(SYSTEM_GIT)
    );
}

#[test]
fn in_place_rewrite_after_pinning_still_executes_the_verified_bytes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("fake-git");
    let original = pin_script(&path, "#!/bin/sh\necho ORIGINAL\n");
    let git = SafeGit::with_binary(&tmp.path().join("runtime"), original.clone()).expect("git");
    assert_eq!(run_text(&git, "version"), "ORIGINAL");

    // Same inode, new bytes: the pinned instance keeps running the staged,
    // verified bytes while a fresh construction sees the new digest.
    let replaced = write_executable(&path, "#!/bin/sh\necho REPLACED\n");
    assert_ne!(replaced, original.digest());
    assert_eq!(run_text(&git, "version"), "ORIGINAL");
    let err = PinnedGit::new(&path, original.digest()).expect_err("rewritten file refused");
    assert_eq!(err.reason_code(), "GIT_BINARY_DIGEST_MISMATCH");
    assert!(err.to_string().contains(&replaced.to_hex()), "{err}");
    let fresh = PinnedGit::new(&path, replaced).expect("new digest pins the new bytes");
    let fresh_git = SafeGit::with_binary(&tmp.path().join("runtime2"), fresh).expect("git");
    assert_eq!(run_text(&fresh_git, "version"), "REPLACED");
    assert_eq!(run_text(&git, "version"), "ORIGINAL");
}

#[test]
fn rename_swap_or_deletion_after_pinning_still_executes_the_verified_bytes() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let path = tmp.path().join("fake-git");
    let original = pin_script(&path, "#!/bin/sh\necho ORIGINAL\n");
    let git = SafeGit::with_binary(&tmp.path().join("runtime"), original.clone()).expect("git");

    let swap = tmp.path().join("swap");
    write_executable(&swap, "#!/bin/sh\necho SWAPPED\n");
    fs::rename(&swap, &path).expect("rename over the pinned path");
    assert_eq!(run_text(&git, "version"), "ORIGINAL");
    let err = PinnedGit::new(&path, original.digest()).expect_err("swapped file refused");
    assert_eq!(err.reason_code(), "GIT_BINARY_DIGEST_MISMATCH");

    fs::remove_file(&path).expect("delete the pinned path");
    assert_eq!(run_text(&git, "version"), "ORIGINAL");
    let err = PinnedGit::new(&path, original.digest()).expect_err("deleted file refused");
    assert_eq!(err.reason_code(), "GIT_BINARY_UNREADABLE");
}

#[test]
fn deadline_kills_a_sleeping_fake_git() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let git = fake_git(
        tmp.path(),
        "#!/bin/sh\nexec sleep 30\n",
        Duration::from_millis(300),
        KIB,
        KIB,
    );
    let started = Instant::now();
    let err = git
        .run(None, FileProtocol::Never, &["status"], &[])
        .expect_err("deadline trips");
    let elapsed = started.elapsed();
    assert_eq!(err.reason_code(), "GIT_DEADLINE_EXCEEDED");
    assert_eq!(err.git_binary_code(), Some("GIT_DEADLINE_EXCEEDED"));
    assert!(err.to_string().contains("git status"), "{err}");
    assert!(
        elapsed < Duration::from_secs(10),
        "child was not killed at the deadline: {elapsed:?}"
    );
    // `probe` and `head_state` share the same bounded executor.
    let err = git
        .probe(None, &["status"])
        .expect_err("probe deadline trips");
    assert_eq!(err.reason_code(), "GIT_DEADLINE_EXCEEDED");
}

#[test]
fn stdout_bound_trips_one_byte_over_and_admits_the_exact_cap() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cap = 64 * KIB;
    let over = tmp.path().join("over");
    fs::create_dir_all(&over).expect("dir");
    let chatty = fake_git(
        &over,
        &format!("#!/bin/sh\nexec head -c {} /dev/zero\n", cap + 1),
        LOOSE,
        cap,
        KIB,
    );
    let err = chatty
        .run(None, FileProtocol::Never, &["log"], &[])
        .expect_err("one byte over the stdout cap trips");
    assert_eq!(err.reason_code(), "GIT_OUTPUT_BOUND_EXCEEDED");
    assert!(err.to_string().contains("stdout"), "{err}");

    let exact = tmp.path().join("exact");
    fs::create_dir_all(&exact).expect("dir");
    let bounded = fake_git(
        &exact,
        &format!("#!/bin/sh\nexec head -c {cap} /dev/zero\n"),
        LOOSE,
        cap,
        KIB,
    );
    let out = bounded
        .run(None, FileProtocol::Never, &["log"], &[])
        .expect("exactly the cap is admitted");
    assert_eq!(out.stdout.len(), cap);
}

#[test]
fn unbounded_stdout_is_cut_off_promptly() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let git = fake_git(tmp.path(), "#!/bin/sh\nexec yes\n", LOOSE, 8 * KIB, KIB);
    let started = Instant::now();
    let err = git
        .run(None, FileProtocol::Never, &["log"], &[])
        .expect_err("infinite output trips");
    assert_eq!(err.reason_code(), "GIT_OUTPUT_BOUND_EXCEEDED");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[test]
fn stderr_bound_trips_independently_of_stdout() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let cap = 4 * KIB;
    let git = fake_git(
        tmp.path(),
        &format!("#!/bin/sh\nhead -c {} /dev/zero >&2\nexit 0\n", cap + 1),
        LOOSE,
        64 * KIB,
        cap,
    );
    let err = git
        .run(None, FileProtocol::Never, &["fetch"], &[])
        .expect_err("stderr over the cap trips");
    assert_eq!(err.reason_code(), "GIT_OUTPUT_BOUND_EXCEEDED");
    assert!(err.to_string().contains("stderr"), "{err}");
    assert!(err.to_string().contains("git fetch"), "{err}");
}

#[test]
fn pinned_binary_runs_from_the_staged_descriptor_with_the_isolated_environment() {
    let tmp = tempfile::tempdir().expect("tempdir");
    let git = fake_git(
        tmp.path(),
        "#!/bin/sh\nprintf '%s\\n' \"$0\"\nenv | grep '^GIT_' | sort\n",
        LOOSE,
        64 * KIB,
        KIB,
    );
    let out = run_text(&git, "version");
    let mut lines = out.lines();
    let argv0 = lines.next().expect("argv[0] line");
    assert!(
        argv0.starts_with("/proc/self/fd/"),
        "script must run from the staged descriptor, got {argv0}"
    );
    let git_env: Vec<&str> = lines.collect();
    let expected = [
        "GIT_ASKPASS=",
        "GIT_CONFIG_GLOBAL=/dev/null",
        "GIT_CONFIG_NOSYSTEM=1",
        "GIT_SSH_COMMAND=false",
        "GIT_TERMINAL_PROMPT=0",
    ];
    assert_eq!(
        git_env.len(),
        expected.len(),
        "GIT_* environment: {git_env:?}"
    );
    for (actual, prefix) in git_env.iter().zip(expected) {
        assert!(actual.starts_with(prefix), "{actual} vs {prefix}");
    }
}

#[test]
fn self_pinned_source_is_named_and_process_default_is_a_fixed_candidate() {
    let (path, digest) = system_git();
    let tofu = PinnedGit::self_pinned(&path).expect("self pin");
    assert_eq!(tofu.source(), PinSource::SelfPinned);
    assert_eq!(tofu.digest(), digest);
    assert_ne!(tofu, PinnedGit::new(&path, digest).expect("operator pin"));

    let tmp = tempfile::tempdir().expect("tempdir");
    let git = SafeGit::new(tmp.path()).expect("default safe git");
    let binary = git.binary();
    assert!(binary.path().is_absolute());
    let shown = binary.path().to_string_lossy().into_owned();
    assert!(
        SYSTEM_GIT_CANDIDATES.contains(&shown.as_str()),
        "{shown} is not a fixed candidate"
    );
    let metadata = fs::symlink_metadata(binary.path()).expect("metadata");
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(
        binary.digest(),
        Digest::of(&fs::read(binary.path()).expect("bytes"))
    );
    // Only this file's operator pin can be installed in this process, so an
    // Operator default is exactly the system pin; otherwise it is TOFU.
    match binary.source() {
        PinSource::Operator => assert_eq!(binary.path(), path.as_path()),
        PinSource::SelfPinned => {}
    }
    assert_eq!(binary.bounds().deadline, Duration::from_secs(600));
    assert_eq!(binary.bounds().max_stdout_bytes, 128 * 1_048_576);
    assert_eq!(binary.bounds().max_stderr_bytes, 4 * 1_048_576);
}

#[test]
fn clone_and_apply_run_under_the_explicitly_pinned_system_git() {
    let (path, digest) = pin_system_git();
    let tmp = tempfile::tempdir().expect("tempdir");
    let (src, base) = init_source(tmp.path());
    let workspace = clone_workspace(tmp.path(), &src, &base, ATTEMPT);
    assert_eq!(workspace.git().binary().path(), path.as_path());
    assert_eq!(workspace.git().binary().digest(), digest);
    assert_eq!(workspace.git().binary().source(), PinSource::Operator);
    let head = workspace
        .git()
        .run(
            Some(workspace.repo_dir()),
            FileProtocol::Never,
            &["rev-parse", "HEAD"],
            &[],
        )
        .expect("rev-parse under the pin")
        .text();
    assert_eq!(format!("sha1:{head}"), base);

    let mut repo = real_repo(workspace, ATTEMPT);
    repo.apply_change(
        &good_auth(),
        &[PatchHunk::write(
            "src/pinned.rs",
            b"pub fn pinned() {}\n".to_vec(),
        )],
    )
    .expect("apply under the pin");
    let checkpoint = repo
        .checkpoint(&good_auth())
        .expect("checkpoint under the pin");
    assert!(repo.workspace().repo_dir().join("src/pinned.rs").is_file());
    assert!(checkpoint.through_seq > 0, "apply recorded no journal op");
    assert_eq!(repo.workspace().git().binary().path(), path.as_path());
}
