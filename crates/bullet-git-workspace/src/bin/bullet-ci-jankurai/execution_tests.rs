//! Actual native execution, inherited descriptors and bounded failure paths.
use super::*;
use crate::tool::{
    admission, settle,
    tests::{audit, Fixture},
};
use std::fs;
use std::io::Seek;

#[test]
fn actual_version_and_retained_raw_output() {
    let fixture = Fixture::new("version");
    let expected = Command::new("/usr/bin/true")
        .arg("--version")
        .env_clear()
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    assert!(expected.status.success());
    let end = expected
        .stdout
        .iter()
        .rposition(|b| !b"\r\n".contains(b))
        .unwrap()
        + 1;
    let profile = Profile {
        version: &expected.stdout[..end],
        ..fixture.profile()
    };
    let mut request = fixture.request();
    request.argv = vec!["--version".into()];
    assert_eq!(
        crate::tool::invoke(&request, profile, fixture.environment()),
        0
    );
    assert_eq!(
        fs::read(format!("{}.stdout", fixture.record)).unwrap(),
        expected.stdout
    );
    assert_eq!(fs::read(format!("{}.stderr", fixture.record)).unwrap(), b"");
    assert!(fixture
        .rows()
        .iter()
        .any(|row| row["event"] == "version_output"));
}

#[test]
fn version_mismatch_after_observed_zero_refuses() {
    let fixture = Fixture::new("version-mismatch");
    let mut request = fixture.request();
    request.argv = vec!["--version".into()];
    assert_eq!(
        crate::tool::invoke(&request, fixture.profile(), fixture.environment()),
        75
    );
    let rows = fixture.rows();
    assert_eq!(rows.last().unwrap()["native_status"], 0);
    assert!(rows.last().unwrap()["reason"]
        .as_str()
        .unwrap()
        .contains("VERSION_OUTPUT_MISMATCH"));
}

#[test]
fn dynamic_loader_environment_refuses_before_start() {
    let fixture = Fixture::new("loader-env");
    for (index, key) in [
        "LD_PRELOAD",
        "LD_AUDIT",
        "GLIBC_TUNABLES",
        "GCONV_PATH",
        "LOCPATH",
    ]
    .iter()
    .enumerate()
    {
        let mut environment = fixture.environment();
        environment.insert((*key).into(), "".into());
        let mut request = fixture.request();
        request.record = fixture
            .root
            .join(format!("loader-{index}.jsonl"))
            .to_str()
            .unwrap()
            .into();
        assert_eq!(
            crate::tool::invoke(&request, fixture.profile(), environment),
            75
        );
        let rows = fs::read_to_string(&request.record).unwrap();
        assert!(rows.contains("DYNAMIC_LOADER_ENVIRONMENT_REFUSED"));
        assert!(!rows.contains("\"event\":\"started\""));
    }
}

#[test]
fn actually_inheritable_foreign_fd_refuses_with_cloexec_control() {
    let fixture = Fixture::new("inherited-fd");
    let foreign = File::open("/dev/null").unwrap();
    let inheritable = rustix::io::dup(&foreign).unwrap();
    assert_eq!(fixture.invoke(), 75);
    fixture.no_start();
    assert!(fixture.rows().last().unwrap()["reason"]
        .as_str()
        .unwrap()
        .contains("INHERITED_DESCRIPTOR_REFUSED"));
    drop(inheritable);
    let mut request = fixture.request();
    request.record = fixture.root.join("cloexec.jsonl").to_str().unwrap().into();
    assert_eq!(
        crate::tool::invoke(&request, fixture.profile(), fixture.environment()),
        0
    );
    assert!(foreign.metadata().is_ok());
}

#[test]
fn descriptor_flags_malformed_duplicate_missing_refuse() {
    for text in [
        "",
        "flags: 09",
        "flags: -1",
        "flags: 02000000\nflags: 00",
        "flags: 0x1",
        "flags: 88888888888888888888888",
    ] {
        assert!(descriptors::flags(text).is_err());
    }
    assert_eq!(
        descriptors::flags("pos:\t0\nflags:\t02100000\n").unwrap(),
        0o2100000
    );
}

#[test]
fn oversized_actual_fdinfo_file_refuses_before_unbounded_read() {
    let fixture = Fixture::new("fdinfo-limit");
    let path = fixture.root.join("large-fdinfo");
    fs::write(&path, vec![b'7'; 70_000]).unwrap();
    let mut input = File::open(path).unwrap();
    assert_eq!(
        descriptors::read_info(&mut input).unwrap_err(),
        "DESCRIPTOR_INFO_LIMIT"
    );
    assert_eq!(input.stream_position().unwrap(), 65_537);
}

#[test]
fn record_failure_keeps_actual_native_failure() {
    let mut fixture = Fixture::new("record-native-failure");
    fs::copy("/usr/bin/false", &fixture.candidate).unwrap();
    fixture.refresh();
    let mut record = Record::new(&fixture.record).unwrap();
    let executable = admission::admit(&fixture.candidate, &mut record, fixture.profile()).unwrap();
    let mut native = None;
    assert_eq!(
        run(
            &executable,
            &audit(),
            &mut record,
            &mut native,
            fixture.profile(),
            fixture.environment()
        )
        .unwrap(),
        1
    );
    assert_eq!(native, Some(1));
    record.file = fs::OpenOptions::new()
        .write(true)
        .open("/dev/full")
        .unwrap();
    let failure = record
        .append("complete", json!({"exit_status": 1}))
        .map(|()| 1);
    assert!(failure.is_err());
    assert_eq!(settle(failure, native, &mut record), 1);
}

fn child_fixture(name: &str) -> (Fixture, Vec<String>, Environment) {
    let mut fixture = Fixture::new(name);
    fs::copy(std::env::current_exe().unwrap(), &fixture.candidate).unwrap();
    fixture.refresh();
    let mut environment = fixture.environment();
    environment.insert("BULLET_CI_FIXTURE".into(), name.into());
    environment.insert(
        "BULLET_CI_MARKER".into(),
        fixture.root.join("child-start.json").into_os_string(),
    );
    let argv = [
        "--exact",
        "tool::execution::tests::fixture_child",
        "--nocapture",
    ]
    .map(str::to_owned)
    .to_vec();
    (fixture, argv, environment)
}

#[test]
fn actual_version_timeout_retains_start_and_returns_without_unbounded_wait() {
    let (fixture, argv, environment) = child_fixture("hang");
    let mut record = Record::new(&fixture.record).unwrap();
    let executable = admission::admit(&fixture.candidate, &mut record, fixture.profile()).unwrap();
    let mut native = None;
    let start = Instant::now();
    let result = run_inner(
        &executable,
        &argv,
        &mut record,
        &mut native,
        fixture.profile(),
        environment,
        Some(Duration::from_millis(150)),
    );
    assert_eq!(result.unwrap_err(), "VERSION_TIMEOUT");
    assert!(start.elapsed() < Duration::from_secs(6));
    assert!(fixture.root.join("child-start.json").exists());
    assert!(fixture.rows().iter().any(|row| row["event"] == "started"));
}

#[test]
fn actual_oversized_version_is_bounded_and_preserved() {
    let (fixture, argv, environment) = child_fixture("overflow");
    let mut record = Record::new(&fixture.record).unwrap();
    let executable = admission::admit(&fixture.candidate, &mut record, fixture.profile()).unwrap();
    let mut native = None;
    let result = run_inner(
        &executable,
        &argv,
        &mut record,
        &mut native,
        fixture.profile(),
        environment,
        Some(Duration::from_secs(3)),
    );
    assert_eq!(result.unwrap_err(), "VERSION_OUTPUT_LIMIT");
    assert!(fixture.root.join("child-start.json").exists());
    assert_eq!(
        fs::metadata(format!("{}.stdout", fixture.record))
            .unwrap()
            .len(),
        (VERSION_BYTES + 1) as u64
    );
}

#[test]
fn actual_child_receives_exact_argv_update_opt_out_and_only_admitted_fd() {
    let (fixture, argv, mut environment) = child_fixture("inspect");
    environment.insert("JANKURAI_NO_UPDATE_CHECK".into(), "0".into());
    let mut record = Record::new(&fixture.record).unwrap();
    let executable = admission::admit(&fixture.candidate, &mut record, fixture.profile()).unwrap();
    let mut native = None;
    assert_eq!(
        run(
            &executable,
            &argv,
            &mut record,
            &mut native,
            fixture.profile(),
            environment
        )
        .unwrap(),
        23
    );
    let child: serde_json::Value =
        serde_json::from_slice(&fs::read(fixture.root.join("child-start.json")).unwrap()).unwrap();
    assert_eq!(child["update_check"], "1");
    assert_eq!(
        child["argv"],
        json!(([vec!["jankurai".to_owned()], argv].concat()))
    );
    let rows = fixture.rows();
    let intent = rows
        .iter()
        .find(|row| row["event"] == "launch_intent")
        .unwrap();
    assert_eq!(
        child["inheritable"],
        json!([intent["passed_executable_fd"]])
    );
    assert_eq!(native, Some(23));
}

#[test]
fn fixture_child() {
    // This is a real separately executed copy of the test ELF. Normal suite
    // enumeration never activates it; the parent must observe its own marker.
    let Ok(behavior) = std::env::var("BULLET_CI_FIXTURE") else {
        assert!(std::env::var_os("BULLET_CI_MARKER").is_none());
        return;
    };
    let marker = std::env::var_os("BULLET_CI_MARKER").expect("child marker path");
    let mut inherited = Vec::new();
    let entries = fs::read_dir("/proc/self/fdinfo").unwrap();
    for entry in entries {
        let entry = entry.unwrap();
        let fd: i32 = entry.file_name().to_str().unwrap().parse().unwrap();
        let flags = descriptors::flags(&fs::read_to_string(entry.path()).unwrap()).unwrap();
        if fd >= 3 && flags & u64::from(OFlags::CLOEXEC.bits()) == 0 {
            inherited.push(fd);
        }
    }
    fs::write(marker, serde_json::to_vec(&json!({"argv": std::env::args().collect::<Vec<_>>(),
        "update_check": std::env::var("JANKURAI_NO_UPDATE_CHECK").unwrap(), "inheritable": inherited})).unwrap()).unwrap();
    match behavior.as_str() {
        "hang" => thread::sleep(Duration::from_secs(60)),
        "overflow" => {
            let _ = std::io::stdout().write_all(&vec![b'X'; VERSION_BYTES * 4]);
        }
        "inspect" => std::process::exit(23),
        _ => panic!("unknown fixture behavior"),
    }
}
