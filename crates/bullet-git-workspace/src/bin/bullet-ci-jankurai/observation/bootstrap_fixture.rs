//! Explicitly synthetic Cargo/tool rows over real fixture files, never build proof.
use super::super::{bootstrap, bootstrap_inputs};
use super::{Fixture, json_bytes, write};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

pub(super) fn sources(root: &str) {
    for path in bootstrap_inputs::SOURCE_ROOTS {
        if path.ends_with("/src") || path == "contracts/generated/rust" {
            write(
                &format!("{root}/{path}/fixture.rs"),
                b"// fixture source only\n",
            );
        } else {
            write(&format!("{root}/{path}"), b"# fixture source only\n");
        }
    }
    write(
        &format!("{root}/crates/bullet-git-workspace/src/bin/bullet-ci-jankurai/main.rs"),
        b"// fixture, not compiled\n",
    );
}

pub(super) fn attach(f: &Fixture) {
    let directory = format!("{}/target/jankurai/bootstrap/run.ABCD1234", f.root);
    fs::create_dir_all(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let sysroot = f
        .directory
        .path()
        .join("fixture-toolchain")
        .to_str()
        .unwrap()
        .to_owned();
    let mut tools = vec![];
    for name in ["cargo", "rustc"] {
        let path = format!("{sysroot}/bin/{name}");
        let bytes = format!("component fixture {name}; not executed\n");
        write(&path, bytes.as_bytes());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        tools.extend(bootstrap_inputs::checksum_line(&path, bytes.as_bytes()));
    }
    let binary = b"\x7fELF\x02component fixture, not an executed compiler output\n";
    let executable = format!("{directory}/target/debug/bullet-ci-jankurai");
    write(&executable, binary);
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o700)).unwrap();
    let source = bootstrap_inputs::current(&f.root).unwrap().0;
    let argv = [
        format!("{sysroot}/bin/cargo"),
        "build".into(),
        "--frozen".into(),
        "--manifest-path".into(),
        format!("{}/Cargo.toml", f.root),
        "--package".into(),
        "bullet-git-workspace".into(),
        "--bin".into(),
        "bullet-ci-jankurai".into(),
        "--message-format=json".into(),
        "--target-dir".into(),
        format!("{directory}/target"),
        "--jobs".into(),
        "2".into(),
    ];
    let mut cargo = json_bytes(
        &json!({"reason":"compiler-artifact","target":{"name":"bullet-ci-jankurai",
        "src_path":format!("{}/crates/bullet-git-workspace/src/bin/bullet-ci-jankurai/main.rs",f.root),"kind":["bin"]},
        "profile":{"test":false},"fresh":false,"executable":executable}),
    );
    cargo.extend(json_bytes(
        &json!({"reason":"build-finished","success":true}),
    ));
    let mut reports: BTreeMap<String, Vec<u8>> = bootstrap::REPORTS
        .iter()
        .map(|name| ((*name).into(), vec![]))
        .collect();
    reports.insert("invocation.json".into(), f.read("invocation.json"));
    reports.insert("source.before.sha256z".into(), source.clone());
    reports.insert("source.after.sha256z".into(), source);
    reports.insert("tools.sha256".into(), tools);
    reports.insert("sysroot.stdout".into(), format!("{sysroot}\n").into_bytes());
    for name in ["cargo", "rustc"] {
        reports.insert(
            format!("{name}.version"),
            format!("{name} 1.97.1 (synthetic fixture)\n").into_bytes(),
        );
    }
    reports.insert(
        "cargo.argv".into(),
        argv.iter().flat_map(|arg| arg.bytes().chain([0])).collect(),
    );
    reports.insert(
        "cargo.environment.json".into(),
        json_bytes(
            &json!({"HOME":"/fixture-home","CARGO_HOME":"/fixture-cargo",
        "PATH":format!("{sysroot}/bin:/usr/bin:/bin"),"RUSTC":format!("{sysroot}/bin/rustc"),
        "CARGO_NET_OFFLINE":"true","CARGO_INCREMENTAL":"0","LANG":"C","LC_ALL":"C","TZ":"UTC0"}),
        ),
    );
    reports.insert("cargo.stdout".into(), cargo);
    reports.insert("cargo.exit".into(), b"0\n".to_vec());
    reports.insert("bootstrap.exit".into(), b"0\n".to_vec());
    reports.insert(
        "artifact.json".into(),
        json_bytes(&json!({"schema":"bullet.audit-bootstrap.v1","run":f.run,
        "purpose":"audit","executable":executable,"sha256":hex::encode(Sha256::digest(binary)),
        "evidence_class":"local_diagnostic","continuous_custody":false})),
    );
    let checksums: Vec<u8> = bootstrap::REPORTS
        .iter()
        .take(18)
        .flat_map(|name| bootstrap_inputs::checksum_line(name, &reports[*name]))
        .collect();
    reports.insert("subjects.sha256".into(), checksums);
    for (name, bytes) in reports {
        write(&format!("{directory}/{name}"), &bytes);
    }
    f.stage("bootstrap", &["jankurai_bootstrap_prepare", &f.run], 0);
}

pub(super) fn validation(f: &Fixture, name: &str) {
    let binary = format!(
        "{}/target/jankurai/bootstrap/run.ABCD1234/target/debug/bullet-ci-jankurai",
        f.root
    );
    let report = if name == "ratchet" {
        format!("{}/ratchet.json", f.run)
    } else {
        format!("{}/.jankurai/repo-score.json", f.root)
    };
    let mut args = vec![
        binary,
        "report".into(),
        "--root".into(),
        f.root.clone(),
        "--runtime".into(),
        f.directory
            .path()
            .join(format!("report-runtime-{name}"))
            .to_str()
            .unwrap()
            .into(),
        "--report".into(),
        report,
    ];
    if name == "ratchet" {
        args.extend([
            "--baseline".into(),
            format!("{}/target/jankurai/accepted-baseline.json", f.root),
        ]);
    }
    f.put(
        &format!("{name}.validation.argv"),
        &args
            .iter()
            .flat_map(|s| s.bytes().chain([0]))
            .collect::<Vec<_>>(),
    );
}

pub(super) fn directory(f: &Fixture) -> String {
    Path::new(&f.root)
        .join("target/jankurai/bootstrap/run.ABCD1234")
        .to_str()
        .unwrap()
        .into()
}

pub(super) fn refresh_checksums(f: &Fixture) {
    let directory = directory(f);
    let checksums: Vec<u8> = bootstrap::REPORTS
        .iter()
        .take(18)
        .flat_map(|name| {
            bootstrap_inputs::checksum_line(name, &fs::read(format!("{directory}/{name}")).unwrap())
        })
        .collect();
    write(&format!("{directory}/subjects.sha256"), &checksums);
}
