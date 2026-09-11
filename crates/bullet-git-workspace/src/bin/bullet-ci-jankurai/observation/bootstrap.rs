//! The compiler receipt is checked against retained output and current inputs.
//! Cache/build intermediates are excluded explicitly; they are not proof inputs.
use super::super::{artifacts, io, paths, report_policy, Result};
use super::{bootstrap_inputs, common::require, inventory::Inventory};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;

pub(super) const REPORTS: [&str; 20] = [
    "invocation.json",
    "source.before.sha256z",
    "source.after.sha256z",
    "tools.sha256",
    "sysroot.stdout",
    "sysroot.stderr",
    "cargo.version",
    "cargo.version.stderr",
    "rustc.version",
    "rustc.version.stderr",
    "cargo.argv",
    "cargo.environment.json",
    "cargo.stdout",
    "cargo.stderr",
    "cargo.exit",
    "artifact.json",
    "tools.readback.stdout",
    "tools.readback.stderr",
    "subjects.sha256",
    "bootstrap.exit",
];
const BINARY: &str = "target/debug/bullet-ci-jankurai";

pub(super) fn collect(inventory: &mut Inventory, root: &str, run: &str) -> Result<()> {
    let name = run.rsplit('/').next().ok_or("BOOTSTRAP_RUN_INVALID")?;
    let directory = format!("{root}/target/jankurai/bootstrap/{name}");
    let allowed: BTreeSet<_> = REPORTS.into_iter().chain(["target"]).collect();
    let (descriptor, _, _) = paths::open_parent(&format!("{directory}/.lookup"))?;
    let metadata = descriptor.metadata().map_err(io)?;
    require(
        metadata.mode() & 0o7777 == 0o700 && metadata.uid() == rustix::process::getuid().as_raw(),
        "BOOTSTRAP_DIRECTORY_OWNER_INVALID",
    )?;
    let mut count = 0;
    for child in std::fs::read_dir(format!("/proc/self/fd/{}", descriptor.as_raw_fd()))
        .map_err(io)?
        .take(allowed.len() + 1)
    {
        count += 1;
        if count > allowed.len() {
            inventory.issues.push("BOOTSTRAP_ENTRY_LIMIT".into());
            inventory
                .omissions
                .push("build/unexamined-extra-entries".into());
            break;
        }
        let child = child.map_err(io)?;
        let name = child
            .file_name()
            .into_string()
            .map_err(|_| "BOOTSTRAP_NON_UTF8_ENTRY")?;
        if !allowed.contains(name.as_str()) {
            inventory
                .issues
                .push(format!("BOOTSTRAP_EXTRA_ENTRY:{name}"));
            inventory.omissions.push(format!("build/{name}"));
        }
        if name == "target" {
            require(
                child.file_type().map_err(io)?.is_dir(),
                "BOOTSTRAP_TARGET_NOT_DIRECTORY",
            )?;
        }
    }
    for name in REPORTS.into_iter().chain([BINARY]) {
        let artifact = match artifacts::read(&format!("{directory}/{name}")) {
            Ok(artifact) => artifact,
            Err(error) => {
                inventory
                    .issues
                    .push(format!("BOOTSTRAP_ARTIFACT_UNREADABLE:{name}:{error}"));
                inventory.omissions.push(format!("build/{name}"));
                continue;
            }
        };
        require(
            name == BINARY || artifact.bytes.len() <= 32 * 1024 * 1024,
            "BOOTSTRAP_REPORT_BYTE_LIMIT",
        )?;
        let total: usize = inventory.data.values().map(|a| a.bytes.len()).sum();
        require(
            total + artifact.bytes.len() <= 256 * 1024 * 1024,
            "INVENTORY_BYTE_LIMIT",
        )?;
        require(
            inventory
                .data
                .insert(format!("build/{name}"), artifact)
                .is_none(),
            "BOOTSTRAP_DUPLICATE_ARTIFACT",
        )?;
    }
    Ok(())
}

pub(super) fn validate(
    inventory: &Inventory,
    root: &str,
    run: &str,
) -> Result<Vec<artifacts::Artifact>> {
    let get = |name: &str| inventory.get(&format!("build/{name}"));
    inventory.argv(
        "bootstrap",
        &["jankurai_bootstrap_prepare".into(), run.into()],
    )?;
    require(
        inventory.exit("bootstrap.exit")? == 0
            && inventory.exit("build/bootstrap.exit")? == 0
            && inventory.exit("build/cargo.exit")? == 0,
        "BOOTSTRAP_NOT_PASSING",
    )?;
    require(
        get("invocation.json")? == inventory.get("invocation.json")?,
        "BOOTSTRAP_FOREIGN_INVOCATION",
    )?;
    let (sources, mut inputs) = bootstrap_inputs::current(root)?;
    require(
        get("source.before.sha256z")? == get("source.after.sha256z")?
            && get("source.before.sha256z")? == sources,
        "BOOTSTRAP_SOURCE_DRIFT",
    )?;
    let mut checksums = vec![];
    for name in REPORTS.into_iter().take(18) {
        checksums.extend(bootstrap_inputs::checksum_line(name, get(name)?));
    }
    require(
        get("subjects.sha256")? == checksums,
        "BOOTSTRAP_SUBJECT_INVENTORY_MISMATCH",
    )?;
    let directory = format!(
        "{root}/target/jankurai/bootstrap/{}",
        run.rsplit('/').next().ok_or("BOOTSTRAP_RUN_INVALID")?
    );
    let executable = format!("{directory}/{BINARY}");
    let artifact = report_policy::decode(get("artifact.json")?)?;
    require(
        artifact
            == json!({"schema":"bullet.audit-bootstrap.v1","run":run,"purpose":"audit",
        "executable":executable,"sha256":hex::encode(Sha256::digest(get(BINARY)?)),
        "evidence_class":"local_diagnostic","continuous_custody":false}),
        "BOOTSTRAP_BINARY_SUBJECT_MISMATCH",
    )?;
    require(
        get(BINARY)?.starts_with(b"\x7fELF\x02"),
        "BOOTSTRAP_BINARY_NOT_ELF64",
    )?;
    let binary = &inventory.data[&format!("build/{BINARY}")].subject["identity"];
    require(
        binary["mode"]
            .as_u64()
            .is_some_and(|mode| mode & 0o111 != 0 && mode & 0o022 == 0)
            && binary["uid"].as_u64() == Some(u64::from(rustix::process::getuid().as_raw())),
        "BOOTSTRAP_BINARY_PERMISSIONS_INVALID",
    )?;
    cargo(get("cargo.stdout")?, root, &executable)?;
    inputs.extend(tools(inventory, root, &directory)?);
    Ok(inputs)
}

fn cargo(bytes: &[u8], root: &str, executable: &str) -> Result<()> {
    let (mut selected, mut finished) = (0, 0);
    for line in bytes.split(|b| *b == b'\n').filter(|line| !line.is_empty()) {
        let value = report_policy::decode(line)?;
        if value["reason"] == "compiler-artifact" && value["target"]["name"] == "bullet-ci-jankurai"
        {
            selected += 1;
            require(
                value["target"]["src_path"]
                    == format!(
                        "{root}/crates/bullet-git-workspace/src/bin/bullet-ci-jankurai/main.rs"
                    )
                    && value["target"]["kind"] == json!(["bin"])
                    && value["profile"]["test"] == false
                    && value["fresh"] == false
                    && value["executable"] == executable,
                "BOOTSTRAP_CARGO_ARTIFACT_MISMATCH",
            )?;
        }
        if value["reason"] == "build-finished" {
            finished += 1;
            require(
                value == json!({"reason":"build-finished","success":true}),
                "BOOTSTRAP_CARGO_FAILED",
            )?;
        }
    }
    require(
        selected == 1 && finished == 1,
        "BOOTSTRAP_CARGO_SELECTION_INCOMPLETE",
    )
}

fn tools(inventory: &Inventory, root: &str, directory: &str) -> Result<Vec<artifacts::Artifact>> {
    let get = |name: &str| inventory.get(&format!("build/{name}"));
    let sysroot = std::str::from_utf8(get("sysroot.stdout")?)
        .map_err(io)?
        .strip_suffix('\n')
        .ok_or("BOOTSTRAP_SYSROOT_NEWLINE_REQUIRED")?;
    paths::absolute_parts(sysroot)?;
    let mut hashes = vec![];
    let mut inputs = vec![];
    for name in ["cargo", "rustc"] {
        let tool = artifacts::read(&format!("{sysroot}/bin/{name}"))?;
        hashes.extend(bootstrap_inputs::checksum_line(
            &format!("{sysroot}/bin/{name}"),
            &tool.bytes,
        ));
        require(
            get(&format!("{name}.version"))?.starts_with(format!("{name} 1.97.1 ").as_bytes()),
            "BOOTSTRAP_TOOL_VERSION_MISMATCH",
        )?;
        tool.recheck()?;
        inputs.push(tool);
    }
    require(get("tools.sha256")? == hashes, "BOOTSTRAP_TOOL_DRIFT")?;
    let argv = [
        format!("{sysroot}/bin/cargo"),
        "build".into(),
        "--frozen".into(),
        "--manifest-path".into(),
        format!("{root}/Cargo.toml"),
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
    let expected: Vec<u8> = argv.iter().flat_map(|arg| arg.bytes().chain([0])).collect();
    require(
        get("cargo.argv")? == expected,
        "BOOTSTRAP_CARGO_ARGV_MISMATCH",
    )?;
    let environment: Value = report_policy::decode(get("cargo.environment.json")?)?;
    for key in ["HOME", "CARGO_HOME"] {
        paths::absolute_parts(
            environment[key]
                .as_str()
                .ok_or("BOOTSTRAP_ENVIRONMENT_INVALID")?,
        )?;
    }
    require(
        environment
            == json!({"HOME":environment["HOME"],"CARGO_HOME":environment["CARGO_HOME"],
        "PATH":format!("{sysroot}/bin:/usr/bin:/bin"),"RUSTC":format!("{sysroot}/bin/rustc"),
        "CARGO_NET_OFFLINE":"true","CARGO_INCREMENTAL":"0","LANG":"C","LC_ALL":"C","TZ":"UTC0"}),
        "BOOTSTRAP_ENVIRONMENT_MISMATCH",
    )?;
    Ok(inputs)
}
