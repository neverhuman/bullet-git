//! Independent settlement checks over the complete retained local audit inventory.
use super::super::{artifacts, io, paths, report_policy, Result};
use super::{common::*, inventory::Inventory, tool_record};
use serde_json::Value;
use std::collections::BTreeMap;

pub(super) fn validate(
    inventory: &Inventory,
    root: &str,
    run: &str,
    status: u8,
    policy: &[u8],
    tools: &mut BTreeMap<String, Value>,
) -> Result<()> {
    inventory.argv(
        "doctor",
        &[
            "bash".into(),
            "scripts/ci-doctor.sh".into(),
            "audit".into(),
            "--audit-run".into(),
            run.into(),
        ],
    )?;
    let doctor = inventory.exit("doctor.exit")?;
    tools.insert(
        "doctor".into(),
        tool_record::validate(inventory, run, "doctor", &["--version".into()], doctor)?,
    );
    if doctor != 0 {
        require(
            status == doctor
                && !inventory.data.keys().any(|path| {
                    ["lane.", "audit.", "ratchet.", "before/", "final/"]
                        .iter()
                        .any(|prefix| path.starts_with(prefix))
                }),
            "DOCTOR_FAILURE_LAUNCHED_LANE",
        )?;
        return Ok(());
    }
    inventory.argv(
        "lane",
        &[
            "bash".into(),
            "ops/ci/audit.sh".into(),
            "--audit-run".into(),
            run.into(),
        ],
    )?;
    let lane = inventory.exit("lane.exit")?;
    let started = std::str::from_utf8(inventory.get("audit.started")?).map_err(io)?;
    let pid = started
        .strip_prefix("pid=")
        .and_then(|s| s.strip_suffix('\n'))
        .ok_or("LANE_START_INVALID")?;
    require(
        !pid.is_empty()
            && !pid.starts_with('0')
            && pid.bytes().all(|b| b.is_ascii_digit())
            && lane == status,
        "LANE_STATUS_OR_START_MISMATCH",
    )?;
    let result = result_fields(inventory.get("result.txt")?)?;
    require(
        decimal(result["final_status"].as_bytes())? == lane,
        "RESULT_EXIT_CONTRADICTION",
    )?;
    inventory.snapshot("before")?;
    inventory.snapshot("final")?;
    let baseline_path = "target/jankurai/accepted-baseline.json";
    let baseline = inventory
        .data
        .get(&format!("before/{baseline_path}"))
        .map(|artifact| report_policy::decode(&artifact.bytes))
        .transpose()?;
    for name in ["ratchet", "audit"] {
        if name == "ratchet" && baseline.is_none() {
            require(
                !inventory
                    .data
                    .keys()
                    .any(|path| path.starts_with("ratchet")),
                "UNEXPECTED_RATCHET",
            )?;
            continue;
        }
        if !inventory.data.contains_key(&format!("{name}.exit")) {
            require(lane != 0, format!("MISSING_NATIVE_RUN:{name}"))?;
            continue;
        }
        let native_status = inventory.exit(&format!("{name}.exit"))?;
        // An exit receipt cannot replace the original retained process streams.
        for suffix in ["stdout", "stderr"] {
            inventory.get(&format!("{name}.{suffix}"))?;
        }
        if inventory
            .data
            .contains_key(&format!("{name}.validation.exit"))
        {
            for suffix in ["stdout", "stderr"] {
                inventory.get(&format!("{name}.validation.{suffix}"))?;
            }
            if inventory.exit(&format!("{name}.validation.exit"))? == 0
                || inventory
                    .data
                    .contains_key(&format!("{name}.validation.argv"))
            {
                validation_argv(inventory, root, run, name)?;
            }
        }
        let argv = native_argv(run, name);
        tools.insert(
            name.into(),
            tool_record::validate(inventory, run, name, &argv, native_status)?,
        );
        inventory.snapshot(name)?;
        require(
            native_status == 0
                || (lane == native_status
                    && decimal(result["primary_status"].as_bytes())? == native_status),
            "NATIVE_FAILURE_PROMOTED",
        )?;
        if native_status == 0 {
            require(
                inventory.exit(&format!("{name}.validation.exit"))? == 0 || lane != 0,
                "VALIDATION_FAILURE_PROMOTED",
            )?;
            let path = if name == "ratchet" {
                "ratchet.json"
            } else {
                "audit/.jankurai/repo-score.json"
            };
            let report = report_policy::decode(inventory.get(path)?)?;
            report_policy::validate(
                &report,
                policy,
                if name == "ratchet" {
                    baseline.as_ref()
                } else {
                    None
                },
            )?;
        }
    }
    if lane == 0 {
        require(
            result["stage"] == "complete"
                && ["primary_status", "retention_status", "final_status"]
                    .iter()
                    .all(|k| result[*k] == "0"),
            "PASS_WITH_INCOMPLETE_SETTLEMENT",
        )?;
        for name in REPORTS {
            let original = inventory.get(&format!("audit/.jankurai/{name}"))?;
            require(
                original == inventory.get(&format!("final/.jankurai/{name}"))?
                    && original == inventory.get(&format!("final/target/jankurai/{name}"))?,
                "STAGED_REPORT_MISMATCH",
            )?;
        }
        for name in ["target/jankurai/update/state.json", baseline_path] {
            require(
                inventory
                    .data
                    .get(&format!("before/{name}"))
                    .map(|a| &a.bytes)
                    == inventory
                        .data
                        .get(&format!("final/{name}"))
                        .map(|a| &a.bytes),
                "STATE_OR_BASELINE_CHANGED",
            )?;
        }
        require(
            !inventory
                .data
                .contains_key("final/.jankurai/score-history.jsonl"),
            "UNEXPECTED_SCORE_HISTORY_WRITE",
        )?;
        for path in ARTIFACTS {
            if path == ".ci-artifacts/observations/audit.json" {
                continue;
            }
            let absolute = format!("{root}/{path}");
            let current = match std::fs::symlink_metadata(&absolute) {
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
                Err(error) => return Err(io(error)),
                Ok(_) => Some(artifacts::read(&absolute)?.bytes),
            };
            require(
                inventory
                    .data
                    .get(&format!("final/{path}"))
                    .map(|a| &a.bytes)
                    == current.as_ref(),
                format!("CURRENT_ARTIFACT_DRIFT:{path}"),
            )?;
        }
    }
    Ok(())
}

fn validation_argv(inventory: &Inventory, root: &str, run: &str, name: &str) -> Result<()> {
    let raw = inventory.get(&format!("{name}.validation.argv"))?;
    let args: Vec<&str> = raw
        .strip_suffix(b"\0")
        .ok_or("VALIDATION_ARGV_TERMINATOR")?
        .split(|b| *b == 0)
        .map(std::str::from_utf8)
        .collect::<std::result::Result<_, _>>()
        .map_err(io)?;
    let runtime = *args.get(5).ok_or("VALIDATION_ARGV_INCOMPLETE")?;
    paths::absolute_parts(runtime)?;
    require(
        !std::path::Path::new(runtime).starts_with(root),
        "VALIDATION_RUNTIME_WITHIN_SOURCE",
    )?;
    let mut expected = vec![
        format!(
            "{root}/target/jankurai/bootstrap/{}/target/debug/bullet-ci-jankurai",
            run.rsplit('/').next().ok_or("VALIDATION_RUN_INVALID")?
        ),
        "report".into(),
        "--root".into(),
        root.into(),
        "--runtime".into(),
        runtime.into(),
        "--report".into(),
        if name == "ratchet" {
            format!("{run}/ratchet.json")
        } else {
            format!("{root}/.jankurai/repo-score.json")
        },
    ];
    if name == "ratchet" {
        expected.extend([
            "--baseline".into(),
            format!("{root}/target/jankurai/accepted-baseline.json"),
        ]);
    }
    require(args == expected, "VALIDATION_ARGV_MISMATCH")
}

pub(super) fn native_argv(run: &str, name: &str) -> Vec<String> {
    let mut argv: Vec<String> = ["audit", ".", "--full", "--no-score-history"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    if name == "ratchet" {
        argv.extend([
            "--mode".into(),
            "ratchet".into(),
            "--baseline".into(),
            "target/jankurai/accepted-baseline.json".into(),
            "--json".into(),
            format!("{run}/ratchet.json"),
            "--md".into(),
            format!("{run}/ratchet.md"),
        ]);
    } else {
        argv.extend(
            [
                "--repair-queue-jsonl",
                ".jankurai/repair-queue.jsonl",
                "--json",
                ".jankurai/repo-score.json",
                "--md",
                ".jankurai/repo-score.md",
            ]
            .into_iter()
            .map(str::to_owned),
        );
    }
    argv
}

fn result_fields(bytes: &[u8]) -> Result<BTreeMap<&str, &str>> {
    let text = std::str::from_utf8(bytes).map_err(io)?;
    let mut result = BTreeMap::new();
    for line in text.lines() {
        let (key, value) = line.split_once('=').ok_or("RESULT_FIELD_INVALID")?;
        require(
            result.insert(key, value).is_none(),
            "DUPLICATE_RESULT_FIELD",
        )?;
    }
    require(
        result
            .keys()
            .copied()
            .collect::<std::collections::BTreeSet<_>>()
            == [
                "stage",
                "primary_status",
                "retention_status",
                "final_status",
            ]
            .into_iter()
            .collect(),
        "RESULT_FIELDS_INVALID",
    )?;
    for key in ["primary_status", "retention_status", "final_status"] {
        decimal(result[key].as_bytes())?;
    }
    Ok(result)
}
