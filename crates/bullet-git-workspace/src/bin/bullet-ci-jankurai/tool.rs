//! Fixed artifact/argv admission shared by this local CI binary and its tests.
#[path = "admission.rs"]
mod admission;
#[path = "artifacts.rs"]
mod artifacts;
#[path = "execution.rs"]
mod execution;
#[path = "observation/mod.rs"]
mod observation;
#[path = "paths.rs"]
mod paths;
#[path = "record.rs"]
mod record;
#[path = "report.rs"]
mod report;
#[path = "report_policy/mod.rs"]
mod report_policy;
#[cfg(test)]
#[path = "tests.rs"]
mod tests;

use record::Record;
use serde_json::json;
use std::collections::BTreeMap;
use std::ffi::OsString;

type Result<T> = std::result::Result<T, String>;
type Environment = BTreeMap<OsString, OsString>;

const PROFILE_NAME: &str = "local-linux-x86_64-gnu-jankurai-1.6.11";
const INSTALL_RECEIPT: &str = "40749914e412bc54f62c872884a76d287d48e359a4a7b3ddb0efc9d4ffbdd43a";
const SOURCE_COMMIT: &str = "b88562fdb124aa86dedd70ab972e7d0d87e58be1";
const PIN: Profile<'static> = Profile {
    sha256: "9e6b8857a26f6004d4c74e510e13b06d880f2e2ae0c89502698889ed690c5d6c",
    size: 19_484_592,
    version: b"jankurai 1.6.11",
};

#[derive(Clone, Copy)]
struct Profile<'a> {
    sha256: &'a str,
    size: u64,
    version: &'a [u8],
}

#[derive(Debug)]
struct Request {
    candidate: String,
    record: String,
    argv: Vec<String>,
}

fn io(error: impl std::fmt::Display) -> String {
    format!("OS_ERROR: {error}")
}

pub(super) fn entry(args: Vec<OsString>) -> i32 {
    if args == [OsString::from("--help")] {
        println!("bullet-ci-jankurai --candidate ABSOLUTE --record ABSOLUTE -- COMMAND\nbullet-ci-jankurai report --root ABS --runtime NEW_ABS --report ABS [--baseline ABS]\nbullet-ci-jankurai capture --root ABS --runtime NEW_ABS --run ABS --status N\nbullet-ci-jankurai check --root ABS --runtime NEW_ABS --commit OID\nLocal CI artifact admission and diagnostics only; no release authority.");
        return 0;
    }
    if let Some(command) = args
        .first()
        .and_then(|arg| arg.to_str())
        .filter(|command| matches!(*command, "report" | "capture" | "check"))
    {
        let result = args[1..]
            .iter()
            .map(|arg| {
                arg.to_str()
                    .map(str::to_owned)
                    .ok_or_else(|| "NON_UTF8_ARGUMENT".to_owned())
            })
            .collect::<Result<Vec<_>>>()
            .and_then(|args| {
                if command == "report" {
                    report::entry(&args).map(|()| 0)
                } else {
                    observation::entry(command, &args)
                }
            });
        return match result {
            Ok(status) => i32::from(status),
            Err(error) => {
                eprintln!("audit-observation: {error}");
                75
            }
        };
    }
    match parse(args) {
        Ok(request) => invoke(&request, PIN, std::env::vars_os().collect()),
        Err(error) => {
            eprintln!("jankurai-tool: {error}");
            2
        }
    }
}

fn parse(args: Vec<OsString>) -> Result<Request> {
    let args: Vec<String> = args
        .into_iter()
        .map(|s| s.into_string().map_err(|_| "NON_UTF8_ARGUMENT".to_owned()))
        .collect::<Result<_>>()?;
    let mut candidate = None;
    let mut record = None;
    let mut index = 0;
    while index < args.len() && args[index] != "--" {
        let value = args.get(index + 1).ok_or("MISSING_OPTION_VALUE")?.clone();
        match args[index].as_str() {
            "--candidate" if candidate.is_none() => candidate = Some(value),
            "--record" if record.is_none() => record = Some(value),
            _ => return Err("UNSUPPORTED_OR_DUPLICATE_OPTION".into()),
        }
        index += 2;
    }
    if args.get(index).map(String::as_str) != Some("--") {
        return Err("COMMAND_SEPARATOR_REQUIRED".into());
    }
    Ok(Request {
        candidate: candidate.ok_or("CANDIDATE_REQUIRED")?,
        record: record.ok_or("RECORD_REQUIRED")?,
        argv: args[index + 1..].to_vec(),
    })
}

fn validate_argv(argv: &[String]) -> Result<()> {
    if argv == ["--version"] {
        return Ok(());
    }
    if argv.get(..4)
        != Some(&[
            "audit".into(),
            ".".into(),
            "--full".into(),
            "--no-score-history".into(),
        ])
    {
        return Err("UNSUPPORTED_TOOL_ARGV".into());
    }
    let rest = &argv[4..];
    if rest.len() % 2 != 0 || rest.len() > 10 {
        return Err("UNSUPPORTED_TOOL_ARGV".into());
    }
    let mut values = BTreeMap::new();
    for pair in rest.chunks_exact(2) {
        if ![
            "--json",
            "--md",
            "--repair-queue-jsonl",
            "--mode",
            "--baseline",
        ]
        .contains(&pair[0].as_str())
            || pair[1].is_empty()
            || pair[1].len() > 4096
            || pair[1].contains('\0')
            || values.insert(pair[0].as_str(), pair[1].as_str()).is_some()
        {
            return Err("UNSUPPORTED_TOOL_ARGV".into());
        }
    }
    if !values.contains_key("--json") || !values.contains_key("--md") {
        return Err("AUDIT_REPORT_PATHS_REQUIRED".into());
    }
    if values.contains_key("--mode") != values.contains_key("--baseline") {
        return Err("INCOMPLETE_RATCHET_ARGV".into());
    }
    if values.get("--mode").is_some_and(|mode| *mode != "ratchet") {
        return Err("UNSUPPORTED_AUDIT_MODE".into());
    }
    Ok(())
}

fn invoke(request: &Request, profile: Profile<'_>, environment: Environment) -> i32 {
    let mut record = match Record::new(&request.record) {
        Ok(record) => record,
        Err(error) => {
            eprintln!("jankurai-tool: {error}");
            return 75;
        }
    };
    let mut native = None;
    let result = (|| {
        record.append(
            "request",
            json!({"profile": PROFILE_NAME, "candidate": request.candidate,
            "argv": request.argv, "record_path": request.record,
            "pinned_sha256": profile.sha256, "pinned_size": profile.size,
            "install_receipt_sha256": INSTALL_RECEIPT, "source_commit": SOURCE_COMMIT,
            "provenance_is_distribution_acceptance": false}),
        )?;
        validate_argv(&request.argv)?;
        let executable = admission::admit(&request.candidate, &mut record, profile)?;
        let status = execution::run(
            &executable,
            &request.argv,
            &mut record,
            &mut native,
            profile,
            environment,
        )?;
        record.append("complete", json!({"exit_status": status}))?;
        Ok(status)
    })();
    settle(result, native, &mut record)
}

fn settle(result: Result<i32>, native: Option<i32>, record: &mut Record) -> i32 {
    match result {
        Ok(status) => status,
        Err(error) => {
            let status = native.filter(|status| *status != 0).unwrap_or(75);
            if record
                .append(
                    "refused",
                    json!({"reason": error, "native_status": native,
                "exit_status": status}),
                )
                .is_err()
            {
                eprintln!("jankurai-tool: RECORD_PERSISTENCE_FAILED");
            }
            eprintln!("jankurai-tool: {error}");
            status
        }
    }
}
