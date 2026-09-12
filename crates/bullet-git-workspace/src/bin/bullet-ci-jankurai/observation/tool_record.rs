//! Consume the exact one-use native admission event sequence and raw version streams.
use super::super::{
    paths, report_policy, Result, INSTALL_RECEIPT, PIN, PROFILE_NAME, SOURCE_COMMIT,
};
use super::common::{field, require};
use super::inventory::Inventory;
use base64::Engine;
use serde_json::{json, Value};

pub(super) fn validate(
    inventory: &Inventory,
    run: &str,
    name: &str,
    argv: &[String],
    expected: u8,
) -> Result<Value> {
    let path = format!("{name}.tool.jsonl");
    let raw = inventory.get(&path)?;
    let body = raw.strip_suffix(b"\n").ok_or("TRUNCATED_TOOL_RECORD")?;
    let lines = body.split(|b| *b == b'\n').take(11).collect::<Vec<_>>();
    require(!lines.is_empty() && lines.len() <= 10, "TOOL_RECORD_BOUND")?;
    let rows: Vec<Value> = lines
        .into_iter()
        .map(report_policy::decode)
        .collect::<Result<_>>()?;
    let mut events = Vec::new();
    for (index, row) in rows.iter().enumerate() {
        let timestamp = field(row, "time_ns")?.as_str().ok_or("TOOL_TIME_INVALID")?;
        require(
            field(row, "schema")? == "bullet.local-auditor-tool.v1"
                && field(row, "sequence")?.as_u64() == Some(index as u64)
                && field(row, "evidence_class")? == "LOCAL_TOOL_DIAGNOSTIC"
                && !timestamp.is_empty()
                && timestamp.len() <= 24
                && timestamp.bytes().all(|b| b.is_ascii_digit()),
            "TOOL_RECORD_ORDER_OR_SCHEMA",
        )?;
        events.push(field(row, "event")?.as_str().ok_or("TOOL_EVENT_INVALID")?);
    }
    let mut order = vec![
        "request",
        "candidate_opened",
        "candidate_read",
        "admitted",
        "launch_intent",
        "started",
        "terminated",
    ];
    if name == "doctor" {
        order.push("version_output");
    }
    let terminal = events[events.len() - 1];
    let prefix = &events[..events.len() - 1];
    require(
        matches!(terminal, "complete" | "refused") && order.get(..prefix.len()) == Some(prefix),
        "TOOL_EVENTS_INVALID",
    )?;
    require(
        terminal != "complete" || prefix == order,
        "TOOL_COMPLETION_INCOMPLETE",
    )?;
    require(
        terminal != "refused" || expected != 0,
        "REFUSED_TOOL_REPORTED_PASS",
    )?;
    let request = &rows[0];
    for (key, expected) in
        json!({"profile":PROFILE_NAME,"record_path":format!("{run}/{path}"),"argv":argv,
        "pinned_sha256":PIN.sha256,"pinned_size":PIN.size,"install_receipt_sha256":INSTALL_RECEIPT,
        "source_commit":SOURCE_COMMIT,"provenance_is_distribution_acceptance":false})
        .as_object()
        .ok_or("REQUEST_EXPECTATION_INVALID")?
    {
        require(
            field(request, key)? == expected,
            format!("TOOL_REQUEST_BINDING_MISMATCH:{name}"),
        )?;
    }
    let candidate = field(request, "candidate")?
        .as_str()
        .ok_or("CANDIDATE_PATH_INVALID")?;
    paths::absolute_parts(candidate)?;
    let event = |name: &str| {
        events
            .iter()
            .position(|value| *value == name)
            .map(|i| &rows[i])
    };
    if let Some(admitted) = event("admitted") {
        require(
            field(admitted, "sha256")? == PIN.sha256
                && field(admitted, "size")?.as_u64() == Some(PIN.size)
                && field(admitted, "seals")?.as_u64() == Some(15),
            "ADMITTED_TOOL_MISMATCH",
        )?;
        let read = event("candidate_read").ok_or("CANDIDATE_READ_MISSING")?;
        require(
            field(read, "path")? == candidate
                && field(
                    event("candidate_opened").ok_or("CANDIDATE_OPEN_MISSING")?,
                    "path",
                )? == candidate
                && field(read, "sha256")? == PIN.sha256
                && field(read, "copied_bytes")?.as_u64() == Some(PIN.size),
            "CANDIDATE_READ_MISMATCH",
        )?;
    }
    if let Some(launch) = event("launch_intent") {
        let fd = field(launch, "passed_executable_fd")?
            .as_u64()
            .filter(|fd| *fd >= 3)
            .ok_or("TOOL_FD_INVALID")?;
        let mut arguments = vec!["jankurai".to_owned()];
        arguments.extend_from_slice(argv);
        require(
            field(launch, "argv")? == &json!(arguments)
                && field(launch, "executable")? == &json!(format!("/proc/self/fd/{fd}"))
                && field(launch, "update_check")? == "disabled_by_JANKURAI_NO_UPDATE_CHECK_1",
            "TOOL_LAUNCH_MISMATCH",
        )?;
    }
    if let Some(started) = event("started") {
        require(
            field(started, "pid")?.as_u64().is_some_and(|pid| pid > 0),
            "NATIVE_PID_INVALID",
        )?;
    }
    let native = event("terminated")
        .map(|row| {
            field(row, "native_returncode")?
                .as_i64()
                .ok_or_else(|| "NATIVE_RETURN_CODE_INVALID".to_owned())
        })
        .transpose()?;
    let native_status = event("terminated")
        .map(|row| {
            field(row, "exit_status")?
                .as_u64()
                .filter(|status| *status <= 255)
                .ok_or_else(|| "NATIVE_STATUS_INVALID".to_owned())
        })
        .transpose()?;
    if let Some(native) = native {
        let calculated = if native >= 0 {
            Some(native)
        } else {
            128i64.checked_sub(native)
        };
        require(
            calculated.and_then(|status| u64::try_from(status).ok()) == native_status,
            "NATIVE_STATUS_CONTRADICTION",
        )?;
    }
    let last = rows.last().ok_or("TOOL_RECORD_EMPTY")?;
    require(
        field(last, "exit_status")?.as_u64() == Some(u64::from(expected)),
        "TOOL_EXIT_CONTRADICTION",
    )?;
    if terminal == "complete" {
        require(
            native_status == Some(u64::from(expected)),
            "COMPLETE_EXIT_CONTRADICTION",
        )?;
    } else {
        require(
            field(last, "native_status")? == &json!(native_status)
                && u64::from(expected) == native_status.filter(|status| *status != 0).unwrap_or(75),
            "REFUSAL_STATUS_CONTRADICTION",
        )?;
    }
    if name == "doctor" && expected == 0 {
        let version = event("version_output").ok_or("VERSION_RECORD_MISSING")?;
        let decode = |key: &str| -> Result<Vec<u8>> {
            base64::engine::general_purpose::STANDARD
                .decode(
                    field(version, key)?
                        .as_str()
                        .ok_or("VERSION_ENCODING_INVALID")?,
                )
                .map_err(|e| e.to_string())
        };
        let stdout = decode("stdout_base64")?;
        let stderr = decode("stderr_base64")?;
        let version_text = stdout.trim_ascii_end();
        // Native version permits only CR/LF framing, not arbitrary trailing whitespace.
        let trailing = &stdout[version_text.len()..];
        require(
            stdout == inventory.get(&format!("{path}.stdout"))?
                && stderr == inventory.get(&format!("{path}.stderr"))?
                && version_text == PIN.version
                && trailing.iter().all(|b| matches!(b, b'\r' | b'\n'))
                && stderr.is_empty(),
            "ACTUAL_VERSION_MISMATCH",
        )?;
    }
    Ok(
        json!({"record":path,"candidate":candidate,"admitted_sha256":event("admitted").and_then(|r|r.get("sha256")),
        "native_returncode":native,"helper_exit":expected,
        "version":if name == "doctor" && expected == 0 { Some(std::str::from_utf8(PIN.version).map_err(|e|e.to_string())?) } else { None }}),
    )
}
