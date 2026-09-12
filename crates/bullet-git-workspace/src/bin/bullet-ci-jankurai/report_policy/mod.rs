//! Native report-to-policy validation; filesystem/source custody is a caller prerequisite.
mod strict_json;
#[cfg(test)]
mod tests;
use serde_json::Value;
use sha2::{Digest, Sha256};

type Result<T> = std::result::Result<T, String>;
pub(super) fn decode(bytes: &[u8]) -> Result<Value> {
    strict_json::decode(bytes)
}

fn require(condition: bool, reason: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(reason.to_owned())
    }
}
fn field<'a>(value: &'a Value, key: &str) -> Result<&'a Value> {
    value
        .as_object()
        .and_then(|row| row.get(key))
        .ok_or_else(|| format!("REPORT_FIELD_MISSING:{key}"))
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
    field(value, key)?
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| format!("REPORT_ARRAY_REQUIRED:{key}"))
}

struct Policy {
    minimum: i64,
    fail_on: Vec<String>,
    advisory_on: Vec<String>,
    fingerprint: String,
}
impl Policy {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let source =
            std::str::from_utf8(bytes).map_err(|error| format!("SOURCE_POLICY_UTF8:{error}"))?;
        let value: toml::Value =
            toml::from_str(source).map_err(|error| format!("SOURCE_POLICY_INVALID:{error}"))?;
        let minimum = value
            .get("minimum_score")
            .and_then(toml::Value::as_integer)
            .filter(|minimum| *minimum >= 65)
            .ok_or("SOURCE_POLICY_BELOW_FLOOR")?;
        let strings = |key: &str| -> Result<Vec<String>> {
            value
                .get(key)
                .and_then(toml::Value::as_array)
                .ok_or_else(|| format!("SOURCE_POLICY_ARRAY_REQUIRED:{key}"))?
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| format!("SOURCE_POLICY_STRING_REQUIRED:{key}"))
                })
                .collect()
        };
        Ok(Self {
            minimum,
            fail_on: strings("fail_on")?,
            advisory_on: strings("advisory_on")?,
            fingerprint: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
        })
    }
}

/// Checks full native JSON values without dropping unknown historical fields.
/// The caller must additionally bind exact native execution, committed source
/// policy bytes, retained artifact identities, and the selected baseline.
pub(super) fn validate(
    report: &Value,
    policy_bytes: &[u8],
    baseline: Option<&Value>,
) -> Result<()> {
    let policy = Policy::parse(policy_bytes)?;
    let observed = field(report, "policy")?;
    require(
        field(observed, "minimum_score")?.as_i64() == Some(policy.minimum),
        "REPORT_POLICY_MISMATCH:minimum_score",
    )?;
    for (key, expected) in [
        ("fail_on", &policy.fail_on),
        ("advisory_on", &policy.advisory_on),
    ] {
        require(
            field(observed, key)?
                == &serde_json::to_value(expected).map_err(|error| error.to_string())?,
            &format!("REPORT_POLICY_MISMATCH:{key}"),
        )?;
    }
    require(
        field(report, "policy_fingerprint")?.as_str() == Some(&policy.fingerprint),
        "POLICY_FINGERPRINT_MISMATCH",
    )?;
    let decision = field(report, "decision")?;
    let score = field(report, "score")?
        .as_i64()
        .filter(|score| *score >= policy.minimum)
        .ok_or("REPORT_DECISION_NOT_PASSING")?;
    require(
        field(decision, "passed")?.as_bool() == Some(true)
            && field(decision, "status")?.as_str() == Some("pass")
            && field(decision, "minimum_score")?.as_i64() == Some(policy.minimum)
            && field(decision, "hard_findings")?.as_i64() == Some(0),
        "REPORT_DECISION_NOT_PASSING",
    )?;
    for finding in array(report, "findings")? {
        let severity = field(finding, "severity")?
            .as_str()
            .ok_or("FINDING_SEVERITY_INVALID")?;
        require(
            !policy.fail_on.iter().any(|denied| denied == severity),
            "HARD_FINDING_IN_PASS",
        )?;
    }
    require(
        field(observed, "mode")?.as_str()
            == Some(if baseline.is_some() {
                "ratchet"
            } else {
                "standard"
            }),
        "REPORT_MODE_MISMATCH",
    )?;
    if let Some(baseline) = baseline {
        validate_ratchet(report, baseline, decision, score)?;
    }
    Ok(())
}

fn validate_ratchet(report: &Value, baseline: &Value, decision: &Value, score: i64) -> Result<()> {
    let baseline_score = field(baseline, "score")?
        .as_i64()
        .ok_or("RATCHET_SCORE_DROP")?;
    require(score >= baseline_score, "RATCHET_SCORE_DROP")?;
    let delta = score
        .checked_sub(baseline_score)
        .ok_or("RATCHET_DECISION_MISMATCH")?;
    let ratchet = field(decision, "ratchet")?;
    require(
        field(ratchet, "passed")?.as_bool() == Some(true)
            && field(ratchet, "allowed_drop")?.as_i64() == Some(0)
            && field(ratchet, "baseline_score")?.as_i64() == Some(baseline_score)
            && field(ratchet, "score_delta")?.as_i64() == Some(delta)
            && array(ratchet, "new_caps")?.is_empty()
            && array(ratchet, "new_hard_findings")?.is_empty()
            && field(ratchet, "policy_changed")?.as_bool() == Some(false),
        "RATCHET_DECISION_MISMATCH",
    )?;
    for key in [
        "report_fingerprint",
        "input_fingerprint",
        "policy_fingerprint",
    ] {
        require(
            field(ratchet, &format!("baseline_{key}"))? == field(baseline, key)?,
            "RATCHET_BASELINE_MISMATCH",
        )?;
    }
    for key in ["policy_fingerprint", "schema_version", "standard_version"] {
        require(
            field(report, key)? == field(baseline, key)?,
            "RATCHET_POLICY_OR_VERSION_DRIFT",
        )?;
    }
    let old_caps = array(baseline, "caps_applied")?;
    require(
        array(report, "caps_applied")?
            .iter()
            .all(|cap| old_caps.contains(cap)),
        "RATCHET_NEW_CAP",
    )?;
    let old_hard = hard_findings(baseline)?;
    require(
        hard_findings(report)?
            .iter()
            .all(|finding| old_hard.contains(finding)),
        "RATCHET_NEW_HARD_FINDING",
    )
}

fn hard_findings(report: &Value) -> Result<Vec<&Value>> {
    let mut result = Vec::new();
    for finding in array(report, "findings")? {
        if matches!(
            field(finding, "severity")?.as_str(),
            Some("critical" | "high")
        ) {
            result.push(field(finding, "fingerprint")?);
        }
    }
    Ok(result)
}
