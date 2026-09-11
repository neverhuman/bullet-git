//! Explicit local root/runtime operands; no shell strings or implicit repository choice.
use super::super::{paths, Result};
use super::common::{decimal, require};
use std::collections::BTreeMap;

pub(super) fn entry(command: &str, args: &[String]) -> Result<u8> {
    require(args.len() % 2 == 0, "OBSERVATION_OPTION_VALUE_REQUIRED")?;
    let mut options = BTreeMap::new();
    let allowed = if command == "capture" {
        vec!["--root", "--runtime", "--run", "--status"]
    } else if command == "check" {
        vec!["--root", "--runtime", "--commit"]
    } else {
        return Err("OBSERVATION_COMMAND_INVALID".into());
    };
    for pair in args.chunks_exact(2) {
        require(
            allowed.contains(&pair[0].as_str())
                && options.insert(pair[0].as_str(), pair[1].as_str()).is_none(),
            "OBSERVATION_OPTION_INVALID",
        )?;
    }
    require(
        options.len() == allowed.len(),
        "OBSERVATION_OPTIONS_MISSING",
    )?;
    let root = options["--root"];
    let runtime = options["--runtime"];
    paths::absolute_parts(root)?;
    paths::absolute_parts(runtime)?;
    if command == "capture" {
        let parent = rustix::process::getppid()
            .ok_or("PARENT_ID_UNAVAILABLE")?
            .as_raw_nonzero()
            .get() as u32;
        super::capture(
            root,
            options["--run"],
            decimal(options["--status"].as_bytes())?,
            parent,
            runtime,
        )
    } else {
        super::check(root, options["--commit"], runtime)?;
        Ok(0)
    }
}
