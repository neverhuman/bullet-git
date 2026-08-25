//! Dedicated non-release gitd. Production `bullet-gitd` never includes this
//! target. Clone is confined to one pre-opened private fixture root and a
//! session-wide MAC-bound permit.

use bullet_gitd::daemon::{
    parse_fixture_key, require_preopened_fixture_root, Daemon, FixturePermit,
};
use bullet_gitd::protocol;
use serde_json::Value;
use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

fn main() -> ExitCode {
    let config = match parse_args(std::env::args().skip(1)) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("bullet-gitd-fixture: {message}");
            return ExitCode::from(2);
        }
    };
    let fixture_root = match require_preopened_fixture_root(&config.root) {
        Ok(root) => root,
        Err(error) => {
            eprintln!("bullet-gitd-fixture: {error}");
            return ExitCode::from(2);
        }
    };
    let key = match parse_fixture_key(&config.key_hex) {
        Ok(key) => key,
        Err(error) => {
            eprintln!("bullet-gitd-fixture: {error}");
            return ExitCode::from(2);
        }
    };
    let permit = match load_permit(&config.permit_file) {
        Ok(permit) => permit,
        Err(error) => {
            eprintln!("bullet-gitd-fixture: {error}");
            return ExitCode::from(2);
        }
    };
    let mut daemon = match Daemon::fixture(&fixture_root, key, permit) {
        Ok(daemon) => daemon,
        Err(error) => {
            eprintln!("bullet-gitd-fixture: {error}");
            return ExitCode::FAILURE;
        }
    };
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut input = stdin.lock();
    loop {
        let line = match protocol::read_frame(&mut input) {
            Ok(Some(line)) => line,
            Ok(None) => break,
            Err(error) => {
                let response =
                    protocol::err_line(&Value::Null, error.reason_code(), &error.to_string());
                let _ = writeln!(out, "{response}");
                let _ = out.flush();
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let response = daemon.handle_line(&line);
        if writeln!(out, "{response}").is_err() {
            break;
        }
        if out.flush().is_err() {
            break;
        }
    }
    ExitCode::SUCCESS
}

struct Config {
    root: PathBuf,
    key_hex: String,
    permit_file: PathBuf,
}

fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Config, String> {
    let mut root = None;
    let mut key_hex = None;
    let mut permit_file = None;
    let mut args = args.into_iter();
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--root" => {
                root = Some(PathBuf::from(
                    args.next().ok_or("--root requires a directory")?,
                ));
            }
            "--key-hex" => {
                key_hex = Some(args.next().ok_or("--key-hex requires 64 hex")?);
            }
            "--permit-file" => {
                permit_file = Some(PathBuf::from(
                    args.next().ok_or("--permit-file requires a path")?,
                ));
            }
            other => return Err(format!("unknown argument {other}")),
        }
    }
    Ok(Config {
        root: root.ok_or("--root is required")?,
        key_hex: key_hex.ok_or("--key-hex is required")?,
        permit_file: permit_file.ok_or("--permit-file is required")?,
    })
}

fn load_permit(path: &std::path::Path) -> Result<FixturePermit, String> {
    let bytes = std::fs::read(path).map_err(|error| format!("read permit file: {error}"))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("decode permit file: {error}"))
}
