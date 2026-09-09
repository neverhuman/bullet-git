//! bullet-gitd binary: line-delimited JSON over stdio. One request object per
//! line in, one response object per line out. Protocol: docs/architecture.md.

use bullet_gitd::{daemon::Daemon, protocol};
use serde_json::Value;
use std::io::Write;

fn main() {
    if let Some(arg) = std::env::args().nth(1) {
        eprintln!("bullet-gitd: unknown argument {arg}");
        std::process::exit(2);
    }
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut daemon = Daemon::new();
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
}
