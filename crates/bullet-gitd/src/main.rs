//! bullet-gitd binary: line-delimited JSON over stdio. One request object per
//! line in, one response object per line out. Protocol: docs/architecture.md.

use bullet_gitd::daemon::Daemon;
use std::io::{BufRead, Write};

fn main() {
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    let mut daemon = Daemon::new();
    for line in stdin.lock().lines() {
        let Ok(line) = line else { break };
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
